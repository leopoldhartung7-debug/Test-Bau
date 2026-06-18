"""
Frida session management — spawn / attach / script injection.

All platform-specific logic is handled by the caller; this module owns only
the Frida session lifecycle and message routing.
"""

from __future__ import annotations

import logging
import uuid
from threading import Event, Lock
from typing import Any, Callable

from .models import Platform, Session, SessionState, TargetApp

logger = logging.getLogger(__name__)


def _require_frida() -> Any:
    try:
        import frida
        return frida
    except ImportError:
        raise RuntimeError(
            "frida-tools is required. Install with: pip install frida-tools"
        )


class FridaBridge:
    """
    Manages Frida device selection, process spawning/attaching, and script
    injection lifecycle for iOS (via USB or remote) and Android (ADB transport).
    """

    def __init__(
        self,
        device_id: str | None = None,
        device_type: str = "usb",   # "usb" | "remote" | "local"
        remote_host: str = "localhost",
        remote_port: int = 27042,
    ):
        self._device_id = device_id
        self._device_type = device_type
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._device: Any = None
        self._sessions: dict[str, Session] = {}
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _get_device(self) -> Any:
        frida = _require_frida()
        if self._device is not None:
            return self._device

        if self._device_type == "local":
            self._device = frida.get_local_device()
        elif self._device_type == "remote":
            self._device = frida.get_device_manager().add_remote_device(
                f"{self._remote_host}:{self._remote_port}"
            )
        else:
            # USB — pick the specified device or the first one
            if self._device_id:
                self._device = frida.get_device(self._device_id)
            else:
                self._device = frida.get_usb_device(timeout=10)

        logger.info("Using Frida device: %s", self._device.name)
        return self._device

    # ------------------------------------------------------------------
    # Attach / Spawn
    # ------------------------------------------------------------------

    def attach(self, target: TargetApp) -> Session:
        """
        Attach to an already-running process or spawn a fresh one.

        Parameters
        ----------
        target:
            TargetApp with bundle_id and spawn flag.  If target.pid is set
            we attach by PID directly; otherwise we resolve by bundle ID /
            process name.

        Returns
        -------
        Session
            Initialised session in ATTACHED state.
        """
        frida = _require_frida()
        device = self._get_device()
        session_id = str(uuid.uuid4())

        try:
            if target.spawn:
                logger.info("Spawning %s on %s", target.bundle_id, device.name)
                pid = device.spawn([target.bundle_id])
                frida_session = device.attach(pid)
                device.resume(pid)
                target.pid = pid
            elif target.pid:
                logger.info("Attaching by PID %d", target.pid)
                frida_session = device.attach(target.pid)
            else:
                logger.info("Attaching to %s by name", target.bundle_id)
                frida_session = device.attach(target.bundle_id)

            session = Session(
                session_id=session_id,
                target=target,
                state=SessionState.ATTACHED,
                _frida_session=frida_session,
            )

            def _on_detached(reason: str, crash: Any) -> None:
                logger.warning("Session %s detached: %s", session_id, reason)
                session.state = SessionState.DETACHED

            frida_session.on("detached", _on_detached)

            with self._lock:
                self._sessions[session_id] = session

            logger.info("Session %s attached to %s", session_id, target.bundle_id)
            return session

        except Exception as exc:
            logger.error("Failed to attach to %s: %s", target.bundle_id, exc)
            return Session(
                session_id=session_id,
                target=target,
                state=SessionState.ERROR,
            )

    # ------------------------------------------------------------------
    # Script injection
    # ------------------------------------------------------------------

    def inject_script(
        self,
        session: Session,
        source: str,
        script_name: str = "apphook",
        on_message: Callable[[dict, bytes | None], None] | None = None,
    ) -> Any:
        """
        Compile and inject a Frida JavaScript source string into the target process.

        Parameters
        ----------
        session:
            Active Session returned by attach().
        source:
            Frida JavaScript source to inject.
        script_name:
            Logical name for tracking; also appears in Frida stack traces.
        on_message:
            Callback invoked for every send() call from the JS side.
            Signature: (message_dict, data_bytes_or_None).

        Returns
        -------
        frida.Script instance (or None on error).
        """
        if not session.is_active:
            raise RuntimeError(f"Session {session.session_id} is not active")

        frida_session = session._frida_session
        try:
            script = frida_session.create_script(source, name=script_name)

            def _default_on_message(message: dict, data: bytes | None) -> None:
                if message.get("type") == "error":
                    logger.error(
                        "[%s] JS error: %s\n%s",
                        script_name,
                        message.get("description", ""),
                        message.get("stack", ""),
                    )
                elif message.get("type") == "send":
                    payload = message.get("payload", {})
                    logger.debug("[%s] send: %s", script_name, payload)

            script.on("message", on_message or _default_on_message)
            script.load()
            session._scripts[script_name] = script
            logger.info("Script '%s' loaded into session %s", script_name, session.session_id)
            return script
        except Exception as exc:
            logger.error("Script injection failed: %s", exc)
            return None

    def unload_script(self, session: Session, script_name: str) -> None:
        script = session._scripts.pop(script_name, None)
        if script:
            try:
                script.unload()
            except Exception:
                pass

    def detach(self, session: Session) -> None:
        """Cleanly detach from the target process."""
        # Unload all injected scripts first
        for name, script in list(session._scripts.items()):
            try:
                script.unload()
            except Exception:
                pass
        session._scripts.clear()

        if session._frida_session:
            try:
                session._frida_session.detach()
            except Exception:
                pass
        session.state = SessionState.DETACHED
        logger.info("Session %s detached", session.session_id)

    # ------------------------------------------------------------------
    # Convenience: synchronous RPC call into injected script
    # ------------------------------------------------------------------

    def rpc_call(
        self,
        session: Session,
        script_name: str,
        fn_name: str,
        *args: Any,
    ) -> Any:
        """
        Invoke an exported RPC function in an already-loaded script.

        The JS side must export via:
            rpc.exports = { fnName: function(...) { ... } };
        """
        script = session._scripts.get(script_name)
        if script is None:
            raise RuntimeError(f"Script '{script_name}' is not loaded in session {session.session_id}")
        return getattr(script.exports, fn_name)(*args)
