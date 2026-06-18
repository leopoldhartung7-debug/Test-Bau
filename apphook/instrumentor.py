"""
RuntimeInstrumentor — main entry point for AppHook dynamic instrumentation.

Provides five public capabilities:
  1. attach()                — establish a Frida session with the target app
  2. hook_method()           — intercept method calls with a Python callback
  3. replace_method()        — replace a method implementation entirely
  4. bypass_ssl_pinning()    — defeat certificate pinning across common libraries
  5. start_tracing()         — structured logging of sensitive API categories
  6. inject_behavior()       — activate named security-test behaviors
  7. scan_vulnerabilities()  — run automated MASVS vulnerability checks
"""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .frida_bridge import FridaBridge
from .models import (
    HookResult,
    HookState,
    Platform,
    Session,
    SessionState,
    TargetApp,
    TraceCategory,
    TraceEvent,
    TraceSession,
    VulnReport,
)
from .vuln.scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)

# Root of the scripts directory (relative to this file)
_SCRIPTS_DIR = Path(__file__).parent / "scripts"


def _read_script(relative_path: str) -> str:
    return (_SCRIPTS_DIR / relative_path).read_text(encoding="utf-8")


class RuntimeInstrumentor:
    """
    Dynamic instrumentation engine for iOS and Android mobile apps.

    Parameters
    ----------
    platform:
        Target platform (Platform.IOS or Platform.ANDROID).
    device_id:
        Frida device serial. None → first USB device.
    device_type:
        "usb" | "remote" | "local".
    remote_host / remote_port:
        Used when device_type == "remote" (e.g. frida-server over TCP).
    proxy_host / proxy_port:
        MITM proxy endpoint. If set, ssl bypass scripts configure traffic routing.
    """

    def __init__(
        self,
        platform: Platform,
        device_id: str | None = None,
        device_type: str = "usb",
        remote_host: str = "localhost",
        remote_port: int = 27042,
        proxy_host: str = "",
        proxy_port: int = 8080,
    ):
        self.platform = platform
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._bridge = FridaBridge(
            device_id=device_id,
            device_type=device_type,
            remote_host=remote_host,
            remote_port=remote_port,
        )
        self._session: Session | None = None
        self._hooks: dict[str, HookResult] = {}
        self._trace_session: TraceSession | None = None
        self._trace_lock = threading.Lock()

    # ──────────────────────────────────────────────────────────────────────────
    # 1. attach / detach
    # ──────────────────────────────────────────────────────────────────────────

    def attach(self, app_bundle_id: str, spawn: bool = False, pid: int | None = None) -> Session:
        """
        Attach to (or spawn) the target application.

        Parameters
        ----------
        app_bundle_id:
            iOS bundle ID (e.g. "com.example.app") or Android package name.
        spawn:
            If True, spawn a fresh instance of the app. Useful for early
            instrumentation before the app's initialisation code runs.
        pid:
            If provided, attach directly by process ID.

        Returns
        -------
        Session
            Active session. Check session.state == SessionState.ATTACHED.
        """
        target = TargetApp(
            bundle_id=app_bundle_id,
            platform=self.platform,
            pid=pid,
            spawn=spawn,
        )
        self._session = self._bridge.attach(target)
        if self._session.state == SessionState.ATTACHED:
            logger.info("Attached to %s (session %s)", app_bundle_id, self._session.session_id)
        else:
            logger.error("Failed to attach to %s", app_bundle_id)
        return self._session

    def detach(self) -> None:
        if self._session:
            self._bridge.detach(self._session)
            self._session = None

    # ──────────────────────────────────────────────────────────────────────────
    # 2. hook_method
    # ──────────────────────────────────────────────────────────────────────────

    def hook_method(
        self,
        class_name: str,
        method_name: str,
        callback: Callable[[dict], None] | None = None,
    ) -> HookResult:
        """
        Intercept calls to a class method, invoking *callback* on each hit.

        iOS:  class_name is an Objective-C class; method_name is a selector
              (e.g. "login:password:" or "+sharedInstance").
        Android: class_name is a fully-qualified Java class name; method_name
              is a method name (overloads are resolved automatically).

        Parameters
        ----------
        callback:
            Optional Python callable receiving a dict with keys:
            class, method, args, ret, tid, stack.
            If None, events are logged at DEBUG level.

        Returns
        -------
        HookResult
        """
        self._require_session()
        hook_id = f"hook-{uuid.uuid4().hex[:8]}"

        # Build a minimal Frida script for this single hook
        if self.platform == Platform.IOS:
            js = self._build_ios_hook_script(class_name, method_name, hook_id)
        else:
            js = self._build_android_hook_script(class_name, method_name, hook_id)

        result = HookResult(
            hook_id=hook_id,
            class_name=class_name,
            method_name=method_name,
            platform=self.platform,
            state=HookState.ACTIVE,
        )

        def _on_message(message: dict, _data: bytes | None) -> None:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("hook_id") == hook_id:
                    result.call_count += 1
                    if callback:
                        try:
                            callback(payload)
                        except Exception as exc:
                            logger.warning("Hook callback raised: %s", exc)
                    else:
                        logger.debug("Hook %s: %s", hook_id, payload)
            elif message.get("type") == "error":
                result.state = HookState.FAILED
                result.error = message.get("description", "")
                logger.error("Hook script error: %s", result.error)

        script = self._bridge.inject_script(
            self._session, js, script_name=hook_id, on_message=_on_message
        )
        if script is None:
            result.state = HookState.FAILED
            result.error = "Script injection failed"

        self._hooks[hook_id] = result
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 3. replace_method
    # ──────────────────────────────────────────────────────────────────────────

    def replace_method(
        self,
        class_name: str,
        method_name: str,
        implementation: str,
    ) -> HookResult:
        """
        Replace a method's implementation entirely with custom JavaScript.

        Parameters
        ----------
        implementation:
            JavaScript function body (not a function declaration — the wrapper
            is added automatically). The function receives the same arguments
            as the original method.  Use ``this.original(...)`` to call through.

        Example
        -------
        instrumentor.replace_method(
            "com.example.AuthManager", "isLoggedIn",
            "return true;"  # always report logged-in (security test)
        )
        """
        self._require_session()
        hook_id = f"replace-{uuid.uuid4().hex[:8]}"

        if self.platform == Platform.IOS:
            js = self._build_ios_replace_script(
                class_name, method_name, implementation, hook_id
            )
        else:
            js = self._build_android_replace_script(
                class_name, method_name, implementation, hook_id
            )

        result = HookResult(
            hook_id=hook_id,
            class_name=class_name,
            method_name=method_name,
            platform=self.platform,
            state=HookState.REPLACED,
            hook_type="replace",
        )

        script = self._bridge.inject_script(
            self._session, js, script_name=hook_id
        )
        if script is None:
            result.state = HookState.FAILED
            result.error = "Script injection failed"

        self._hooks[hook_id] = result
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 4. bypass_ssl_pinning
    # ──────────────────────────────────────────────────────────────────────────

    def bypass_ssl_pinning(self) -> bool:
        """
        Inject the platform SSL bypass script to defeat certificate pinning.

        Hooks:
          iOS     — SecTrustEvaluate(WithError), AFNetworking, Alamofire, TrustKit,
                    NSURLSession credential challenge delegate.
          Android — TrustManager, SSLContext, OkHttp3 CertificatePinner,
                    WebViewClient, Conscrypt, NetworkSecurityConfig.

        If proxy_host / proxy_port are configured the device's network traffic
        should already be routed through the MITM proxy (e.g. Burp Suite or
        mitmproxy) at the OS level — this method only disables the app-level
        pinning that would otherwise block that proxy's certificate.

        Returns
        -------
        bool
            True if the script was injected without errors.
        """
        self._require_session()
        script_path = (
            "ssl/ios_ssl_bypass.js"
            if self.platform == Platform.IOS
            else "ssl/android_ssl_bypass.js"
        )
        source = _read_script(script_path)
        script = self._bridge.inject_script(
            self._session, source, script_name="ssl_bypass"
        )
        if script is None:
            logger.error("SSL bypass script injection failed")
            return False

        logger.info("SSL pinning bypass active for %s", self._session.target.bundle_id)
        return True

    def get_ssl_bypass_status(self) -> list[str]:
        """Return the list of SSL bypass hooks that have fired (RPC call)."""
        try:
            return self._bridge.rpc_call(self._session, "ssl_bypass", "get_bypassed")
        except Exception:
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # 5. start_tracing
    # ──────────────────────────────────────────────────────────────────────────

    def start_tracing(self, categories: list[TraceCategory]) -> TraceSession:
        """
        Start comprehensive API call tracing for the specified categories.

        Parameters
        ----------
        categories:
            One or more TraceCategory values:
            CRYPTO, FILESYSTEM, KEYCHAIN, NETWORK, BIOMETRICS.

        Returns
        -------
        TraceSession
            Live session; events accumulate in trace.events as the app runs.
            Call stop_tracing() to finalise.
        """
        self._require_session()

        trace_id = str(uuid.uuid4())
        self._trace_session = TraceSession(
            trace_id=trace_id,
            session=self._session,
            categories=categories,
            started_at=datetime.utcnow(),
        )

        # Inject the trace script
        script_path = (
            "trace/ios_trace.js"
            if self.platform == Platform.IOS
            else "trace/android_trace.js"
        )
        source = _read_script(script_path)

        def _on_message(message: dict, _data: bytes | None) -> None:
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            if payload.get("event") != "trace":
                return
            ev = self._parse_trace_event(payload)
            with self._trace_lock:
                self._trace_session.events.append(ev)

        script = self._bridge.inject_script(
            self._session, source, script_name="trace", on_message=_on_message
        )
        if script is None:
            logger.error("Trace script injection failed")
            return self._trace_session

        # Tell the JS side which categories to emit
        try:
            cat_names = [c.value for c in categories]
            self._bridge.rpc_call(self._session, "trace", "set_categories", cat_names)
            logger.info("Tracing started: %s", cat_names)
        except Exception as exc:
            logger.warning("Could not set trace categories: %s", exc)

        return self._trace_session

    def stop_tracing(self) -> TraceSession | None:
        if self._trace_session:
            self._trace_session.active = False
            self._bridge.unload_script(self._session, "trace")
            logger.info("Tracing stopped. %d events captured.",
                        len(self._trace_session.events))
        return self._trace_session

    # ──────────────────────────────────────────────────────────────────────────
    # 6. inject_behavior
    # ──────────────────────────────────────────────────────────────────────────

    def inject_behavior(self, behavior_script: str, opts: dict | None = None) -> bool:
        """
        Activate a named security-test behavior in the running app.

        Behaviors are implemented in scripts/manipulation/{platform}_behaviors.js
        and exposed via rpc.exports.enable(name, opts).

        Built-in behavior names
        -----------------------
        bypass_auth              — hook common auth-check patterns → return success
        bypass_jailbreak_detect  — suppress jailbreak/root detection (iOS)
        bypass_root_detect       — suppress root detection (Android + iOS alias)
        bypass_emulator_detect   — spoof device fingerprint (Android)
        iap_check_bypass         — test bypassability of purchase/subscription checks
        force_biometric_success  — make biometric auth always succeed
        time_travel              — freeze clock to test token/session expiry
        force_network_error      — inject IOException / NSError for chaos testing

        Parameters
        ----------
        behavior_script:
            Behavior name OR arbitrary Frida JavaScript source. If the value
            matches a built-in name, the named behavior is activated via RPC.
            Otherwise the string is treated as raw JavaScript and injected directly.
        opts:
            Optional dict passed to the behavior function (e.g. {"timestamp_ms": ...}).

        Returns
        -------
        bool
            True if the behavior was successfully activated.
        """
        self._require_session()

        BUILTIN_BEHAVIORS = {
            "bypass_auth", "bypass_jailbreak_detect", "bypass_root_detect",
            "bypass_emulator_detect", "iap_check_bypass", "force_biometric_success",
            "time_travel", "force_network_error", "api_response_intercept",
        }

        if behavior_script in BUILTIN_BEHAVIORS:
            # Ensure the behavior script is loaded
            script_name = "behaviors"
            if script_name not in self._session._scripts:
                script_path = (
                    "manipulation/ios_behaviors.js"
                    if self.platform == Platform.IOS
                    else "manipulation/android_behaviors.js"
                )
                source = _read_script(script_path)
                self._bridge.inject_script(self._session, source, script_name=script_name)

            try:
                result = self._bridge.rpc_call(
                    self._session, script_name, "enable", behavior_script, opts or {}
                )
                if result.get("ok"):
                    logger.info("Behavior '%s' activated", behavior_script)
                    return True
                else:
                    logger.warning("Behavior '%s' failed: %s",
                                   behavior_script, result.get("reason"))
                    return False
            except Exception as exc:
                logger.error("inject_behavior RPC failed: %s", exc)
                return False

        # Raw JavaScript injection
        script_name = f"custom-{uuid.uuid4().hex[:8]}"
        script = self._bridge.inject_script(
            self._session, behavior_script, script_name=script_name
        )
        return script is not None

    # ──────────────────────────────────────────────────────────────────────────
    # 7. scan_vulnerabilities
    # ──────────────────────────────────────────────────────────────────────────

    def scan_vulnerabilities(
        self,
        app: TargetApp | None = None,
        memory_strings: list[str] | None = None,
    ) -> VulnReport:
        """
        Run automated OWASP MASVS vulnerability checks against the running app.

        Analyses the current trace session (if active) and any supplemental
        memory/string evidence provided.

        Parameters
        ----------
        app:
            TargetApp to associate with the report. Defaults to the currently
            attached app.
        memory_strings:
            List of raw string chunks from a memory dump or log output.
            Scanned for hardcoded secrets matching known patterns.

        Returns
        -------
        VulnReport
            Sorted by severity (CRITICAL → INFO). Each Vulnerability includes
            MASVS control ID, description, evidence, and remediation guidance.
        """
        target = app or (self._session.target if self._session else None)
        if target is None:
            raise RuntimeError("No attached session. Call attach() first.")

        scanner = VulnerabilityScanner(target, trace=self._trace_session)
        if memory_strings:
            scanner.add_memory_scan_results(memory_strings)

        report = scanner.scan()
        logger.info(
            "Vulnerability scan complete: %d findings (%d critical, %d high)",
            len(report.vulnerabilities), report.critical_count, report.high_count,
        )
        return report

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers — script builders
    # ──────────────────────────────────────────────────────────────────────────

    def _require_session(self) -> None:
        if self._session is None or not self._session.is_active:
            raise RuntimeError(
                "No active session. Call attach() before using instrumentation methods."
            )

    @staticmethod
    def _parse_trace_event(payload: dict) -> TraceEvent:
        return TraceEvent(
            event_id=str(payload.get("id", uuid.uuid4())),
            category=TraceCategory(payload.get("category", "network")),
            timestamp=datetime.utcnow(),
            class_name=payload.get("class", ""),
            method_name=payload.get("method", ""),
            args=payload.get("args", {}),
            return_value=payload.get("ret"),
            thread_id=int(payload.get("tid", 0)),
            call_stack=payload.get("stack", []),
        )

    @staticmethod
    def _build_ios_hook_script(
        class_name: str, method_name: str, hook_id: str
    ) -> str:
        """
        Generate a Frida script that intercepts a single ObjC method and
        forwards call details back to Python via send().
        """
        prefix = "+" if method_name.startswith("+") else "-"
        sel = method_name.lstrip("+-").strip()
        escaped_cls = json.dumps(class_name)
        escaped_sel = json.dumps(sel)
        escaped_id  = json.dumps(hook_id)

        return f"""
'use strict';
(function() {{
    if (typeof ObjC === 'undefined') {{ return; }}
    var cls = ObjC.classes[{escaped_cls}];
    if (!cls) {{ send({{ hook_id: {escaped_id}, error: 'class not found' }}); return; }}
    var method = cls['{prefix} ' + {escaped_sel}];
    if (!method) {{ send({{ hook_id: {escaped_id}, error: 'method not found' }}); return; }}

    Interceptor.attach(method.implementation, {{
        onEnter: function(args) {{
            this._args = [];
            for (var i = 2; i < args.length; i++) {{
                try {{ this._args.push(new ObjC.Object(args[i]).toString()); }}
                catch(_) {{ this._args.push(args[i].toString()); }}
            }}
        }},
        onLeave: function(ret) {{
            var retStr;
            try {{ retStr = new ObjC.Object(ret).toString(); }} catch(_) {{ retStr = ret.toString(); }}
            send({{
                hook_id: {escaped_id},
                class: {escaped_cls},
                method: {escaped_sel},
                args: this._args,
                ret: retStr,
                tid: Process.getCurrentThreadId()
            }});
        }}
    }});
}})();
"""

    @staticmethod
    def _build_android_hook_script(
        class_name: str, method_name: str, hook_id: str
    ) -> str:
        """
        Generate a Frida script that intercepts a Java method and sends
        call details back to Python.
        """
        escaped_cls = json.dumps(class_name)
        escaped_m   = json.dumps(method_name)
        escaped_id  = json.dumps(hook_id)

        return f"""
'use strict';
Java.perform(function() {{
    var cls;
    try {{ cls = Java.use({escaped_cls}); }}
    catch(e) {{ send({{ hook_id: {escaped_id}, error: 'class not found: ' + e }}); return; }}

    var method = cls[{escaped_m}];
    if (!method) {{ send({{ hook_id: {escaped_id}, error: 'method not found' }}); return; }}

    // Hook all overloads
    method.overloads.forEach(function(overload) {{
        overload.implementation = function() {{
            var args = Array.prototype.slice.call(arguments).map(String);
            var ret = this[{escaped_m}].apply(this, arguments);
            send({{
                hook_id: {escaped_id},
                class:   {escaped_cls},
                method:  {escaped_m},
                args:    args,
                ret:     String(ret),
                tid:     Process.getCurrentThreadId()
            }});
            return ret;
        }};
    }});
}});
"""

    @staticmethod
    def _build_ios_replace_script(
        class_name: str,
        method_name: str,
        implementation: str,
        hook_id: str,
    ) -> str:
        prefix = "+" if method_name.startswith("+") else "-"
        sel = method_name.lstrip("+-").strip()
        return f"""
'use strict';
(function() {{
    if (typeof ObjC === 'undefined') return;
    var cls = ObjC.classes[{json.dumps(class_name)}];
    if (!cls) return;
    var m = cls['{prefix} {sel}'];
    if (!m) return;
    var orig = m.implementation;
    Interceptor.replace(m.implementation, new NativeCallback(function() {{
        var self_obj = this;
        this.original = function() {{ return orig.apply(self_obj, arguments); }};
        {implementation}
    }}, 'pointer', ['pointer', 'pointer']));
}})();
"""

    @staticmethod
    def _build_android_replace_script(
        class_name: str,
        method_name: str,
        implementation: str,
        hook_id: str,
    ) -> str:
        return f"""
'use strict';
Java.perform(function() {{
    var cls;
    try {{ cls = Java.use({json.dumps(class_name)}); }}
    catch(e) {{ return; }}

    var method = cls[{json.dumps(method_name)}];
    if (!method) return;

    method.overloads.forEach(function(overload) {{
        overload.implementation = function() {{
            var self_obj = this;
            this.original = function() {{
                return overload.call.apply(overload, [self_obj].concat(
                    Array.prototype.slice.call(arguments)));
            }};
            {implementation}
        }};
    }});
}});
"""
