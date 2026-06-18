"""
Tests for RuntimeInstrumentor — offline tests only (no Frida device required).

We test: script builder logic, hook ID generation, script path resolution,
and the require_session guard. Frida-dependent paths are skipped.
"""

import pytest
import json

from apphook.instrumentor import RuntimeInstrumentor
from apphook.models import Platform, SessionState


class TestScriptBuilders:
    """Verify generated Frida JavaScript is syntactically reasonable."""

    def test_ios_hook_script_contains_class_name(self):
        js = RuntimeInstrumentor._build_ios_hook_script(
            "AFNetworking", "setSSLPinningMode:", "hook-001"
        )
        assert "AFNetworking" in js
        assert "setSSLPinningMode:" in js
        assert "hook-001" in js
        assert "Interceptor.attach" in js

    def test_ios_hook_script_class_method_prefix(self):
        # Class methods use '+' prefix
        js = RuntimeInstrumentor._build_ios_hook_script(
            "NSURLSession", "+sharedSession", "hook-002"
        )
        assert "'+ '" in js or '"+ "' in js or "'+'" in js or "'+ ' +" in js

    def test_android_hook_script_contains_class_name(self):
        js = RuntimeInstrumentor._build_android_hook_script(
            "okhttp3.OkHttpClient", "newCall", "hook-003"
        )
        assert "okhttp3.OkHttpClient" in js
        assert "newCall" in js
        assert "Java.perform" in js
        assert "overloads" in js

    def test_ios_replace_script_contains_implementation(self):
        impl = "return 1;"
        js = RuntimeInstrumentor._build_ios_replace_script(
            "NSFileManager", "fileExistsAtPath:", impl, "replace-001"
        )
        assert "return 1;" in js
        assert "Interceptor.replace" in js
        assert "NSFileManager" in js

    def test_android_replace_script_contains_implementation(self):
        impl = "return true;"
        js = RuntimeInstrumentor._build_android_replace_script(
            "com.example.Auth", "isLoggedIn", impl, "replace-002"
        )
        assert "return true;" in js
        assert "com.example.Auth" in js
        assert "Java.perform" in js

    def test_hook_script_valid_json_embedded_strings(self):
        # Class names with dots and colons should be JSON-safe
        js = RuntimeInstrumentor._build_android_hook_script(
            "com.example.auth.AuthManager",
            "checkCredentials",
            "hook-004",
        )
        # All string literals embedded via json.dumps should be parseable
        # Extract one we know: the class name
        assert json.dumps("com.example.auth.AuthManager") in js


class TestRequireSession:
    def test_methods_raise_without_session(self):
        instr = RuntimeInstrumentor(platform=Platform.IOS)
        with pytest.raises(RuntimeError, match="No active session"):
            instr.hook_method("NSObject", "description")

    def test_bypass_ssl_raises_without_session(self):
        instr = RuntimeInstrumentor(platform=Platform.ANDROID)
        with pytest.raises(RuntimeError, match="No active session"):
            instr.bypass_ssl_pinning()

    def test_start_tracing_raises_without_session(self):
        from apphook.models import TraceCategory
        instr = RuntimeInstrumentor(platform=Platform.IOS)
        with pytest.raises(RuntimeError, match="No active session"):
            instr.start_tracing([TraceCategory.NETWORK])

    def test_inject_behavior_raises_without_session(self):
        instr = RuntimeInstrumentor(platform=Platform.ANDROID)
        with pytest.raises(RuntimeError, match="No active session"):
            instr.inject_behavior("bypass_root_detect")

    def test_scan_vulnerabilities_raises_without_session(self):
        instr = RuntimeInstrumentor(platform=Platform.IOS)
        with pytest.raises(RuntimeError, match="No attached session"):
            instr.scan_vulnerabilities()


class TestScriptPathResolution:
    """Verify all Frida script files exist and are non-empty."""

    def test_ios_ssl_bypass_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/ssl/ios_ssl_bypass.js"
        assert p.exists()
        assert len(p.read_text()) > 100

    def test_android_ssl_bypass_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/ssl/android_ssl_bypass.js"
        assert p.exists()
        assert len(p.read_text()) > 100

    def test_ios_trace_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/trace/ios_trace.js"
        assert p.exists()
        assert "rpc.exports" in p.read_text()

    def test_android_trace_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/trace/android_trace.js"
        assert p.exists()
        assert "Java.perform" in p.read_text()

    def test_ios_behaviors_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/manipulation/ios_behaviors.js"
        assert p.exists()
        assert "bypass_auth" in p.read_text()

    def test_android_behaviors_script_exists(self):
        from pathlib import Path
        p = Path(__file__).parent.parent / "apphook/scripts/manipulation/android_behaviors.js"
        assert p.exists()
        assert "bypass_root_detect" in p.read_text()


class TestTraceEventParsing:
    def test_parse_valid_payload(self):
        from apphook.models import TraceCategory
        payload = {
            "event": "trace",
            "id": 42,
            "category": "crypto",
            "class": "javax.crypto.Cipher",
            "method": "getInstance",
            "args": {"transformation": "AES/GCM/NoPadding"},
            "ret": None,
            "tid": 1234,
            "stack": ["frame1", "frame2"],
        }
        ev = RuntimeInstrumentor._parse_trace_event(payload)
        assert ev.category == TraceCategory.CRYPTO
        assert ev.class_name == "javax.crypto.Cipher"
        assert ev.thread_id == 1234
        assert ev.args == {"transformation": "AES/GCM/NoPadding"}


class TestInstrumentorInit:
    def test_platform_stored(self):
        instr = RuntimeInstrumentor(Platform.IOS)
        assert instr.platform == Platform.IOS

    def test_proxy_config_stored(self):
        instr = RuntimeInstrumentor(
            Platform.ANDROID,
            proxy_host="10.0.0.1",
            proxy_port=8080,
        )
        assert instr.proxy_host == "10.0.0.1"
        assert instr.proxy_port == 8080
