/**
 * Android runtime behavior injection for security testing.
 *
 * Exposes rpc.exports.enable(behaviorName, opts) — activated from Python.
 *
 * Available behaviors:
 *   bypass_auth              — hook common auth-check patterns to return true
 *   bypass_root_detect       — suppress common root detection checks
 *   bypass_emulator_detect   — suppress emulator/tamper detection
 *   iap_check_bypass         — test whether billing checks can be bypassed
 *   force_biometric_success  — force BiometricPrompt to call onAuthenticationSucceeded
 *   time_travel              — freeze System.currentTimeMillis() to a target time
 *   force_network_error      — make OkHttp / HttpURLConnection throw IOException
 */

'use strict';

var active = {};

Java.perform(function () {

    // ─────────────────────────────────────────────────────────────────────────
    // bypass_auth
    // ─────────────────────────────────────────────────────────────────────────
    function bypass_auth() {
        // SharedPreferences: if key contains auth/login/token, return true
        var AUTH_KEYS = ['isloggedin', 'authenticated', 'isauthed',
                         'loginstate', 'authtoken', 'userloggedin'];
        try {
            var SharedPrefsImpl = Java.use('android.app.SharedPreferencesImpl');
            SharedPrefsImpl.getBoolean.implementation = function (key, defVal) {
                var lkey = key.toLowerCase();
                if (AUTH_KEYS.some(function (k) { return lkey.includes(k); })) {
                    send({ event: 'behavior', name: 'bypass_auth',
                           detail: 'SharedPreferences.getBoolean("' + key + '") → true' });
                    return true;
                }
                return this.getBoolean(key, defVal);
            };
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // bypass_root_detect
    // ─────────────────────────────────────────────────────────────────────────
    function bypass_root_detect() {
        // File.exists() — return false for root-indicator paths
        var ROOT_PATHS = [
            '/system/app/Superuser.apk', '/system/xbin/su',
            '/data/local/xbin/su', '/sbin/su',
            '/data/adb/magisk', '/sbin/.magisk',
        ];
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                if (ROOT_PATHS.some(function (p) { return path === p || path.startsWith(p); })) {
                    send({ event: 'behavior', name: 'bypass_root_detect',
                           detail: 'File.exists(' + path + ') → false' });
                    return false;
                }
                return this.exists();
            };
        } catch (_) {}

        // Runtime.exec — swallow "su" subprocess attempts
        try {
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('[Ljava.lang.String;').implementation =
                function (cmdArr) {
                    if (cmdArr && cmdArr.length > 0 && cmdArr[0] === 'su') {
                        send({ event: 'behavior', name: 'bypass_root_detect',
                               detail: 'Runtime.exec(["su",...]) suppressed' });
                        // Return a process that immediately exits with code 1
                        return Runtime.exec(['false']);
                    }
                    return this.exec(cmdArr);
                };
        } catch (_) {}

        // PackageManager.getPackageInfo — hide Magisk / root manager packages
        var ROOT_PKGS = ['com.topjohnwu.magisk', 'io.github.huskydg.magisk',
                         'com.koushikdutta.superuser', 'eu.chainfire.supersu'];
        try {
            var PackageManager = Java.use('android.app.ApplicationPackageManager');
            PackageManager.getPackageInfo.overload(
                'java.lang.String', 'int'
            ).implementation = function (pkg, flags) {
                if (ROOT_PKGS.includes(pkg)) {
                    send({ event: 'behavior', name: 'bypass_root_detect',
                           detail: 'getPackageInfo(' + pkg + ') → NameNotFoundException' });
                    var ex = Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
                    throw ex;
                }
                return this.getPackageInfo(pkg, flags);
            };
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // bypass_emulator_detect
    // ─────────────────────────────────────────────────────────────────────────
    function bypass_emulator_detect() {
        // Build.FINGERPRINT, Build.MODEL, etc. are static fields;
        // hook via reflection to return real-device-like values.
        try {
            var Build = Java.use('android.os.Build');
            Build.FINGERPRINT.value   = 'google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys';
            Build.MODEL.value         = 'Pixel 2';
            Build.MANUFACTURER.value  = 'Google';
            Build.BRAND.value         = 'google';
            Build.DEVICE.value        = 'walleye';
            Build.PRODUCT.value       = 'walleye';
            send({ event: 'behavior', name: 'bypass_emulator_detect',
                   detail: 'Build fields spoofed to Pixel 2' });
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // iap_check_bypass
    // Tests whether Google Play Billing or custom license checks are bypassable
    // (MASVS-RESILIENCE-3).
    // ─────────────────────────────────────────────────────────────────────────
    function iap_check_bypass() {
        // BillingClient.queryPurchasesAsync — not trivially hookable at Java level
        // but custom license check methods often surface with these names:
        var LICENSE_METHODS = ['isPremium', 'isPurchased', 'isSubscribed',
                               'hasPurchased', 'isEntitled', 'isProUser',
                               'isUnlocked', 'checkLicense', 'verifyPurchase'];
        var found = 0;
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                try {
                    var cls = Java.use(name);
                    for (var m of LICENSE_METHODS) {
                        try {
                            var method = cls[m];
                            if (!method) continue;
                            // Only override boolean-returning overloads with no args
                            for (var overload of method.overloads) {
                                if (overload.returnType.name === 'boolean' &&
                                        overload.argumentTypes.length === 0) {
                                    (function (ov, cn, mn) {
                                        ov.implementation = function () {
                                            send({ event: 'behavior',
                                                   name: 'iap_check_bypass',
                                                   detail: cn + '.' + mn + '() → true',
                                                   severity: 'MEDIUM',
                                                   note: 'Purchase check bypassable' });
                                            return true;
                                        };
                                    })(overload, name, m);
                                    found++;
                                }
                            }
                        } catch (_) {}
                    }
                } catch (_) {}
            },
            onComplete: function () {
                send({ event: 'behavior', name: 'iap_check_bypass',
                       detail: 'Hooked ' + found + ' purchase-check methods' });
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // force_biometric_success
    // ─────────────────────────────────────────────────────────────────────────
    function force_biometric_success() {
        try {
            var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
            // Intercept authenticate and immediately call onAuthenticationSucceeded
            // on the callback with a null result (no CryptoObject needed for bypass test)
            BiometricPrompt.authenticate.overload(
                'android.hardware.biometrics.BiometricPrompt$CryptoObject',
                'android.os.CancellationSignal',
                'java.util.concurrent.Executor',
                'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
            ).implementation = function (crypto, cancel, exec, callback) {
                send({ event: 'behavior', name: 'force_biometric_success',
                       detail: 'BiometricPrompt.authenticate intercepted' });
                // Invoke onAuthenticationSucceeded with null result
                var result = Java.use(
                    'android.hardware.biometrics.BiometricPrompt$AuthenticationResult'
                ).$new(null, null, 0);
                callback.onAuthenticationSucceeded(result);
            };
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // time_travel — freeze System.currentTimeMillis() for expiry testing
    // ─────────────────────────────────────────────────────────────────────────
    function time_travel(targetMs) {
        var target = targetMs || Date.now();
        try {
            var System = Java.use('java.lang.System');
            System.currentTimeMillis.implementation = function () {
                return Java.use('java.lang.Long').valueOf(target);
            };
            send({ event: 'behavior', name: 'time_travel',
                   detail: 'System.currentTimeMillis frozen at ' +
                            new Date(target).toISOString() });
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // force_network_error — make OkHttp calls throw IOException (chaos testing)
    // ─────────────────────────────────────────────────────────────────────────
    function force_network_error() {
        try {
            var RealCall = Java.use('okhttp3.RealCall');
            RealCall.execute.implementation = function () {
                send({ event: 'behavior', name: 'force_network_error',
                       detail: 'OkHttp RealCall.execute → IOException' });
                throw Java.use('java.io.IOException').$new('AppHook: injected network error');
            };
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RPC interface
    // ─────────────────────────────────────────────────────────────────────────
    var HANDLERS = {
        bypass_auth:             bypass_auth,
        bypass_root_detect:      bypass_root_detect,
        bypass_emulator_detect:  bypass_emulator_detect,
        iap_check_bypass:        iap_check_bypass,
        force_biometric_success: force_biometric_success,
        time_travel:             function (opts) { time_travel(opts && opts.timestamp_ms); },
        force_network_error:     force_network_error,
    };

    rpc.exports = {
        enable: function (name, opts) {
            if (active[name]) return { ok: false, reason: 'already active' };
            var fn = HANDLERS[name];
            if (!fn) return { ok: false, reason: 'unknown behavior: ' + name };
            try {
                fn(opts);
                active[name] = true;
                return { ok: true, name: name };
            } catch (e) {
                return { ok: false, reason: e.toString() };
            }
        },
        listActive: function () { return Object.keys(active); }
    };
});
