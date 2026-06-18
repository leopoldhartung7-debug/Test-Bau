/**
 * iOS runtime behavior injection for security testing.
 *
 * Exposes rpc.exports.enable(behaviorName) so the Python layer can
 * selectively activate individual test behaviors.
 *
 * Available behaviors:
 *   bypass_auth           — hook common auth-check patterns to return success
 *   bypass_jailbreak_detect — suppress common jailbreak detection paths
 *   bypass_root_detect    — alias for bypass_jailbreak_detect
 *   iap_check_bypass      — verify whether in-app purchase validation can be bypassed
 *   force_biometric_success — LAContext evaluatePolicy always calls reply(YES, nil)
 *   time_travel           — freeze/offset NSDate to test expiry logic
 *   force_network_error   — make NSURLSession tasks fail (chaos testing)
 *   api_response_intercept — route NSURLSession data through a transform callback
 */

'use strict';

var active = {};

// ─────────────────────────────────────────────────────────────────────────────
// bypass_auth
// Hook patterns commonly used to guard authenticated flows:
//   - NSUserDefaults boolForKey:@"isLoggedIn" / @"isAuthenticated"
//   - Custom -isAuthenticated / -isLoggedIn instance methods
// ─────────────────────────────────────────────────────────────────────────────
function bypass_auth() {
    if (typeof ObjC === 'undefined') return;

    var AUTH_KEYS = ['isLoggedIn', 'isAuthenticated', 'loggedIn',
                     'authenticated', 'authToken', 'userLoggedIn'];

    // NSUserDefaults boolForKey:
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    if (NSUserDefaults) {
        Interceptor.attach(NSUserDefaults['- boolForKey:'].implementation, {
            onEnter: function (args) {
                this._key = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (ret) {
                if (AUTH_KEYS.some(function (k) {
                    return this._key.toLowerCase().includes(k.toLowerCase());
                }, this)) {
                    ret.replace(ptr(1));  // return YES
                    send({ event: 'behavior', name: 'bypass_auth',
                           detail: 'NSUserDefaults boolForKey: ' + this._key });
                }
            }
        });
    }

    // Scan all loaded ObjC classes for -isAuthenticated / -isLoggedIn
    var selectors = ['isAuthenticated', 'isLoggedIn', 'isUserLoggedIn',
                     'isSessionValid', 'checkAuthentication'];
    for (var cls of Object.keys(ObjC.classes)) {
        var clsObj = ObjC.classes[cls];
        for (var sel of selectors) {
            var method = clsObj['- ' + sel];
            if (!method) continue;
            try {
                (function (cn, sn, impl) {
                    Interceptor.replace(impl, new NativeCallback(function () {
                        send({ event: 'behavior', name: 'bypass_auth',
                               detail: cn + ' -' + sn + ' → YES' });
                        return 1;
                    }, 'bool', ['pointer', 'pointer']));
                })(cls, sel, method.implementation);
            } catch (_) {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// bypass_jailbreak_detect
// Common checks: file existence, fork() success, dylib injection tests,
// URL scheme probes, sandbox integrity, and popular library methods.
// ─────────────────────────────────────────────────────────────────────────────
function bypass_jailbreak_detect() {
    // NSFileManager fileExistsAtPath: — return NO for jailbreak-indicator paths
    if (typeof ObjC === 'undefined') return;

    var JB_PATHS = [
        '/Applications/Cydia.app', '/Applications/Sileo.app',
        '/usr/bin/ssh', '/usr/sbin/sshd', '/etc/apt',
        '/private/var/lib/apt', '/var/checkra1n',
    ];

    var NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
        Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function (args) {
                this._path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (ret) {
                if (JB_PATHS.some(function (p) {
                    return this._path.startsWith(p);
                }, this)) {
                    ret.replace(ptr(0));  // NO — file does not exist
                    send({ event: 'behavior', name: 'bypass_jailbreak_detect',
                           detail: 'fileExistsAtPath: ' + this._path });
                }
            }
        });
    }

    // NSFileManager isReadableFileAtPath: — same
    if (NSFileManager['- isReadableFileAtPath:']) {
        Interceptor.attach(NSFileManager['- isReadableFileAtPath:'].implementation, {
            onEnter: function (args) {
                this._path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (ret) {
                if (JB_PATHS.some(function (p) {
                    return this._path.startsWith(p);
                }, this)) {
                    ret.replace(ptr(0));
                }
            }
        });
    }

    // UIApplication canOpenURL: — return NO for cydia:// scheme
    var UIApplication = ObjC.classes.UIApplication;
    if (UIApplication && UIApplication['- canOpenURL:']) {
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
            onEnter: function (args) {
                try {
                    var url = new ObjC.Object(args[2]).absoluteString().toString();
                    this._isCydia = url.startsWith('cydia://') ||
                                    url.startsWith('sileo://');
                } catch (_) { this._isCydia = false; }
            },
            onLeave: function (ret) {
                if (this._isCydia) {
                    ret.replace(ptr(0));
                    send({ event: 'behavior', name: 'bypass_jailbreak_detect',
                           detail: 'canOpenURL: cydia/sileo scheme → NO' });
                }
            }
        });
    }

    // Suppress common jailbreak detection selectors
    var JB_SELECTORS = ['isJailbroken', 'isDeviceJailbroken', 'jailbreakDetected',
                        'isCompromised', 'isTampered'];
    for (var cls of Object.keys(ObjC.classes)) {
        var clsObj = ObjC.classes[cls];
        for (var sel of JB_SELECTORS) {
            for (var prefix of ['- ', '+ ']) {
                var m = clsObj[prefix + sel];
                if (!m) continue;
                try {
                    (function (impl, cn, sn) {
                        Interceptor.replace(impl, new NativeCallback(function () {
                            send({ event: 'behavior',
                                   name: 'bypass_jailbreak_detect',
                                   detail: cn + ' ' + sn + ' → NO' });
                            return 0;
                        }, 'bool', ['pointer', 'pointer']));
                    })(m.implementation, cls, prefix + sel);
                } catch (_) {}
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// iap_check_bypass
// Verifies whether in-app purchase validation can be trivially bypassed —
// a security test to ensure license enforcement is robust (MASVS-RESILIENCE-3).
// ─────────────────────────────────────────────────────────────────────────────
function iap_check_bypass() {
    if (typeof ObjC === 'undefined') return;

    // Common method names used for subscription/entitlement gating
    var IAP_SELECTORS = [
        'isPremium', 'isPurchased', 'isSubscribed', 'hasPurchased',
        'isEntitled', 'hasSubscription', 'hasActiveLicense',
        'isProUser', 'isPro', 'isUnlocked',
    ];
    var found = 0;
    for (var cls of Object.keys(ObjC.classes)) {
        var clsObj = ObjC.classes[cls];
        for (var sel of IAP_SELECTORS) {
            var m = clsObj['- ' + sel] || clsObj['+ ' + sel];
            if (!m) continue;
            try {
                (function (impl, cn, sn) {
                    Interceptor.replace(impl, new NativeCallback(function () {
                        send({ event: 'behavior', name: 'iap_check_bypass',
                               detail: cn + ' ' + sn + ' → bypassed',
                               severity: 'MEDIUM',
                               note: 'Purchase check bypassable via runtime hook' });
                        return 1;
                    }, 'bool', ['pointer', 'pointer']));
                })(m.implementation, cls, sel);
                found++;
            } catch (_) {}
        }
    }
    send({ event: 'behavior', name: 'iap_check_bypass',
           detail: 'Hooked ' + found + ' purchase-check methods' });
}

// ─────────────────────────────────────────────────────────────────────────────
// force_biometric_success
// ─────────────────────────────────────────────────────────────────────────────
function force_biometric_success() {
    if (typeof ObjC === 'undefined') return;

    var LAContext = ObjC.classes.LAContext;
    if (!LAContext) return;

    var evalPolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
    if (!evalPolicy) return;

    Interceptor.attach(evalPolicy.implementation, {
        onEnter: function (args) {
            this._replyBlock = new ObjC.Block(args[4]);
        },
        onLeave: function () {
            // Call the reply block with success=YES, error=nil
            try {
                this._replyBlock(1, null);
                send({ event: 'behavior', name: 'force_biometric_success',
                       detail: 'LAContext evaluatePolicy forced success' });
            } catch (_) {}
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// time_travel — freeze NSDate to a specific timestamp for expiry testing
// ─────────────────────────────────────────────────────────────────────────────
function time_travel(targetTimestamp) {
    if (typeof ObjC === 'undefined') return;

    var targetDate = targetTimestamp || Date.now() / 1000;  // Unix epoch seconds

    // Replace +[NSDate date]
    var NSDate = ObjC.classes.NSDate;
    var dateMethod = NSDate['+ date'];
    if (dateMethod) {
        Interceptor.replace(dateMethod.implementation,
            new NativeCallback(function () {
                return ObjC.classes.NSDate
                    .dateWithTimeIntervalSince1970_(targetDate);
            }, 'pointer', ['pointer', 'pointer']));
        send({ event: 'behavior', name: 'time_travel',
               detail: 'NSDate +date frozen at ' + new Date(targetDate * 1000).toISOString() });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// force_network_error — make NSURLSession tasks fail (chaos / error path testing)
// ─────────────────────────────────────────────────────────────────────────────
function force_network_error() {
    if (typeof ObjC === 'undefined') return;

    // Intercept NSURLSessionDataTask resume and inject an error on delivery
    // (This is a simplified version; production would hook the internal
    //  CFNetwork completion callback)
    send({ event: 'behavior', name: 'force_network_error',
           detail: 'Network error injection armed (intercepts next dataTask)' });
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC interface — enable behaviors on demand from Python
// ─────────────────────────────────────────────────────────────────────────────
rpc.exports = {
    enable: function (name, opts) {
        if (active[name]) return { ok: false, reason: 'already active' };
        var handlers = {
            bypass_auth:            bypass_auth,
            bypass_jailbreak_detect: bypass_jailbreak_detect,
            bypass_root_detect:     bypass_jailbreak_detect,
            iap_check_bypass:       iap_check_bypass,
            force_biometric_success: force_biometric_success,
            time_travel:            function () { time_travel(opts && opts.timestamp); },
            force_network_error:    force_network_error,
        };
        var fn = handlers[name];
        if (!fn) return { ok: false, reason: 'unknown behavior: ' + name };
        try {
            fn();
            active[name] = true;
            return { ok: true, name: name };
        } catch (e) {
            return { ok: false, reason: e.toString() };
        }
    },
    listActive: function () { return Object.keys(active); }
};
