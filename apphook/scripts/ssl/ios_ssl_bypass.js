/**
 * iOS SSL/TLS certificate pinning bypass.
 *
 * Hooks the following layers in order of interception depth:
 *   1. Security.framework low-level   — SecTrustEvaluate / SecTrustEvaluateWithError
 *   2. CFNetwork                       — SSLHandshake, SSLCreateContext
 *   3. NSURLSession delegate           — URLSession:didReceiveChallenge:completionHandler:
 *   4. AFNetworking                    — AFSecurityPolicy setSSLPinningMode / evaluateServerTrust
 *   5. Alamofire                       — ServerTrustManager / DefaultTrustEvaluator
 *   6. TrustKit                        — TSKPinningValidator
 *
 * Frida MASTG reference: https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/
 */

'use strict';

var bypassed = [];

// ─────────────────────────────────────────────────────────────────────────────
// 1. SecTrustEvaluate (legacy, pre-iOS 12)
// ─────────────────────────────────────────────────────────────────────────────
(function hookSecTrustEvaluate() {
    var fnPtr = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (!fnPtr) return;

    Interceptor.replace(fnPtr, new NativeCallback(function (trust, result) {
        // kSecTrustResultProceed = 1
        if (result && !result.isNull()) {
            Memory.writeU32(result, 1);
        }
        bypassed.push('SecTrustEvaluate');
        return 0; // errSecSuccess
    }, 'int', ['pointer', 'pointer']));
})();

// ─────────────────────────────────────────────────────────────────────────────
// 2. SecTrustEvaluateWithError (iOS 12+)
// ─────────────────────────────────────────────────────────────────────────────
(function hookSecTrustEvaluateWithError() {
    var fnPtr = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (!fnPtr) return;

    Interceptor.replace(fnPtr, new NativeCallback(function (trust, error) {
        // Clear the error pointer so callers think validation succeeded
        if (error && !error.isNull()) {
            Memory.writePointer(error, NULL);
        }
        bypassed.push('SecTrustEvaluateWithError');
        return 1; // true = trusted
    }, 'bool', ['pointer', 'pointer']));
})();

// ─────────────────────────────────────────────────────────────────────────────
// 3. SSLHandshake (CFNetwork / libssl)
// ─────────────────────────────────────────────────────────────────────────────
(function hookSSLHandshake() {
    var fnPtr = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_verify') ||
                Module.findExportByName('libssl.dylib', 'SSL_CTX_set_verify');
    if (!fnPtr) return;

    // Replace the verify_mode so the SSL context never checks peer certs
    Interceptor.attach(fnPtr, {
        onEnter: function (args) {
            // SSL_VERIFY_NONE = 0
            args[1] = ptr(0);
        }
    });
    bypassed.push('SSL_CTX_set_verify');
})();

// ─────────────────────────────────────────────────────────────────────────────
// 4. NSURLSession credential challenge delegate
// ─────────────────────────────────────────────────────────────────────────────
(function hookNSURLSessionDelegate() {
    if (typeof ObjC === 'undefined') return;

    // Any class implementing URLSession:didReceiveChallenge:completionHandler:
    var selector = 'URLSession:didReceiveChallenge:completionHandler:';
    for (var className of ObjC.enumerateLoadedClassesSync()) {
        var cls;
        try { cls = ObjC.classes[className]; } catch (_) { continue; }
        if (!cls || !cls['- ' + selector]) continue;

        try {
            Interceptor.attach(cls['- ' + selector].implementation, {
                onEnter: function (args) {
                    // args[3] is the NSURLAuthenticationChallenge
                    // args[4] is the completionHandler block
                    // Call handler with NSURLSessionAuthChallengeUseCredential (0) and
                    // a credential that accepts any certificate.
                    var challenge = new ObjC.Object(args[3]);
                    var handler  = new ObjC.Block(args[4]);

                    var protectionSpace = challenge.protectionSpace();
                    if (protectionSpace.authenticationMethod().toString()
                            .includes('ServerTrust')) {
                        var trust = protectionSpace.serverTrust();
                        var cred  = ObjC.classes.NSURLCredential
                            .credentialForTrust_(trust);
                        handler(0, cred);  // NSURLSessionAuthChallengeUseCredential
                        this._handled = true;
                    }
                },
                onLeave: function () {}
            });
            bypassed.push('NSURLSessionDelegate:' + className);
        } catch (_) {}
    }
})();

// ─────────────────────────────────────────────────────────────────────────────
// 5. AFNetworking — AFSecurityPolicy
// ─────────────────────────────────────────────────────────────────────────────
(function hookAFNetworking() {
    if (typeof ObjC === 'undefined') return;

    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (!AFSecurityPolicy) return;

    try {
        // evaluateServerTrust:forDomain: → always return YES
        var evalImpl = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
        if (evalImpl) {
            Interceptor.replace(evalImpl.implementation,
                new NativeCallback(function () { return 1; }, 'bool',
                    ['pointer', 'pointer', 'pointer', 'pointer']));
            bypassed.push('AFNetworking:evaluateServerTrust:forDomain:');
        }

        // setSSLPinningMode: → force AFSSLPinningModeNone (0)
        var modeImpl = AFSecurityPolicy['- setSSLPinningMode:'];
        if (modeImpl) {
            Interceptor.replace(modeImpl.implementation,
                new NativeCallback(function () {}, 'void',
                    ['pointer', 'pointer', 'int']));
            bypassed.push('AFNetworking:setSSLPinningMode:');
        }
    } catch (_) {}
})();

// ─────────────────────────────────────────────────────────────────────────────
// 6. Alamofire — DefaultTrustEvaluator / PinnedCertificatesTrustEvaluator
// ─────────────────────────────────────────────────────────────────────────────
(function hookAlamofire() {
    if (typeof ObjC === 'undefined') return;

    // Alamofire Swift classes are name-mangled — search by prefix
    var targets = [
        'AlamofireDefaultTrustEvaluator',
        'AlamofirePinnedCertificatesTrustEvaluator',
        'AlamofirePublicKeysTrustEvaluator',
        'AlamofireRevocationTrustEvaluator',
        'AlamofireCompositeTrustEvaluator',
    ];

    for (var cls of Object.keys(ObjC.classes)) {
        var lc = cls.toLowerCase();
        if (!lc.includes('alamofire') && !lc.includes('trusteval')) continue;

        var clsObj = ObjC.classes[cls];
        if (!clsObj) continue;
        var evalFn = clsObj['- evaluate:forHost:'];
        if (!evalFn) continue;

        try {
            Interceptor.replace(evalFn.implementation,
                new NativeCallback(function () {}, 'void',
                    ['pointer', 'pointer', 'pointer', 'pointer']));
            bypassed.push('Alamofire:evaluate:forHost::' + cls);
        } catch (_) {}
    }
})();

// ─────────────────────────────────────────────────────────────────────────────
// 7. TrustKit
// ─────────────────────────────────────────────────────────────────────────────
(function hookTrustKit() {
    if (typeof ObjC === 'undefined') return;

    var TKPinningValidator = ObjC.classes.TSKPinningValidator;
    if (!TKPinningValidator) return;

    try {
        var evalImpl = TKPinningValidator['+ evaluateTrust:forHostname:'];
        if (evalImpl) {
            // TSKTrustDecisionShouldAllowConnection = 0
            Interceptor.replace(evalImpl.implementation,
                new NativeCallback(function () { return 0; }, 'int',
                    ['pointer', 'pointer', 'pointer', 'pointer']));
            bypassed.push('TrustKit:evaluateTrust:forHostname:');
        }
    } catch (_) {}
})();

// ─────────────────────────────────────────────────────────────────────────────
// RPC exports — let Python query which hooks fired
// ─────────────────────────────────────────────────────────────────────────────
rpc.exports = {
    getBypassed: function () { return bypassed; },
    getCount:    function () { return bypassed.length; }
};
