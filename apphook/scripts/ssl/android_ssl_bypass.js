/**
 * Android SSL/TLS certificate pinning bypass.
 *
 * Hooks the following layers:
 *   1. javax.net.ssl.TrustManager      — custom X509TrustManager replacing all checks
 *   2. javax.net.ssl.SSLContext        — inject permissive TrustManager
 *   3. okhttp3.CertificatePinner       — replace check() with no-op
 *   4. okhttp3 / OkHttp legacy         — HostnameVerifier always true
 *   5. com.android.org.conscrypt       — NativeCrypto / SSL_do_handshake
 *   6. Network Security Config         — hook NetworkSecurityConfig fallback
 *   7. WebViewClient                   — onReceivedSslError always proceed
 *   8. Apache HttpClient               — SSLSocketFactory allowAllHostnameVerifier
 *
 * OWASP MASTG reference: https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/
 */

'use strict';

var bypassed = [];

Java.perform(function () {

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Blanket TrustManager — accepts any certificate for any host
    // ─────────────────────────────────────────────────────────────────────────
    var TrustManager = Java.registerClass({
        name: 'com.apphook.PermissiveTrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Inject into SSLContext.init()
    // ─────────────────────────────────────────────────────────────────────────
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (km, tms, sr) {
        var permissive = Java.array('Ljavax.net.ssl.TrustManager;',
            [TrustManager.$new()]);
        this.init(km, permissive, sr);
        bypassed.push('SSLContext.init');
    };

    // ─────────────────────────────────────────────────────────────────────────
    // 3. OkHttp3 — CertificatePinner.check()
    // ─────────────────────────────────────────────────────────────────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');

        // check(hostname, peerCertificates) — v3.x
        var checkV3 = CertPinner.check.overload(
            'java.lang.String', 'java.util.List');
        if (checkV3) {
            checkV3.implementation = function (host, certs) {
                bypassed.push('okhttp3.CertificatePinner.check(host,List)');
            };
        }
        // check(hostname, vararg) — older overloads
        try {
            CertPinner.check.overload('java.lang.String',
                '[Ljava.security.cert.Certificate;').implementation =
                function (host, certs) {
                    bypassed.push('okhttp3.CertificatePinner.check(host,[])');
                };
        } catch (_) {}
    } catch (_) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 4. OkHttp / OkHttp3 HostnameVerifier
    // ─────────────────────────────────────────────────────────────────────────
    var AllowAllVerifier = Java.registerClass({
        name: 'com.apphook.AllowAllVerifier',
        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
        methods: {
            verify: function (hostname, session) { return true; }
        }
    });

    try {
        var HttpsURLConnection =
            Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation =
            function (_) {
                this.setDefaultHostnameVerifier(AllowAllVerifier.$new());
                bypassed.push('HttpsURLConnection.setDefaultHostnameVerifier');
            };
        HttpsURLConnection.setHostnameVerifier.implementation =
            function (_) {
                this.setHostnameVerifier(AllowAllVerifier.$new());
                bypassed.push('HttpsURLConnection.setHostnameVerifier');
            };
    } catch (_) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Android Network Security Config — disable cleartext / pinning policy
    // ─────────────────────────────────────────────────────────────────────────
    try {
        var NetworkSecurityTrustManager =
            Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkPins.implementation = function (chain) {
            bypassed.push('NetworkSecurityTrustManager.checkPins');
        };
    } catch (_) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Conscrypt — OpenSSLSocketImpl / NativeCrypto verify callback
    // ─────────────────────────────────────────────────────────────────────────
    try {
        var OpenSSLSocketImpl =
            Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation =
            function (certRefs, authMethod) {
                bypassed.push('conscrypt.OpenSSLSocketImpl.verifyCertificateChain');
            };
    } catch (_) {}

    try {
        var ConscryptSocket =
            Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket');
        ConscryptSocket.verifyCertificateChain.implementation =
            function (certRefs, authMethod) {
                bypassed.push('conscrypt.ConscryptFileDescriptorSocket.verifyCertificateChain');
            };
    } catch (_) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 7. WebViewClient.onReceivedSslError — always proceed
    // ─────────────────────────────────────────────────────────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload(
            'android.webkit.WebView',
            'android.webkit.SslErrorHandler',
            'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            handler.proceed();
            bypassed.push('WebViewClient.onReceivedSslError');
        };
    } catch (_) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 8. Apache HttpClient (legacy) — AllowAllHostnameVerifier
    // ─────────────────────────────────────────────────────────────────────────
    try {
        var AllowAllApache =
            Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier');
        var SSLSocketFactory =
            Java.use('org.apache.http.conn.ssl.SSLSocketFactory');
        SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER.value = AllowAllApache.$new();
        bypassed.push('Apache.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER');
    } catch (_) {}

    send({ event: 'ssl_bypass_loaded', count: bypassed.length });
});

rpc.exports = {
    getBypassed: function () { return bypassed; },
    getCount:    function () { return bypassed.length; }
};
