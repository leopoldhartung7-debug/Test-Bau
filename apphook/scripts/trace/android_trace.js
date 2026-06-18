/**
 * Android runtime API tracing — crypto, filesystem, keystore, network, biometrics.
 *
 * Each intercepted call emits via send():
 *   { event: 'trace', category: '...', class: '...', method: '...',
 *     args: [...], ret: ..., tid: N, stack: [...] }
 */

'use strict';

var activeCategories = {};
var eventCounter = 0;

function emit(category, cls, method, args, ret) {
    if (!activeCategories[category]) return;
    var stack = [];
    try {
        stack = Java.use('java.lang.Thread')
            .currentThread()
            .getStackTrace()
            .slice(2, 10)
            .map(function (f) { return f.toString(); });
    } catch (_) {}

    send({
        event:    'trace',
        id:       ++eventCounter,
        category: category,
        class:    cls,
        method:   method,
        args:     args,
        ret:      ret,
        tid:      Process.getCurrentThreadId(),
        stack:    stack
    });
}

Java.perform(function () {

    // ─────────────────────────────────────────────────────────────────────────
    // CRYPTO — javax.crypto.Cipher
    // ─────────────────────────────────────────────────────────────────────────
    function hookCrypto() {
        var Cipher = Java.use('javax.crypto.Cipher');

        // Cipher.getInstance — log algorithm
        Cipher.getInstance.overload('java.lang.String').implementation =
            function (transformation) {
                emit('crypto', 'Cipher', 'getInstance',
                     { transformation: transformation }, null);
                return this.getInstance(transformation);
            };

        // Cipher.init — log key material
        Cipher.init.overload('int', 'java.security.Key').implementation =
            function (opmode, key) {
                var keyHex = '';
                try {
                    keyHex = bytesToHex(key.getEncoded());
                } catch (_) {}
                emit('crypto', 'Cipher', 'init',
                     { opmode: opmode === 1 ? 'ENCRYPT' : 'DECRYPT',
                       algorithm: key.getAlgorithm(), key_hex: keyHex }, null);
                return this.init(opmode, key);
            };

        // Cipher.doFinal — capture plaintext/ciphertext
        Cipher.doFinal.overload('[B').implementation = function (data) {
            var preview = data ? bytesToHex(data).substring(0, 64) : '';
            var result  = this.doFinal(data);
            emit('crypto', 'Cipher', 'doFinal',
                 { input_preview: preview, input_length: data ? data.length : 0 },
                 result ? bytesToHex(result).substring(0, 64) : null);
            return result;
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // KEYSTORE — Android Keystore + SharedPreferences credential patterns
    // ─────────────────────────────────────────────────────────────────────────
    function hookKeystore() {
        var KeyStore = Java.use('java.security.KeyStore');

        KeyStore.getInstance.overload('java.lang.String').implementation =
            function (type) {
                emit('keychain', 'KeyStore', 'getInstance', { type: type }, null);
                return this.getInstance(type);
            };

        KeyStore.getEntry.overload(
            'java.lang.String',
            'java.security.KeyStore$ProtectionParameter'
        ).implementation = function (alias, param) {
            var entry = this.getEntry(alias, param);
            emit('keychain', 'KeyStore', 'getEntry', { alias: alias },
                 entry ? entry.getClass().getName() : null);
            return entry;
        };

        KeyStore.setEntry.overload(
            'java.lang.String',
            'java.security.KeyStore$Entry',
            'java.security.KeyStore$ProtectionParameter'
        ).implementation = function (alias, entry, param) {
            emit('keychain', 'KeyStore', 'setEntry', { alias: alias }, null);
            return this.setEntry(alias, entry, param);
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FILESYSTEM — insecure storage patterns
    // ─────────────────────────────────────────────────────────────────────────
    function hookFilesystem() {
        // SharedPreferences — plaintext key-value storage
        var SharedPrefs = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        try {
            SharedPrefs.putString.implementation = function (key, value) {
                emit('filesystem', 'SharedPreferences', 'putString',
                     { key: key, value_preview: value ? value.substring(0, 80) : null }, null);
                return this.putString(key, value);
            };
        } catch (_) {}

        // FileOutputStream — track file writes
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.io.File').implementation = function (file) {
            try {
                emit('filesystem', 'FileOutputStream', '<init>',
                     { path: file.getAbsolutePath() }, null);
            } catch (_) {}
            return this.$init(file);
        };

        // SQLiteDatabase — query / execSQL
        var SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
            .implementation = function (sql, selectionArgs) {
                emit('filesystem', 'SQLiteDatabase', 'rawQuery',
                     { sql: sql.substring(0, 200) }, null);
                return this.rawQuery(sql, selectionArgs);
            };
        SQLiteDB.execSQL.overload('java.lang.String').implementation =
            function (sql) {
                emit('filesystem', 'SQLiteDatabase', 'execSQL',
                     { sql: sql.substring(0, 200) }, null);
                return this.execSQL(sql);
            };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NETWORK — OkHttp3 and HttpURLConnection
    // ─────────────────────────────────────────────────────────────────────────
    function hookNetwork() {
        // OkHttp3 — RealCall.execute()
        try {
            var RealCall = Java.use('okhttp3.RealCall');
            RealCall.execute.implementation = function () {
                try {
                    var req = this.request();
                    emit('network', 'okhttp3.RealCall', 'execute', {
                        url:    req.url().toString(),
                        method: req.method()
                    }, null);
                } catch (_) {}
                return this.execute();
            };
        } catch (_) {}

        // HttpURLConnection
        try {
            var HttpURLConn = Java.use('java.net.HttpURLConnection');
            HttpURLConn.connect.implementation = function () {
                try {
                    emit('network', 'HttpURLConnection', 'connect',
                         { url: this.getURL().toString() }, null);
                } catch (_) {}
                return this.connect();
            };
        } catch (_) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BIOMETRICS — BiometricPrompt / FingerprintManager
    // ─────────────────────────────────────────────────────────────────────────
    function hookBiometrics() {
        try {
            var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
            BiometricPrompt.authenticate.overload(
                'android.hardware.biometrics.BiometricPrompt$CryptoObject',
                'android.os.CancellationSignal',
                'java.util.concurrent.Executor',
                'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
            ).implementation = function (crypto, cancel, exec, cb) {
                emit('biometrics', 'BiometricPrompt', 'authenticate',
                     { has_crypto: crypto !== null }, null);
                return this.authenticate(crypto, cancel, exec, cb);
            };
        } catch (_) {}

        // Legacy FingerprintManager
        try {
            var FPM = Java.use('android.hardware.fingerprint.FingerprintManager');
            FPM.authenticate.overload(
                'android.hardware.fingerprint.FingerprintManager$CryptoObject',
                'android.os.CancellationSignal',
                'int',
                'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                'android.os.Handler'
            ).implementation = function (crypto, cancel, flags, cb, handler) {
                emit('biometrics', 'FingerprintManager', 'authenticate',
                     { has_crypto: crypto !== null, flags: flags }, null);
                return this.authenticate(crypto, cancel, flags, cb, handler);
            };
        } catch (_) {}
    }

    hookCrypto();
    hookKeystore();
    hookFilesystem();
    hookNetwork();
    hookBiometrics();

    send({ event: 'trace_loaded' });
});

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function bytesToHex(bytes) {
    return Array.from(bytes).map(function (b) {
        return ('0' + (b & 0xff).toString(16)).slice(-2);
    }).join('');
}

rpc.exports = {
    setCategories: function (cats) {
        activeCategories = {};
        cats.forEach(function (c) { activeCategories[c] = true; });
        return Object.keys(activeCategories);
    },
    getEventCount: function () { return eventCounter; }
};
