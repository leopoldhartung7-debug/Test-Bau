/**
 * iOS runtime API tracing — crypto, filesystem, keychain, network, biometrics.
 *
 * Each intercepted call emits a structured message via send():
 *   { event: 'trace', category: '...', class: '...', method: '...',
 *     args: [...], ret: ..., tid: N, stack: [...] }
 *
 * Enabled categories are controlled via rpc.exports.setCategories([...]).
 */

'use strict';

var activeCategories = {};
var eventCounter = 0;

function emit(category, cls, method, args, ret) {
    if (!activeCategories[category]) return;
    var stack = [];
    try {
        stack = Thread.backtrace(this && this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .slice(0, 8)
            .map(function (s) { return s.toString(); });
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

// ─────────────────────────────────────────────────────────────────────────────
// CRYPTO — CommonCrypto & Security.framework
// ─────────────────────────────────────────────────────────────────────────────
function hookCrypto() {
    // CCCrypt — symmetric encryption/decryption (AES, DES, 3DES, RC4, etc.)
    var CCCryptPtr = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt') ||
                     Module.findExportByName(null, 'CCCrypt');
    if (CCCryptPtr) {
        Interceptor.attach(CCCryptPtr, {
            onEnter: function (args) {
                // CCOperation: 0=encrypt, 1=decrypt
                this._op   = args[0].toInt32();
                this._algo = args[1].toInt32();
                this._dataLen = args[5].toInt32();
                try {
                    this._keyHex = hexdump(args[3], { length: args[4].toInt32(), header: false })
                        .split('\n').map(function (l) { return l.substr(10, 47); }).join('');
                    this._data   = Memory.readByteArray(args[5], Math.min(this._dataLen, 256));
                } catch (_) {}
            },
            onLeave: function (ret) {
                emit.call(this, 'crypto', 'CommonCrypto', 'CCCrypt', {
                    operation:   this._op === 0 ? 'encrypt' : 'decrypt',
                    algorithm:   this._algo,
                    key_hex:     this._keyHex,
                    plaintext_preview: this._data ? Array.from(new Uint8Array(this._data)).slice(0, 32) : null,
                    data_length: this._dataLen
                }, ret.toInt32());
            }
        });
    }

    // SecKeyCreateEncryptedData / SecKeyCreateDecryptedData
    for (var fn of ['SecKeyCreateEncryptedData', 'SecKeyCreateDecryptedData']) {
        var ptr = Module.findExportByName('Security', fn);
        if (!ptr) continue;
        (function (fnName) {
            Interceptor.attach(ptr, {
                onEnter: function (args) { this._args = args; },
                onLeave: function (ret) {
                    emit.call(this, 'crypto', 'Security', fnName, {
                        algorithm: this._args[1].toInt32()
                    }, ret.isNull() ? null : 'CFDataRef');
                }
            });
        })(fn);
    }

    // SecKeyRawSign / SecKeyRawVerify
    for (var fn2 of ['SecKeyRawSign', 'SecKeyRawVerify']) {
        var ptr2 = Module.findExportByName('Security', fn2);
        if (!ptr2) continue;
        (function (fnName) {
            Interceptor.attach(ptr2, {
                onLeave: function (ret) {
                    emit.call(this, 'crypto', 'Security', fnName, {}, ret.toInt32());
                }
            });
        })(fn2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEYCHAIN
// ─────────────────────────────────────────────────────────────────────────────
function hookKeychain() {
    var fns = {
        'SecItemAdd':    'add',
        'SecItemUpdate': 'update',
        'SecItemCopyMatching': 'query',
        'SecItemDelete': 'delete',
    };
    for (var name of Object.keys(fns)) {
        var ptr = Module.findExportByName('Security', name);
        if (!ptr) continue;
        (function (fnName, op) {
            Interceptor.attach(ptr, {
                onLeave: function (ret) {
                    emit.call(this, 'keychain', 'Security', fnName, { operation: op },
                              ret.toInt32());
                }
            });
        })(name, fns[name]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILESYSTEM
// ─────────────────────────────────────────────────────────────────────────────
function hookFilesystem() {
    if (typeof ObjC === 'undefined') return;

    var NSFileManager = ObjC.classes.NSFileManager;
    var NSURL         = ObjC.classes.NSURL;

    // NSData writeToFile:atomically: / writeToURL:atomically:
    var writeToFile = ObjC.classes.NSData['- writeToFile:atomically:'];
    if (writeToFile) {
        Interceptor.attach(writeToFile.implementation, {
            onEnter: function (args) {
                this._path = new ObjC.Object(args[2]).toString();
                this._len  = new ObjC.Object(args[0]).length();
            },
            onLeave: function (ret) {
                emit.call(this, 'filesystem', 'NSData', 'writeToFile:atomically:', {
                    path: this._path, bytes: this._len
                }, ret.toInt32());
            }
        });
    }

    // NSFileManager createFileAtPath:contents:attributes:
    var createFile = NSFileManager['- createFileAtPath:contents:attributes:'];
    if (createFile) {
        Interceptor.attach(createFile.implementation, {
            onEnter: function (args) {
                this._path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (ret) {
                emit.call(this, 'filesystem', 'NSFileManager',
                          'createFileAtPath:contents:attributes:',
                          { path: this._path }, ret.toInt32());
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK — NSURLSession
// ─────────────────────────────────────────────────────────────────────────────
function hookNetwork() {
    if (typeof ObjC === 'undefined') return;

    var NSURLRequest = ObjC.classes.NSURLRequest;
    var NSURLSession = ObjC.classes.NSURLSession;

    // Hook dataTaskWithRequest:completionHandler:
    var dtImpl = NSURLSession['- dataTaskWithRequest:completionHandler:'];
    if (dtImpl) {
        Interceptor.attach(dtImpl.implementation, {
            onEnter: function (args) {
                try {
                    var req    = new ObjC.Object(args[2]);
                    var url    = req.URL().absoluteString().toString();
                    var method = req.HTTPMethod().toString();
                    var bodyLen = req.HTTPBody() ? req.HTTPBody().length() : 0;
                    emit.call(this, 'network', 'NSURLSession',
                              'dataTaskWithRequest:completionHandler:',
                              { url: url, method: method, body_bytes: bodyLen }, null);
                } catch (_) {}
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BIOMETRICS — LocalAuthentication
// ─────────────────────────────────────────────────────────────────────────────
function hookBiometrics() {
    if (typeof ObjC === 'undefined') return;

    var LAContext = ObjC.classes.LAContext;
    if (!LAContext) return;

    // evaluatePolicy:localizedReason:reply:
    var evalPolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
    if (evalPolicy) {
        Interceptor.attach(evalPolicy.implementation, {
            onEnter: function (args) {
                // LAPolicy: 1=deviceOwnerAuthenticationWithBiometrics, 2=deviceOwnerAuthentication
                this._policy = args[2].toInt32();
                this._reason = new ObjC.Object(args[3]).toString();
            },
            onLeave: function () {
                emit.call(this, 'biometrics', 'LAContext',
                          'evaluatePolicy:localizedReason:reply:', {
                              policy: this._policy,
                              reason: this._reason
                          }, null);
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialise
// ─────────────────────────────────────────────────────────────────────────────
hookCrypto();
hookKeychain();
hookFilesystem();
hookNetwork();
hookBiometrics();

rpc.exports = {
    setCategories: function (cats) {
        activeCategories = {};
        cats.forEach(function (c) { activeCategories[c] = true; });
        return Object.keys(activeCategories);
    },
    getEventCount: function () { return eventCounter; }
};
