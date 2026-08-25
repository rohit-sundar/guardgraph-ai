// GuardGraph AI — scoped dynamic-verification hook script.
//
// Deliberately narrow: every hook here exists to answer a yes/no question the
// static pipeline already asked, OR (the IoC-oriented group below) a category
// any real dynamic-analysis sandbox reports standalone. Not a general
// syscall/API tracer — no hook is added here without a specific reason.
//
// Built with `frida-compile` (Frida 16+ no longer bundles the Java bridge as
// a global — see app/analysis/frida_scripts/README.md). Run `npm run build`
// in this directory to regenerate _agent.js after editing this file.
//
// Every hook is wrapped in its own try/catch: an app that never touches
// javax.crypto, for instance, must not stop the SMS/network/DCL hooks from
// installing. A hook that fails to install sends a `hook_error` event rather
// than throwing silently, so the Python side can tell "not observed" apart
// from "we couldn't even attach the hook".

import Java from "frida-java-bridge";

// Relative-ms timestamp on every event, since script load — lets the Python
// side reconstruct an actual timeline ("contacted C2 3.2s after launch")
// instead of only an unordered set, which is what the "time-gated check"
// caveat already shown in the UI needs to eventually be more than a caveat.
const _t0 = Date.now();

function safeSend(kind, value, extra) {
  try {
    send(Object.assign({ kind: kind, value: value, t: Date.now() - _t0 }, extra || {}));
  } catch (e) {
    // send() itself must never throw the hook implementation off a cliff.
  }
}

function hookNetwork(Java) {
  try {
    const InetSocketAddress = Java.use("java.net.InetSocketAddress");
    InetSocketAddress.$init.overload("java.lang.String", "int").implementation = function (host, port) {
      safeSend("network", host + ":" + port);
      return this.$init(host, port);
    };
    safeSend("hook_installed", "network");
  } catch (e) {
    safeSend("hook_error", "network: " + e);
  }
}

function hookSms(Java) {
  try {
    const SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
      "java.lang.String", "java.lang.String", "java.lang.String",
      "android.app.PendingIntent", "android.app.PendingIntent"
    ).implementation = function (destAddr, scAddr, text, sentIntent, deliveryIntent) {
      safeSend("sms_send", destAddr);
      return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
    };
    safeSend("hook_installed", "sms");
  } catch (e) {
    safeSend("hook_error", "sms: " + e);
  }
}

// Incoming-SMS interception — the actual OTP-theft path this whole project
// is aimed at. hookSms above only ever caught the app SENDING a message;
// reading a victim's incoming OTP is what banking trojans actually do, and
// nothing here observed it before this hook existed.
function hookSmsRead(Java) {
  try {
    const SmsMessage = Java.use("android.telephony.SmsMessage");
    // createFromPdu(byte[], String) is the modern overload every SMS
    // BroadcastReceiver.onReceive(SMS_RECEIVED) path funnels through to turn
    // the raw radio PDU into a readable message — hooking the factory method
    // catches interception regardless of which receiver class the app uses.
    SmsMessage.createFromPdu.overload("[B", "java.lang.String").implementation = function (pdu, format) {
      const msg = this.createFromPdu(pdu, format);
      try {
        if (msg !== null) {
          const sender = msg.getOriginatingAddress();
          safeSend("sms_intercepted", sender ? sender : "<unknown sender>");
        }
      } catch (e) {
        // Message parsing itself failing must not un-do the real call above.
      }
      return msg;
    };
    safeSend("hook_installed", "sms_read");
  } catch (e) {
    safeSend("hook_error", "sms_read: " + e);
  }
}

function hookDcl(Java) {
  try {
    const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    BaseDexClassLoader.findClass.implementation = function (name) {
      safeSend("dcl_class_load", name);
      return this.findClass(name);
    };
    safeSend("hook_installed", "dcl");
  } catch (e) {
    safeSend("hook_error", "dcl: " + e);
  }
}

// native_bridge.py statically resolves System.loadLibrary("x") call sites to
// their .so file and JNI symbols but can never confirm the call actually
// executed. This hooks the exact same API dynamically so the Python side can
// give native code the same "predicted vs confirmed" treatment DCL already
// gets — see native_library_confirmed in dynamic_verification.py.
function hookNativeLibraryLoad(Java) {
  try {
    const SystemClass = Java.use("java.lang.System");
    SystemClass.loadLibrary.overload("java.lang.String").implementation = function (libname) {
      safeSend("native_library_loaded", libname);
      return this.loadLibrary(libname);
    };
    SystemClass.load.overload("java.lang.String").implementation = function (pathname) {
      safeSend("native_library_loaded", pathname);
      return this.load(pathname);
    };
    safeSend("hook_installed", "native_library_load");
  } catch (e) {
    safeSend("hook_error", "native_library_load: " + e);
  }
}

function hookAccessibility(Java) {
  try {
    const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.onServiceConnected.implementation = function () {
      safeSend("accessibility_bound", this.getClass().getName());
      return this.onServiceConnected();
    };
    safeSend("hook_installed", "accessibility");
  } catch (e) {
    safeSend("hook_error", "accessibility: " + e);
  }
}

// Cheap, practical substitute for real parameterized string-decryption
// (resolving a decrypt routine whose key comes from runtime state — device
// ID, a value fetched from C2 — statically would need a real Dalvik
// interpreter/symbolic-execution engine, out of scope here). Instead of
// solving it statically, capture the actual decrypted/encrypted bytes at the
// one place they exist in the clear: Cipher.doFinal's return value, live on
// device. Only fires for samples where the code path actually executes
// during the capture window — a complement to the static gap, not a full
// close of it.
//
// CRYPTO_OUTPUT_PREVIEW_CAP bytes: this project has no prior convention for
// capturing arbitrary runtime string content (see hookSmsRead/hookUrls —
// none of them cap length), and a decrypted payload could be arbitrarily
// large unlike a bare algorithm name, so an explicit, documented cap is
// needed here specifically. 128 is enough to recognize a C2 URL, a JSON
// config blob's shape, or a key/token string without shipping an entire
// payload through the event channel.
const CRYPTO_OUTPUT_PREVIEW_CAP = 128;

// Cipher.init's opmode and doFinal's output are reported as independent
// events, not correlated per-Cipher-instance: frida-java-bridge does not
// guarantee a JS property attached to `this` in one hooked call survives to
// a later call on what is nominally "the same" Java object, so building
// instance-keyed correlation here would be fragile state for a hackathon
// feature to depend on. The Python side can still line them up loosely by
// timestamp proximity if useful; this hook does not attempt to.
function previewCryptoBytes(Java, byteArray) {
  const len = byteArray.length;
  const capLen = Math.min(len, CRYPTO_OUTPUT_PREVIEW_CAP);
  const StringClass = Java.use("java.lang.String");
  const decoded = StringClass.$new(byteArray, 0, capLen, "UTF-8");
  const text = decoded.toString();
  // Java's String(byte[], charset) never throws on invalid UTF-8 — it
  // substitutes U+FFFD instead. A high replacement-char ratio means this is
  // binary data, not text, so a hex preview is more useful than a wall of
  // replacement characters.
  let replacementCount = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 0xfffd) replacementCount++;
  }
  if (text.length > 0 && replacementCount / text.length > 0.2) {
    let hex = "";
    for (let i = 0; i < capLen; i++) {
      hex += (byteArray[i] & 0xff).toString(16).padStart(2, "0");
    }
    return "hex:" + hex + (len > capLen ? "..." : "");
  }
  return text + (len > capLen ? "..." : "");
}

function hookCrypto(Java) {
  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
      const output = this.doFinal(input);
      safeSend("crypto_invoked", this.getAlgorithm());
      try {
        safeSend("crypto_output", previewCryptoBytes(Java, output), {
          algorithm: this.getAlgorithm(),
        });
      } catch (e) {
        // Preview extraction failing must not affect the real doFinal result.
      }
      return output;
    };
    safeSend("hook_installed", "crypto");
  } catch (e) {
    safeSend("hook_error", "crypto: " + e);
  }

  // Separate try/catch: an app whose Cipher usage doesn't match this exact
  // init overload must not lose the doFinal hook above.
  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
      // javax.crypto.Cipher.ENCRYPT_MODE=1, DECRYPT_MODE=2, WRAP_MODE=3, UNWRAP_MODE=4.
      const modeName = opmode === 1 ? "encrypt" : opmode === 2 ? "decrypt" : "mode_" + opmode;
      safeSend("crypto_mode", modeName, { algorithm: this.getAlgorithm() });
      return this.init(opmode, key);
    };
    safeSend("hook_installed", "crypto_mode");
  } catch (e) {
    safeSend("hook_error", "crypto_mode: " + e);
  }
}

// Overlay-attack detection — the signature banking-trojan move (a fake
// login screen drawn on top of the real banking app) is a WindowManager
// addView call with a window type in the small set a THIRD-PARTY app can
// actually obtain and that persists over other apps.
//
// A plain `type >= 2000` range check was tried first and confirmed live to
// be too broad: it fired on TYPE_TOAST=2005 from a real sample, which is
// completely routine UI (any app can show a toast, no special permission,
// doesn't overlay another app's content) — exactly the false-positive
// pattern this project has hit before with unfiltered process-wide hooks
// (see hookUrls/hookFileWrites' noise filters). Narrowed to an explicit
// allowlist of types that (a) require SYSTEM_ALERT_WINDOW or an active
// accessibility-service binding to obtain — something a normal app cannot
// just ask for — and (b) actually draw over other apps rather than being
// system-internal (status bar, keyguard, drag-and-drop, volume HUD, etc.,
// none of which a third-party app's own addView call could produce anyway).
const OVERLAY_ATTACK_WINDOW_TYPES = new Set([
  2002, // TYPE_PHONE — legacy pre-O overlay
  2003, // TYPE_SYSTEM_ALERT — legacy pre-O overlay, the classic phishing-overlay type
  2006, // TYPE_SYSTEM_OVERLAY — legacy, draws over other apps without taking focus
  2007, // TYPE_PRIORITY_PHONE — legacy
  2032, // TYPE_ACCESSIBILITY_OVERLAY — the modern path banking trojans actually use, drawn by an app's own bound AccessibilityService
  2038, // TYPE_APPLICATION_OVERLAY — the modern (API 26+) SYSTEM_ALERT_WINDOW type
]);

function hookOverlay(Java) {
  try {
    const WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
    WindowManagerImpl.addView.overload(
      "android.view.View", "android.view.ViewGroup$LayoutParams"
    ).implementation = function (view, params) {
      try {
        const wmParams = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        const type = wmParams.type.value;
        if (OVERLAY_ATTACK_WINDOW_TYPES.has(type)) {
          safeSend("overlay_window", "type=" + type);
        }
      } catch (e) {
        // Cast/field-read failing must not stop the real addView from happening.
      }
      return this.addView(view, params);
    };
    safeSend("hook_installed", "overlay");
  } catch (e) {
    safeSend("hook_error", "overlay: " + e);
  }
}

// Sensitive ContentResolver reads — contacts, call log, and (as a second
// path alongside hookSmsRead) the SMS content provider some stealers query
// directly for message HISTORY rather than only intercepting new arrivals.
// One hook, categorized by URI substring, rather than three separate
// ContentResolver.query overrides repeating the same logic.
function hookContentResolverQuery(Java) {
  try {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const overload = ContentResolver.query.overload(
      "android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
    );
    overload.implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
      try {
        const uriStr = uri.toString().toLowerCase();
        let category = null;
        if (uriStr.indexOf("sms") !== -1) category = "sms";
        else if (uriStr.indexOf("call_log") !== -1 || uriStr.indexOf("calllog") !== -1) category = "call_log";
        else if (uriStr.indexOf("contacts") !== -1) category = "contacts";
        if (category !== null) {
          safeSend("sensitive_content_query", category + ": " + uriStr);
        }
      } catch (e) {
        // Fall through to the real call below regardless.
      }
      return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
    safeSend("hook_installed", "content_query");
  } catch (e) {
    safeSend("hook_error", "content_query: " + e);
  }
}

function hookClipboard(Java) {
  try {
    const ClipboardManager = Java.use("android.content.ClipboardManager");
    ClipboardManager.getPrimaryClip.implementation = function () {
      safeSend("clipboard_read", true);
      return this.getPrimaryClip();
    };
    safeSend("hook_installed", "clipboard");
  } catch (e) {
    safeSend("hook_error", "clipboard: " + e);
  }
}

// IoC-oriented hooks — not tied to a specific static prediction the way the
// hooks above are, but they're categories any real dynamic-analysis report
// shows: full request URLs (not just host:port), dropped files, and
// executed commands/shell-outs. Reported as-observed, standalone IoCs.
//
// Both hooks below are process-wide (Frida has no cheap way to scope a Java
// hook to "only code the app developer wrote" — ART/Android's own internals
// run through the exact same java.net.URL / FileOutputStream constructors on
// the app's behalf). Confirmed live: an unfiltered run reported
// "file:/system/framework/framework.jar" as a URL "accessed" by a password
// stealer sample, and EVERY benign app in a 40-sample sweep reported writing
// "primary.prof" / "profileinstaller_profileWrittenFor_lastUpdateTime.dat" —
// both are Android's own ART profiling housekeeping, not anything the app
// did. Filtered out before being reported as an IoC, since noise here
// directly undermines the signal the whole point of this section carries.

function isNoiseUrl(spec) {
  return /^file:\/(system|apex|vendor|product|system_ext)\//.test(spec);
}

function isNoiseFilePath(path) {
  return (
    path.indexOf("/data/misc/profiles/") === 0 ||
    path.indexOf("profileinstaller_profileWrittenFor") !== -1 ||
    path.endsWith(".prof") ||
    path.endsWith(".profm")
  );
}

function hookUrls(Java) {
  try {
    const URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function (spec) {
      if (!isNoiseUrl(spec)) {
        safeSend("url_accessed", spec);
      }
      return this.$init(spec);
    };
    safeSend("hook_installed", "url");
  } catch (e) {
    safeSend("hook_error", "url: " + e);
  }
}

function hookFileWrites(Java) {
  try {
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
      // A malicious/dropper payload's own files land under this app's
      // sandbox, not somewhere pre-declared statically — the raw path IS
      // the IoC here, not a confirmation of anything already known.
      const path = file.getAbsolutePath();
      if (!isNoiseFilePath(path)) {
        safeSend("file_written", path);
      }
      return this.$init(file, append);
    };
    safeSend("hook_installed", "file_write");
  } catch (e) {
    safeSend("hook_error", "file_write: " + e);
  }
}

function hookProcessExec(Java) {
  try {
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdarray) {
      const cmd = [];
      for (let i = 0; i < cmdarray.length; i++) cmd.push(cmdarray[i]);
      safeSend("command_executed", cmd.join(" "));
      return this.exec(cmdarray);
    };
    safeSend("hook_installed", "process_exec");
  } catch (e) {
    safeSend("hook_error", "process_exec: " + e);
  }
}

Java.perform(function () {
  hookNetwork(Java);
  hookSms(Java);
  hookSmsRead(Java);
  hookDcl(Java);
  hookNativeLibraryLoad(Java);
  hookAccessibility(Java);
  hookCrypto(Java);
  hookOverlay(Java);
  hookContentResolverQuery(Java);
  hookClipboard(Java);
  hookUrls(Java);
  hookFileWrites(Java);
  hookProcessExec(Java);
  safeSend("ready", true);
});
