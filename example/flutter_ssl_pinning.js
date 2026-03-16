"use strict";

var TARGET_MODULE = "libflutter.so";

var HOOK_CANDIDATES = [
  { name: "FUN_00bc7a5c", rva: "0xac7a5c", params: 3, sig: "void FUN_00bc7a5c(undefined8 param_1,undefined8 param_2,undefined1 *param_3);" }
];

function hookCandidate(mod, candidate) {
    var addr = mod.base.add(candidate.rva);
    if (addr.compare(mod.base.add(mod.size)) >= 0) {
        console.log("[-] " + candidate.name + ": RVA " + candidate.rva + " outside module bounds");
        return;
    }
    try {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                retval.replace(ptr(1));
            }
        });
        console.log("[+] Hooked " + candidate.name + " @ " + addr);
    } catch (e) {
        console.log("[-] Failed to hook " + candidate.name + ": " + e.message);
    }
}

function bypassSslPinning(mod) {
    console.log("[*] SSL pinning bypass starting (" + HOOK_CANDIDATES.length + " candidate(s))");
    console.log("[+] " + TARGET_MODULE + " found at: " + mod.base + " size: " + mod.size);
    HOOK_CANDIDATES.forEach(function (c) { hookCandidate(mod, c); });
    console.log("[+] Done.");
}

// Check if already loaded (in case we attach late)
var mod = Process.findModuleByName(TARGET_MODULE);
if (mod) {
    console.log("[*] " + TARGET_MODULE + " already loaded, hooking now...");
    bypassSslPinning(mod);
} else {
    console.log("[*] " + TARGET_MODULE + " not yet loaded, waiting for it...");

    var listener = Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            var path = args[0].readCString();
            if (path && path.indexOf("libflutter.so") !== -1) {
                console.log("[*] Detected load: " + path);
                this.isTarget = true;
            }
        },
        onLeave: function (retval) {
            if (this.isTarget) {
                var loadedMod = Process.findModuleByName(TARGET_MODULE);
                if (loadedMod) {
                    bypassSslPinning(loadedMod);
                    listener.detach();
                    console.log("[*] Listener detached.");
                } else {
                    console.log("[-] dlopen returned but module not found yet");
                }
            }
        }
    });

    console.log("[*] Listening on dlopen/android_dlopen_ext...");
}
