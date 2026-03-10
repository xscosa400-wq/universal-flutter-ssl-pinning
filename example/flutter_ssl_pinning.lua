local TARGET_MODULE = "libflutter.so"

local HOOK_CANDIDATES = {
  { name = "FUN_00bc7a5c", rva = 0xac7a5c, params = 3 }
}

local base = Module.find(TARGET_MODULE)
if not base then
    print("[-] Module not found: " .. TARGET_MODULE)
    return
end

print("[*] SSL pinning bypass starting (" .. #HOOK_CANDIDATES .. " candidate(s))")
print(string.format("[+] %s found at: 0x%x", TARGET_MODULE, base))

-- ssl_crypto_x509_session_verify_cert_chain returns bool: true (1) = success.
-- Patch the function entry to: MOV X0, #1 ; RET
-- This avoids hook trampoline issues entirely.
-- MOV X0, #1 = \x20\x00\x80\xd2  (ARM64 little-endian)
-- RET         = \xc0\x03\x5f\xd6
for _, candidate in ipairs(HOOK_CANDIDATES) do
    local addr = base + candidate.rva
    Memory.patch(addr, "\x20\x00\x80\xd2\xc0\x03\x5f\xd6")
    print(string.format("[+] Patched %s @ 0x%x", candidate.name, addr))
end

print("[+] Done.")
