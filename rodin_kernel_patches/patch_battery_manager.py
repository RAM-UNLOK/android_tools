#!/usr/bin/env python3
import os

# Target file
TARGET = "mtk_battery_manager.ko"

# Original bytes at 0x10a4:
# 10a4: b9425296  ldr w22, [x20, #0x250]
# 10a8: 71018edf  cmp w22, #0x63
# 10ac: 5400018d  b.le 0x10dc
ORIGINAL = bytes.fromhex("965242b9df8e01718d010054")

# Patched bytes:
# 10a4: 12800780  mov w0, #-0x3d  (Set return value to -ENODATA)
# 10a8: 140000cd  b 0x13dc        (Jump straight to the function's return)
# 10ac: d503201f  nop             (Padding to keep binary size identical)
PATCHED = bytes.fromhex("80078012cd0000141f2003d5")

def apply_patch():
    if not os.path.exists(TARGET):
        print(f"[-] {TARGET} not found in the current directory.")
        return

    with open(TARGET, "rb") as f:
        data = bytearray(f.read())

    count = data.count(ORIGINAL)
    if count == 0:
        print("[-] Original byte sequence not found. The file may already be patched.")
        return
    elif count > 1:
        print("[!] Warning: Multiple occurrences found. Patching all...")

    patched_data = data.replace(ORIGINAL, PATCHED)

    with open(TARGET, "wb") as f:
        f.write(patched_data)

    print(f"[+] Successfully patched charging estimates in {TARGET}.")
    print("[+] Android will now calculate the charging time natively.")

if __name__ == "__main__":
    apply_patch()