"""
create_test_files.py — Generate harmless antivirus test samples.

Creates test files that trigger each detection engine:
  1. EICAR test file  → triggers ClamAV (industry standard test signature)
  2. YARA trigger file → triggers YARA rules (suspicious PE patterns)
  3. Benign PE file    → should be flagged SAFE by ML

IMPORTANT: None of these files are actual malware.
The EICAR string is the official antivirus test standard by EICAR/CARO.
"""

import os
import struct
import sys

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def create_eicar_test():
    """
    Create the EICAR anti-malware test file.

    This is the universal antivirus test standard — a completely harmless
    68-byte file that every AV engine (including ClamAV) is designed to
    detect. It's NOT malware; it just prints a string and exits.
    See: https://www.eicar.org/download-anti-malware-testfile/
    """
    # The official EICAR test string (68 bytes)
    eicar = (
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR"
        r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    path = os.path.join(OUTPUT_DIR, "eicar_test.com")
    with open(path, "w") as f:
        f.write(eicar)
    print(f"[✓] EICAR test file created: {path}")
    print(f"    → Will trigger: ClamAV (signature match)")
    return path


def create_yara_trigger_exe():
    """
    Create a dummy PE file with strings that match our YARA rules.

    This is a non-functional PE stub with embedded strings that trigger
    rules like Suspicious_Imports_Keylogging and Suspicious_Section_Names.
    The file cannot execute — it has no real code.
    """
    # Minimal PE header (DOS + PE signature)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"                          # DOS magic
    struct.pack_into("<I", dos_header, 60, 64)        # e_lfanew → PE header at offset 64

    pe_sig = b"PE\x00\x00"

    # COFF header
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x14c)            # Machine: i386
    struct.pack_into("<H", coff, 2, 3)                # NumberOfSections: 3
    struct.pack_into("<H", coff, 16, 224)              # SizeOfOptionalHeader

    # Optional header (simplified, just enough to be a "PE")
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10b)              # Magic: PE32

    # Section headers (3 sections, 40 bytes each)
    sections = bytearray(120)
    # Section 1: .text (normal)
    sections[0:8] = b".text\x00\x00\x00"
    # Section 2: .aspack (suspicious — triggers YARA rule)
    sections[40:48] = b".aspack\x00"
    # Section 3: .upx0 (suspicious — triggers UPX packer rule)
    sections[80:88] = b"UPX0\x00\x00\x00\x00"

    # Suspicious API strings that trigger YARA rules
    payload = b"\x00".join([
        b"GetAsyncKeyState",      # Keylogger indicator
        b"SetWindowsHookEx",      # Keylogger indicator
        b"VirtualAllocEx",        # Injection indicator
        b"WriteProcessMemory",    # Injection indicator
        b"CreateRemoteThread",    # Injection indicator
        b"IsDebuggerPresent",     # Anti-debug indicator
        b"URLDownloadToFile",     # Dropper indicator
        b"",
    ])

    # Assemble the PE
    pe_data = dos_header + pe_sig + coff + opt + sections
    # Pad to 512 bytes then add the suspicious strings
    pe_data = pe_data.ljust(512, b"\x00") + payload
    # Pad to 2KB total
    pe_data = pe_data.ljust(2048, b"\x00")

    path = os.path.join(OUTPUT_DIR, "yara_trigger_test.exe")
    with open(path, "wb") as f:
        f.write(pe_data)
    print(f"[✓] YARA trigger test created: {path}")
    print(f"    → Will trigger: YARA (Suspicious_Section_Names, Suspicious_UPX_Packed,")
    print(f"                          Suspicious_Imports_Keylogging, Suspicious_AntiDebug)")
    return path


def create_benign_exe():
    """
    Create a minimal valid-looking PE file that should be classified SAFE.

    Has a normal structure with standard section names and no suspicious strings.
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)

    pe_sig = b"PE\x00\x00"

    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x14c)
    struct.pack_into("<H", coff, 2, 2)                # 2 sections (normal)
    struct.pack_into("<H", coff, 16, 224)

    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10b)
    struct.pack_into("<I", opt, 16, 0x1000)            # SizeOfCode
    struct.pack_into("<I", opt, 20, 0x2000)            # SizeOfInitializedData
    struct.pack_into("<I", opt, 28, 0x400000)          # ImageBase

    sections = bytearray(80)   # 2 sections
    sections[0:8] = b".text\x00\x00\x00"
    sections[40:48] = b".rdata\x00\x00"

    # Normal strings
    payload = b"This program cannot be run in DOS mode.\r\n\x00"
    payload += b"Microsoft Visual C++ Runtime Library\x00"

    pe_data = dos_header + pe_sig + coff + opt + sections
    pe_data = pe_data.ljust(512, b"\x00") + payload
    pe_data = pe_data.ljust(4096, b"\x00")

    path = os.path.join(OUTPUT_DIR, "benign_test.exe")
    with open(path, "wb") as f:
        f.write(pe_data)
    print(f"[✓] Benign test file created: {path}")
    print(f"    → Should be classified: SAFE by all engines")
    return path


if __name__ == "__main__":
    print("=" * 55)
    print("  🧪 Antivirus Test Sample Generator")
    print("  ⚠️  All files are HARMLESS test samples")
    print("=" * 55)
    print()

    create_eicar_test()
    print()
    create_yara_trigger_exe()
    print()
    create_benign_exe()

    print()
    print("=" * 55)
    print("  ✅ 3 test files created in:")
    print(f"     {OUTPUT_DIR}")
    print()
    print("  Scan these with LivKid AV to test all 3 engines!")
    print("=" * 55)
