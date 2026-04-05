"""
create_sandbox_test.py — Generates a specialized file to test the Livware Sandbox Analyzer.

This script creates a dummy PE (executable) file named `advanced_sandbox_test.exe` 
designed strictly to trigger multiple behavioral warnings in the Sandbox UI, including:
  1. High entropy sections (simulated packing/encryption)
  2. Suspicious embedded strings (Registry Autorun, URLs, Ransomware keywords)
  3. Structural anomalies (Abnormal section count)

THIS IS NOT MALWARE. It cannot be executed and will immediately crash if run.
It's just structured data for the analyzer to read.
"""

import os
import struct
import random

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def create_sandbox_trigger():
    # DOS Header
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)

    pe_sig = b"PE\x00\x00"

    # COFF Header (Setting NumberOfSections to 9 to trigger "Structure Anomaly")
    # > 8 sections is considered suspicious by the analyzer.
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x14c)
    struct.pack_into("<H", coff, 2, 9)                # 9 sections
    struct.pack_into("<H", coff, 16, 224)

    # Optional Header
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10b)
    struct.pack_into("<I", opt, 16, 0)
    struct.pack_into("<I", opt, 28, 0x400000)

    # Section Headers (9 sections, 40 bytes each = 360 bytes)
    sections = bytearray(360)
    for i in range(9):
        name = f".sec{i}".encode("ascii").ljust(8, b"\x00")
        offset = i * 40
        sections[offset:offset+8] = name

    # ── High Entropy Payload ──────────────────────────────────────
    # We generate random bytes to simulate an encrypted or packed payload.
    # This will trigger the "Packed/Encrypted: Section has very high entropy" rule.
    high_entropy_data = bytearray(random.getrandbits(8) for _ in range(8000))

    # ── Suspicious Strings Payload ────────────────────────────────
    # These exact strings match the regex patterns in sandbox.py
    suspicious_strings = [
        b"http://192.168.1.100/malware.exe\x00",                # Hardcoded IP URL
        b"cmd.exe /c start payload.bat\x00",                    # Shell Reference
        b"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\x00", # Autorun Registry Path
        b"Your files are .encrypted. Pay bitcoin to wallet.\x00", # Ransomware & Crypto keywords
        b"vssadmin.exe Delete Shadows /All /Quiet\x00",         # Shadow Copy Deletion
        b"HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\x00"  # Registry Hive Ref
    ]
    strings_payload = b"\x00".join(suspicious_strings)

    # Assemble the file
    pe_data = dos_header + pe_sig + coff + opt + sections
    pe_data = pe_data.ljust(1024, b"\x00") 
    pe_data += strings_payload
    pe_data = pe_data.ljust(2048, b"\x00")
    pe_data += high_entropy_data
    
    # Save the file
    path = os.path.join(OUTPUT_DIR, "advanced_sandbox_test.exe")
    with open(path, "wb") as f:
        f.write(pe_data)
        
    print("==================================================")
    print("✅ Advanced Sandbox Test File Created!")
    print(f"Path: {path}")
    print("==================================================")
    print("What this will trigger in the Sandbox:")
    print(" 1. CRITICAL: Autorun Registry Path string")
    print(" 2. CRITICAL: Ransomware Extension & Keywords")
    print(" 3. CRITICAL: Shadow Copy Deletion string")
    print(" 4. HIGH: Hardcoded IP URL")
    print(" 5. HIGH: Shell Reference (cmd.exe)")
    print(" 6. HIGH: Packed/Encrypted Data (High Entropy Section)")
    print(" 7. MEDIUM: Structure Anomaly (9 sections, Missing Imports)")
    print("==================================================")

if __name__ == "__main__":
    create_sandbox_trigger()
