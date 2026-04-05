"""
feature_extractor.py — PE file feature extraction for ML-based malware detection.

Extracts a fixed-size numerical feature vector from Portable Executable (PE) files
using the pefile library.  The vector consists of PE header fields and per-section
entropy values, padded or truncated to a consistent length.
"""

from __future__ import annotations

import math
import os
from typing import Optional

import pefile

from config import FEATURE_VECTOR_SIZE, NUM_HEADER_FEATURES, NUM_ENTROPY_FEATURES


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    ent = 0.0
    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)
    return round(ent, 6)


def extract_features(file_path: str) -> Optional[list[float]]:
    """
    Extract a fixed-size feature vector from a PE file.

    Returns a list of FEATURE_VECTOR_SIZE floats, or None if the file
    is not a valid PE or cannot be parsed.

    Feature layout (16 values):
        [0]  Machine
        [1]  NumberOfSections
        [2]  TimeDateStamp
        [3]  SizeOfOptionalHeader
        [4]  Characteristics
        [5]  SizeOfCode
        [6]  SizeOfInitializedData
        [7]  SizeOfUninitializedData
        [8]  AddressOfEntryPoint
        [9]  ImageBase
        [10-15]  Per-section entropy (6 slots, padded with 0.0)
    """
    if not os.path.isfile(file_path):
        return None

    try:
        pe = pefile.PE(file_path, fast_load=False)
    except pefile.PEFormatError:
        return None
    except Exception:
        return None

    try:
        # ── Header features ─────────────────────────────────────────
        header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER

        features: list[float] = [
            float(header.Machine),
            float(header.NumberOfSections),
            float(header.TimeDateStamp),
            float(header.SizeOfOptionalHeader),
            float(header.Characteristics),
            float(optional.SizeOfCode),
            float(optional.SizeOfInitializedData),
            float(optional.SizeOfUninitializedData),
            float(optional.AddressOfEntryPoint),
            float(optional.ImageBase),
        ]

        # ── Section entropy ─────────────────────────────────────────
        section_entropies: list[float] = []
        for section in pe.sections:
            try:
                raw = section.get_data()
                section_entropies.append(_entropy(raw))
            except Exception:
                section_entropies.append(0.0)

        # Pad or truncate to NUM_ENTROPY_FEATURES
        if len(section_entropies) < NUM_ENTROPY_FEATURES:
            section_entropies.extend(
                [0.0] * (NUM_ENTROPY_FEATURES - len(section_entropies))
            )
        else:
            section_entropies = section_entropies[:NUM_ENTROPY_FEATURES]

        features.extend(section_entropies)

        pe.close()

        # Sanity check
        assert len(features) == FEATURE_VECTOR_SIZE, (
            f"Feature vector length mismatch: {len(features)} != {FEATURE_VECTOR_SIZE}"
        )
        return features

    except Exception as e:
        print(f"[feature_extractor] Error extracting features from {file_path}: {e}")
        try:
            pe.close()
        except Exception:
            pass
        return None
