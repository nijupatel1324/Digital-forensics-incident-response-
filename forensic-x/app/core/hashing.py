"""
FORENSIC-X — Forensic Hashing & Cryptographic Verification
app/core/hashing.py
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict, Tuple, Union


CHUNK_SIZE = 64 * 1024  # 64 KB chunk size for streaming large forensic images


def calculate_stream_hashes(
    stream: Union[BinaryIO, Path, str]
) -> Dict[str, str]:
    """
    Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes simultaneously in a streaming fashion.
    Supports file paths and binary file streams.
    """
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    sha256_hasher = hashlib.sha256()
    sha512_hasher = hashlib.sha512()

    if isinstance(stream, (str, Path)):
        with open(stream, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                md5_hasher.update(chunk)
                sha1_hasher.update(chunk)
                sha256_hasher.update(chunk)
                sha512_hasher.update(chunk)
    else:
        while chunk := stream.read(CHUNK_SIZE):
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)
            sha256_hasher.update(chunk)
            sha512_hasher.update(chunk)

    return {
        "md5": md5_hasher.hexdigest(),
        "sha1": sha1_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
        "sha512": sha512_hasher.hexdigest(),
    }


def calculate_bytes_hashes(data: bytes) -> Dict[str, str]:
    """Calculate MD5, SHA-1, SHA-256, and SHA-512 for in-memory bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def verify_file_integrity(
    file_path: Union[str, Path],
    expected_sha256: str = None,
    expected_md5: str = None,
    expected_sha1: str = None,
) -> Tuple[bool, Dict[str, Dict[str, str]]]:
    """
    Verify the cryptographic integrity of a stored evidence file.
    Returns (is_intact, details_dict).
    """
    current_hashes = calculate_stream_hashes(file_path)
    is_intact = True
    details = {}

    if expected_sha256:
        match = current_hashes["sha256"].lower() == expected_sha256.lower()
        details["sha256"] = {
            "expected": expected_sha256.lower(),
            "actual": current_hashes["sha256"],
            "matched": match,
        }
        if not match:
            is_intact = False

    if expected_md5:
        match = current_hashes["md5"].lower() == expected_md5.lower()
        details["md5"] = {
            "expected": expected_md5.lower(),
            "actual": current_hashes["md5"],
            "matched": match,
        }
        if not match:
            is_intact = False

    if expected_sha1:
        match = current_hashes["sha1"].lower() == expected_sha1.lower()
        details["sha1"] = {
            "expected": expected_sha1.lower(),
            "actual": current_hashes["sha1"],
            "matched": match,
        }
        if not match:
            is_intact = False

    return is_intact, details
