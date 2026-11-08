"""
crypto_utils.py
----------------
Minimal, portable HMAC-SHA256 implementation that works unmodified on
both MicroPython (Pico 2 W) and standard CPython (gateway), since
MicroPython's hashlib module doesn't reliably expose Python's built-in
`hmac` module across all ports.

Copy this same file onto the gateway and onto each Pico 2 W so both
sides compute identical results.
"""

import hashlib

BLOCK_SIZE = 64  # SHA-256 block size in bytes


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256(key, message), returning 32 raw bytes."""
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    if len(key) < BLOCK_SIZE:
        key = key + b"\x00" * (BLOCK_SIZE - len(key))

    o_key_pad = _xor_bytes(key, b"\x5c" * BLOCK_SIZE)
    i_key_pad = _xor_bytes(key, b"\x36" * BLOCK_SIZE)

    inner = hashlib.sha256(i_key_pad + message).digest()
    return hashlib.sha256(o_key_pad + inner).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking timing information."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
