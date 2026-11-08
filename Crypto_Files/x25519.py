"""
x25519.py
----------
Pure-Python implementation of X25519 (RFC 7748), the elliptic-curve
Diffie-Hellman function on Curve25519. Portable to both MicroPython
(Pico 2 W) and CPython (gateway) since it relies only on built-in
arbitrary-precision integers -- no external crypto library needed.

NOTE: this is a teaching/research implementation, not constant-time.
It is adequate for this experiment (measuring protocol overhead on
constrained hardware) but should not be used as-is in a production
security product, where timing side-channels matter.

Copy this same file onto the gateway and onto each Pico 2 W.
"""

import os

P = 2 ** 255 - 19
A24 = 121665  # (486662 - 2) // 4


def _decode_little_endian(b):
    return int.from_bytes(b, "little")


def _encode_little_endian(n):
    return n.to_bytes(32, "little")


def _clamp_scalar(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return _decode_little_endian(bytes(k))


def _cswap(swap, a, b):
    """Constant-structure conditional swap (not constant-time in pure Python,
    but keeps the algorithm structure correct per the RFC)."""
    if swap:
        return b, a
    return a, b


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """
    Compute the X25519 function: given a 32-byte private scalar and a
    32-byte public u-coordinate, return the resulting 32-byte shared value.

    Use with BASE_POINT as public_key to generate a public key from a
    private key. Use with a peer's public key to compute a shared secret.
    """
    k = _clamp_scalar(private_key)
    u = _decode_little_endian(public_key) % P

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = pow(DA + CB, 2, P)
        z3 = (x1 * pow(DA - CB, 2, P)) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E)) % P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    result = (x2 * pow(z2, P - 2, P)) % P
    return _encode_little_endian(result)


BASE_POINT = _encode_little_endian(9)


def generate_private_key() -> bytes:
    """Generate a random 32-byte X25519 private key."""
    return os.urandom(32)


def generate_public_key(private_key: bytes) -> bytes:
    """Derive the public key corresponding to a private key."""
    return x25519(private_key, BASE_POINT)


def compute_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Compute the shared secret given your private key and the peer's public key."""
    return x25519(private_key, peer_public_key)
