# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from .ed25519 import B, Scalar

__all__ = ["pubkey_gen"]


def pubkey_gen(seckey: bytes) -> bytes:
    """Return the public key corresponding to a raw-scalar secret key.

    The secret key is a uniform scalar in 1..L-1, little-endian, NOT an RFC 8032
    seed: there is no clamping, no SHA-512 expansion and no prefix. Host keys in
    this protocol are raw scalars precisely so that only one signing
    construction has to exist.

    This replaces secp256k1lab's pubkey_gen_plain. The "plain" qualifier
    contrasted with x-only key generation, which does not exist here.
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    p = d * B
    assert not p.is_identity
    return p.to_bytes()
