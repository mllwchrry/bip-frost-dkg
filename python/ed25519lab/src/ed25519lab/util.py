# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Hashing and byte helpers.

All integer/byte conversion here is LITTLE-ENDIAN, matching the rest of the
library. Note that this differs from secp256k1lab, where bytes_from_int and
int_from_bytes are big-endian; the names are kept because the role is unchanged.
"""

import hashlib

__all__ = [
    "bytes_from_int",
    "hash_sha512",
    "int_from_bytes",
    "tagged_hash",
    "xor_bytes",
]


def tagged_hash(tag: str, *parts: bytes) -> bytes:
    """Domain-separated hash. 64 bytes.

        tagged_hash(tag, *parts) == SHA-512(SHA-512(tag)[:32] || parts...)

    THE TAG IS DIGESTED TO A FIXED WIDTH, ON PURPOSE.

    The obvious construction, SHA-512(tag || data), is a trap: with a plain
    string prefix, one tag can be a prefix of another, and then the two domains
    collide outright. "proto/nonce" with data "coef..." and "proto/noncecoef"
    with data "..." hash the same bytes. Nothing in the code catches it; the
    only defence is remembering to check prefix-freeness by hand every time a
    tag is added, forever.

    Hashing the tag first makes that impossible by construction. Every tag
    becomes exactly 32 bytes, so the data always begins at offset 32 and no tag
    can be a prefix of another. The cost is one extra hash per call.

    This is BIP340's approach with the widths adjusted. Three differences, both
    deliberate:

    * BIP340 hashes the tag TWICE. That is a SHA-256 midstate optimisation --
      2 x 32 bytes exactly fills its 64-byte block. SHA-512's block is 128
      bytes, so the trick buys nothing here and the second copy is dropped.
    * The tag is digested with SHA-512, not SHA-256. Any fixed width closes the
      prefix hazard equally well, so the deciding argument is that the library
      then uses exactly one hash function everywhere. A second primitive in a
      reference implementation is one more thing to specify, port and get
      wrong, for no gain.
    * The 64-byte digest is truncated to 32. This saves an entire SHA-512 
      compression for short inputs without introducing any vulnerabilities 
      (a 32-byte prefix still needs ~2**128 work to collide). int/nonce and 
      int/challenge hash tag || 32 || 32 || 4: 100 bytes with a 32-byte tag 
      (one compression), 132 with a 64-byte one (two).

    WHAT THE CALLER STILL HAS TO GUARANTEE

    Fixing the tag width removes the tag-prefix hazard. It does NOT make the
    concatenation of `parts` injective. At most one part may be
    variable-length, and it must be last -- otherwise (b"ab", b"cd") and
    (b"a", b"bcd") still produce the same hash. For anything else, length-prefix
    each variable field.

    That matters most for a signature nonce. If k = tagged_hash(tag, d, aux, m)
    collides for two different messages, the signer emits the same R twice under
    different challenges and the secret key falls out of
    d = (s1 - s2) / (e1 - e2).

    The 64-byte output is exactly what Scalar.from_bytes_wide requires, so
    `Scalar.from_bytes_wide(tagged_hash(...))` composes without a length
    adapter, and no other length can be passed by accident.
    """
    return hashlib.sha512(hashlib.sha512(tag.encode()).digest()[:32] + b"".join(parts)).digest()


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="little")


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little")


def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    assert len(b0) == 32 and len(b1) == 32
    return bytes(x ^ y for (x, y) in zip(b0, b1))


def hash_sha512(b: bytes) -> bytes:
    """Plain SHA-512, untagged.

    For the one place that must match RFC 8032 / Solana byte for byte: the
    standard Ed25519 challenge e = SHA-512(R || A || m). Everything else that
    hashes to a scalar goes through tagged_hash.
    """
    return hashlib.sha512(b).digest()
