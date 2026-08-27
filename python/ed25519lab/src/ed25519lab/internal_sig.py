# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The internal signature scheme used by PoP and CertEq.

This REPLACES secp256k1lab's schnorr_sign / schnorr_verify (BIP340). The rename
is deliberate and load-bearing: this is a different scheme, and the old name
would invite using it as a general-purpose signer, which it must never be.

WHY IT IS NOT A REAL Ed25519 SIGNATURE, AND WHY THAT IS THE POINT

The domain tag is prepended to the challenge input, BEFORE R and the public key:

    e = wide_reduce(SHA-512(tag || bytes(R) || bytes(A) || m))

Standard Ed25519 computes e = wide_reduce(SHA-512(bytes(R) || bytes(A) || m)).
Because R and A are pinned by the signature and the key, there is no message m'
for which the standard challenge equals ours -- finding one means finding a
SHA-512 collision. So an internal signature is structurally unverifiable outside
this protocol.

Had the tag been placed after, on the message only, the result would have been a
VALID Ed25519 signature over the prefixed message tag || m. That is exactly the
property we do not want here: a PoP or CertEq signature must never be replayable
as an ordinary signature.

NONCE DERIVATION

Standard Ed25519 derives its deterministic nonce from a by-product of the seed,
prefix = SHA-512(seed)[32:]. This protocol has no seeds anywhere -- host keys are
raw scalars -- so that mechanism does not exist for us and the derivation has to
be spelled out. It is keyed by the raw secret scalar instead:

    k = wide_reduce(SHA-512(tag || d_le || aux || m))

Deterministic nonces are safe here because PoP and CertEq are SINGLE-PARTY
signatures; the MPSW18 multi-party attack does not apply. `aux` is optional
extra entropy.
"""

from .ed25519 import GE, B, Scalar
from .util import tagged_hash

__all__ = ["TAG_CHALLENGE", "TAG_NONCE", "internal_sign", "internal_verify"]

TAG_NONCE = "ChillDKG-ed25519-v1/int/nonce"
TAG_CHALLENGE = "ChillDKG-ed25519-v1/int/challenge"

# aux is fixed-width on purpose; see the note in internal_sign.
AUX_SIZE = 32
NO_AUX = b"\x00" * AUX_SIZE


def internal_sign(msg: bytes, seckey: bytes, aux: bytes = NO_AUX) -> bytes:
    """Sign msg with a raw secret scalar. Returns 64 bytes, bytes(R) || le(s).

    `aux` MUST be exactly 32 bytes; pass NO_AUX for the purely deterministic
    variant.

    WHY aux IS FIXED-WIDTH -- this refines the spec, which writes the nonce
    input as `tag || d_le || aux || m` with both aux and m variable-length.
    Plain concatenation is not injective, so distinct (aux, m) pairs can produce
    the same byte string and therefore the same k. Two signatures with the same
    R and different messages give different challenges, and the secret key falls
    straight out of d = (s1 - s2) / (e1 - e2). Fixing aux at 32 bytes makes
    d_le || aux exactly 64 bytes, so m is unambiguously the tail and the
    collision is impossible by construction. BIP340 solves the same problem the
    same way, by hashing its aux down to a fixed width first.
    """
    if len(aux) != AUX_SIZE:
        raise ValueError(f"aux must be exactly {AUX_SIZE} bytes, got {len(aux)}")
    d = Scalar.from_bytes_nonzero_checked(seckey)
    a = d * B
    assert not a.is_identity

    k = Scalar.from_bytes_wide(tagged_hash(TAG_NONCE, d.to_bytes(), aux, msg))
    if k == 0:
        raise RuntimeError("Failure. This happens only with negligible probability.")
    r = k * B
    assert not r.is_identity

    e = Scalar.from_bytes_wide(
        tagged_hash(TAG_CHALLENGE, r.to_bytes(), a.to_bytes(), msg)
    )
    s = k + e * d
    sig = r.to_bytes() + s.to_bytes()
    assert internal_verify(msg, a.to_bytes(), sig)
    return sig


def internal_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify an internal signature. Returns False rather than raising.

    The group equation is COFACTORLESS:

        [s]B == R + [e]A

    Every point here arrives through GE.from_bytes, which enforces
    the prime-order subgroup, so the cofactored form would accept exactly the
    same set -- but writing the cofactorless one keeps a single verification
    equation across the whole protocol and matches what Solana enforces for the
    final aggregate signature.

    IDENTITY. A is [d]B with d nonzero and R is [k]B with k nonzero, so neither
    can legitimately be the identity here; an identity means a broken or
    malicious signer. from_bytes already refuses it, so this function
    needs no separate check -- the rejection lands in the except below.
    """
    if len(pubkey) != 32:
        raise ValueError("The public key must be a 32-byte array.")
    if len(sig) != 64:
        raise ValueError("The signature must be a 64-byte array.")
    try:
        a = GE.from_bytes(pubkey)
        r = GE.from_bytes(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False

    e = Scalar.from_bytes_wide(tagged_hash(TAG_CHALLENGE, sig[0:32], pubkey, msg))
    return s * B == r + e * a
