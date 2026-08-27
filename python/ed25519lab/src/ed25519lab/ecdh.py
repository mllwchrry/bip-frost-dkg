# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""ECDH key derivation for encrypted share transport (EncPedPop).

This replaces secp256k1lab's ecdh_libsecp256k1. The rename is not cosmetic: the
old name names the wrong curve and the wrong library.

Two changes carry real security weight.

STRICT DECODE OF THE PEER KEY. GE.from_bytes rejects small-order and
mixed-order points, which closes a small-subgroup attack: a torsioned peer key
would make the shared point depend on deckey only through deckey mod 8, leaking
three bits of the long-term decryption key per exchange.

The security argument here DEPENDS on the subgroup check happening at parse
time. That dependency is not a footnote -- it is the whole reason this function
does not need a cofactor multiplication of its own. (The belt-and-braces
alternative, multiplying the shared point by 8 before hashing, is deliberately
not used: the library has one uniform decode policy and this call site relies on
it like every other.)

THE RAW SHARED POINT IS NEVER KEY MATERIAL. It goes into a KDF together with
both public keys, which binds the derived key to this specific pair and session.
Using the point directly would leave the key unbound to who is talking to whom.

X25519 was considered and rejected: it would drag in Montgomery form, clamping,
and a second key encoding for no benefit, given that host keys are already
Edwards points.
"""

from .ed25519 import GE, B, Scalar
from .util import tagged_hash

__all__ = ["TAG_ECDH", "ecdh_ed25519"]

# Verbatim from the spec. Note the space rather than a slash before "ecdh" --
# inherited from the upstream tag name; harmless, but worth normalising if the
# spec is ever revised.
TAG_ECDH = "ChillDKG-ed25519-v1/encpedpop ecdh"


def ecdh_ed25519(seckey: bytes, pubkey: bytes, context: bytes, sending: bool) -> Scalar:
    """Derive the additive encryption pad shared with a peer.

        pad = wide_reduce(SHA-512(tag || bytes([d]P_peer)
                                      || pk_sender || pk_recipient || context))

    `sending` selects the ordering of the two public keys, so that both sides
    derive the same pad: the sender puts its own key first, the recipient puts
    the peer's key first. Getting this backwards is silent -- the two sides
    simply derive different pads and decryption produces garbage -- so it is
    covered by a round-trip test.

    Returns a Scalar because the ciphertext is `share + pad mod L`; that
    additive construction and the coordinator's homomorphic ciphertext summation
    carry over from upstream unchanged.

    The concatenation is unambiguous: the shared point and both public keys are
    32 bytes each, and `context` is the only variable-length part and comes
    last. See tagged_hash for why that matters.
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    # from_bytes refuses the identity as well as small- and
    # mixed-order points, which is exactly this call site's policy.
    peer = GE.from_bytes(pubkey)

    shared = d * peer
    assert not shared.is_identity  # d != 0 and peer has prime order

    own = (d * B).to_bytes()
    pk_sender, pk_recipient = (own, pubkey) if sending else (pubkey, own)

    return Scalar.from_bytes_wide(
        tagged_hash(
            TAG_ECDH,
            shared.to_bytes(),
            pk_sender,
            pk_recipient,
            context,
        )
    )
