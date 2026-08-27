# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Standard Ed25519 verification for the fork's final output.

The aggregated FROST signature is an ordinary Ed25519 signature that has to be
accepted on Solana. This is the verifier for it -- distinct from
internal_sig.internal_verify, which checks the domain-separated internal scheme
used by PoP and CertEq and is deliberately not an Ed25519 verifier at all.

Note that the spec's API mapping table has no row for this function. It should:
pitfall 3 requires "our verifier" to be the cofactorless form, which presupposes
one exists.
"""

from .ed25519 import GE, B, Scalar
from .util import hash_sha512

__all__ = ["ed25519_verify"]


def ed25519_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify a standard Ed25519 signature, COFACTORLESS: [s]B == R + [e]A.

    Rejects, in order: wrong signature length; a non-canonical or off-curve or
    out-of-subgroup A or R; s >= L; the neutral element as A or R; and finally a
    failing group equation.

    WHY COFACTORLESS. RFC 8032 section 5.1.7 gives [8][s]B = [8]R + [8][e]A as
    its primary form and permits the cofactorless one as an alternative, and the
    RFC's own appendix code implements the cofactored one. Copying that verbatim
    would give the permissive verifier. Solana enforces the cofactorless
    equation, so that is what this is.

    SMALL ORDER, INCLUDING THE IDENTITY. ed25519-dalek's verify_strict rejects A
    and R of small order, and its is_small_order() is true for all eight torsion
    points, the identity included. GE.from_bytes rejects the seven
    non-identity ones via the subgroup check and the identity explicitly, so all
    eight are refused at parse time and nothing further is needed here.

    NOT A MODEL OF WHAT SOLANA ACCEPTS -- read this before using it as an oracle.

    This verifier is STRICTER than dalek verify_strict, in one specific way:
    GE.from_bytes rejects mixed-order points, A = [a]B + T, at parse
    time, whereas dalek only rejects SMALL-order points and lets mixed-order
    ones through to the group equation. The equation can be made to hold for a
    mixed-order A whenever the challenge happens to be divisible by the order of
    the torsion component, which an attacker reaches by grinding a handful of
    candidates. Such a signature is accepted by dalek and rejected here.

    That divergence is intended -- it is the fork's whole decode policy -- but it
    means this function answers "is this valid under our rules", NOT "would
    Solana accept this". For the second question the answer has to come from
    solders / dalek itself, and the spec's section 6 already calls for recording
    both verdicts per vector.
    """
    if len(sig) != 64:
        return False
    try:
        a = GE.from_bytes(pubkey)
        r = GE.from_bytes(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False

    e = Scalar.from_bytes_wide(hash_sha512(sig[0:32] + pubkey + msg))
    return s * B == r + e * a
