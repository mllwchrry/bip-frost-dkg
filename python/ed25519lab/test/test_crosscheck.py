"""Cross-check every primitive against an independent implementation.

The oracle is libsodium via PyNaCl. The version floor is load-bearing:
CVE-2025-69277 -- libsodium <= 1.0.20 wrongly accepted some mixed-order points
in crypto_core_ed25519_is_valid_point, which is exactly the function used here
as a second opinion on our subgroup predicate.

PyNaCl is a test-only dependency; ed25519lab itself has none. If it is missing
or too old, this module skips rather than fails -- EXCEPT when
ED25519LAB_REQUIRE_CROSSCHECK is set, which turns the skip into an error. CI
sets it, because a green run with these tests silently skipped would mean the
only independent check of our arithmetic never executed.
"""

import os
import unittest
from random import randint, seed

from ed25519lab.ed25519 import GE, B, Scalar
from ed25519lab.keys import pubkey_gen

L = Scalar.SIZE

# libsodium <= 1.0.20 wrongly accepted some mixed-order points in
# crypto_core_ed25519_is_valid_point (CVE-2025-69277). PyNaCl 1.6.2 is the first
# release bundling a fixed libsodium, so compare all three components: a
# major.minor comparison would silently accept 1.6.0 and 1.6.1.
MIN_PYNACL = (1, 6, 2)


def _parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in v.split(".")[:3]:
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


try:
    import nacl
    import nacl.bindings as sodium

    _v = _parse_version(nacl.__version__)
    HAVE_SODIUM = _v >= MIN_PYNACL
    SKIP_REASON = (
        f"PyNaCl {nacl.__version__} < "
        f"{'.'.join(map(str, MIN_PYNACL))} (CVE-2025-69277)"
    )
except ImportError:
    HAVE_SODIUM = False
    SKIP_REASON = "PyNaCl not installed"

if not HAVE_SODIUM and os.environ.get("ED25519LAB_REQUIRE_CROSSCHECK"):
    raise RuntimeError(
        f"ED25519LAB_REQUIRE_CROSSCHECK is set but the cross-check oracle is "
        f"unusable: {SKIP_REASON}. Install with: "
        f"pip install 'pynacl>={'.'.join(map(str, MIN_PYNACL))}'"
    )


class VersionParsingTests(unittest.TestCase):
    """The CVE floor is only as good as the comparison enforcing it."""

    def test_floor_rejects_earlier_1_6_releases(self):
        for bad in ("1.5.0", "1.6", "1.6.0", "1.6.1"):
            with self.subTest(v=bad):
                self.assertLess(_parse_version(bad), MIN_PYNACL)
        for ok in ("1.6.2", "1.6.10", "1.7.0", "2.0.0", "1.6.2.dev0"):
            with self.subTest(v=ok):
                self.assertGreaterEqual(_parse_version(ok), MIN_PYNACL)


def rand_scalar() -> Scalar:
    return Scalar(randint(1, L - 1))


@unittest.skipUnless(HAVE_SODIUM, SKIP_REASON)
class LibsodiumCrossCheck(unittest.TestCase):
    def setUp(self):
        seed(20260818)

    def test_scalarmult_base_noclamp(self):
        for _ in range(30):
            a = rand_scalar()
            self.assertEqual(
                (a * B).to_bytes(),
                sodium.crypto_scalarmult_ed25519_base_noclamp(a.to_bytes()),
            )

    def test_scalarmult_noclamp(self):
        for _ in range(30):
            a, b = rand_scalar(), rand_scalar()
            p = a * B
            self.assertEqual(
                (b * p).to_bytes(),
                sodium.crypto_scalarmult_ed25519_noclamp(b.to_bytes(), p.to_bytes()),
            )

    def test_point_add_and_sub(self):
        for _ in range(30):
            p, q = rand_scalar() * B, rand_scalar() * B
            pb, qb = p.to_bytes(), q.to_bytes()
            self.assertEqual((p + q).to_bytes(), sodium.crypto_core_ed25519_add(pb, qb))
            self.assertEqual((p - q).to_bytes(), sodium.crypto_core_ed25519_sub(pb, qb))

    def test_negation(self):
        for _ in range(30):
            p = rand_scalar() * B
            self.assertEqual(
                (-p).to_bytes(),
                sodium.crypto_core_ed25519_sub(
                    GE().to_bytes_with_identity(), p.to_bytes()
                ),
            )

    def test_wide_reduction(self):
        for _ in range(30):
            h = bytes(randint(0, 255) for _ in range(64))
            self.assertEqual(
                Scalar.from_bytes_wide(h).to_bytes(),
                sodium.crypto_core_ed25519_scalar_reduce(h),
            )

    def test_scalar_arithmetic(self):
        for _ in range(30):
            a, b = rand_scalar(), rand_scalar()
            self.assertEqual(
                (a + b).to_bytes(),
                sodium.crypto_core_ed25519_scalar_add(a.to_bytes(), b.to_bytes()),
            )
            self.assertEqual(
                (a * b).to_bytes(),
                sodium.crypto_core_ed25519_scalar_mul(a.to_bytes(), b.to_bytes()),
            )
            self.assertEqual(
                (Scalar(1) / a).to_bytes(),
                sodium.crypto_core_ed25519_scalar_invert(a.to_bytes()),
            )

    def test_pubkey_gen_is_raw_scalar(self):
        # Not RFC 8032 key generation: no seed, no SHA-512, no clamping.
        for _ in range(20):
            sk = rand_scalar().to_bytes()
            self.assertEqual(pubkey_gen(sk), sodium.crypto_scalarmult_ed25519_base_noclamp(sk))

    def test_subgroup_predicate_agrees(self):
        from test.test_strictness import SMALL_ORDER, unchecked_decode

        for _ in range(30):
            enc = (rand_scalar() * B).to_bytes()
            self.assertTrue(sodium.crypto_core_ed25519_is_valid_point(enc))
            self.assertTrue(GE.from_bytes(enc).in_prime_order_subgroup())

        for name in ("order 2", "order 4 (a)", "order 8 (a)"):
            t = unchecked_decode(SMALL_ORDER[name])
            for _ in range(10):
                enc = (rand_scalar() * B + t).to_bytes()
                with self.subTest(torsion=name):
                    self.assertFalse(sodium.crypto_core_ed25519_is_valid_point(enc))
                    with self.assertRaises(ValueError):
                        GE.from_bytes(enc)
    def test_libsodium_also_rejects_non_canonical_encodings(self):
        # is_valid_point is not only a subgroup predicate: it also enforces
        # canonicality, so it is a usable oracle for most of our decode policy.
        from ed25519lab.ed25519 import FE

        non_canonical = [(FE.SIZE + i).to_bytes(32, "little") for i in range(4)]
        nc_neutral = bytearray(b"\x01" + b"\x00" * 31)
        nc_neutral[31] |= 0x80
        for enc in non_canonical + [bytes(nc_neutral)]:
            with self.subTest(enc=enc.hex()[:16]):
                self.assertFalse(sodium.crypto_core_ed25519_is_valid_point(enc))
                with self.assertRaises(ValueError):
                    GE.from_bytes(enc)

    def test_we_now_agree_with_libsodium_on_the_neutral_element(self):
        """This used to be the one row where libsodium was not a valid oracle.

        crypto_core_ed25519_is_valid_point accepts only points "on the main
        subgroup" that "do not have a small order", and the identity has order
        one, so libsodium refuses it. We used to accept it in
        from_bytes and push the decision to each call site. Since the
        decoder was split, from_bytes refuses it too and the
        divergence is gone -- libsodium is now a clean oracle for the default
        decoder on every input class.

        The permissive variant still accepts it, which is the whole point of
        having two: the identity is a real element of the prime-order subgroup,
        it just is not a valid value at most call sites.
        """
        neutral = GE().to_bytes_with_identity()
        self.assertEqual(neutral, b"\x01" + b"\x00" * 31)
        self.assertFalse(sodium.crypto_core_ed25519_is_valid_point(neutral))
        with self.assertRaises(ValueError):
            GE.from_bytes(neutral)
        self.assertTrue(GE.from_bytes_with_identity(neutral).is_identity)
        self.assertTrue(GE().in_prime_order_subgroup())


@unittest.skipUnless(HAVE_SODIUM, SKIP_REASON)
class ProtocolCrossCheck(unittest.TestCase):
    def setUp(self):
        seed(20260819)

    def test_ecdh_shared_point_matches_libsodium(self):
        """The KDF is ours, but the shared point underneath must be standard."""
        from ed25519lab.ecdh import TAG_ECDH, ecdh_ed25519
        from ed25519lab.keys import pubkey_gen
        from ed25519lab.util import tagged_hash

        for _ in range(10):
            sk_a, sk_b = rand_scalar().to_bytes(), rand_scalar().to_bytes()
            pk_a, pk_b = pubkey_gen(sk_a), pubkey_gen(sk_b)

            shared = sodium.crypto_scalarmult_ed25519_noclamp(sk_a, pk_b)
            self.assertEqual(
                shared,
                sodium.crypto_scalarmult_ed25519_noclamp(sk_b, pk_a),
            )
            expected = Scalar.from_bytes_wide(
                tagged_hash(TAG_ECDH, shared, pk_a, pk_b, b"ctx")
            )
            self.assertEqual(ecdh_ed25519(sk_a, pk_b, b"ctx", sending=True), expected)
            self.assertEqual(ecdh_ed25519(sk_b, pk_a, b"ctx", sending=False), expected)

    def test_libsodium_rejects_our_internal_signature(self):
        """An internal signature must not verify as a standard Ed25519 one.

        The structural argument is in test_internal_sig; this is the same claim
        put to an independent implementation.
        """
        import nacl.exceptions

        from ed25519lab.internal_sig import TAG_CHALLENGE, internal_sign
        from ed25519lab.keys import pubkey_gen

        sk = rand_scalar().to_bytes()
        pk = pubkey_gen(sk)
        msg = b"payload"
        sig = internal_sign(msg, sk)
        for candidate in (msg, TAG_CHALLENGE.encode() + msg, b""):
            # crypto_sign_open takes signature || message
            with (
                self.subTest(msg=candidate[:16]),
                self.assertRaises(nacl.exceptions.BadSignatureError),
            ):
                sodium.crypto_sign_open(sig + candidate, pk)


    def test_ed25519_verify_agrees_with_libsodium_on_honest_signatures(self):
        """Signatures produced by libsodium must verify under our verifier."""
        from ed25519lab.verify import ed25519_verify

        for _ in range(20):
            pk, sk = sodium.crypto_sign_keypair()
            msg = bytes(randint(0, 255) for _ in range(randint(0, 64)))
            sig = sodium.crypto_sign(msg, sk)[:64]
            self.assertTrue(ed25519_verify(msg, pk, sig))
            self.assertFalse(ed25519_verify(msg + b"x", pk, sig))

    def test_KNOWN_DIVERGENCE_libsodium_accepts_a_mixed_order_pubkey(self):
        """The concrete signature where we and a standard library disagree.

        See test_verify.KnownDivergenceFromDalekTests for the construction. The
        point of running it here is that the "other side" of the divergence is
        an implementation we did not write: libsodium ACCEPTS this signature.

        Note also that libsodium is internally inconsistent about it --
        crypto_core_ed25519_is_valid_point rejects the same key that
        crypto_sign_open accepts, because signature verification does not go
        through the point-validation path.
        """
        import nacl.exceptions

        from ed25519lab.verify import ed25519_verify
        from test.test_verify import forge_mixed_order_pubkey

        msg, pk_mixed, sig, *_ = forge_mixed_order_pubkey()

        self.assertFalse(ed25519_verify(msg, pk_mixed, sig))
        self.assertFalse(sodium.crypto_core_ed25519_is_valid_point(pk_mixed))
        try:
            sodium.crypto_sign_open(sig + msg, pk_mixed)
            accepted = True
        except nacl.exceptions.BadSignatureError:
            accepted = False
        self.assertTrue(accepted, "libsodium was expected to accept this signature")


if __name__ == "__main__":
    unittest.main()
