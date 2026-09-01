"""Test that strict decoding rejects exactly what the spec says it rejects.

These are the adversarial cases: they all decode successfully in every standard
Ed25519 library, and our divergence from those libraries is the property being
pinned here. Each case corresponds to a row of the accept/reject matrix that the
spec requires against dalek verify_strict and the ed25519-speccheck vectors.
"""

import unittest
from random import randint, seed

from ed25519lab.ed25519 import FE, GE, B, Scalar, _mul_int, _recover_x

P = FE.SIZE
L = Scalar.SIZE

# Canonical encodings of the eight points of small order. The neutral element
# has order 1; the other seven must never survive strict decoding.
SMALL_ORDER = {
    "order 1 (neutral)": "0100000000000000000000000000000000000000000000000000000000000000",
    "order 2": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "order 4 (a)": "0000000000000000000000000000000000000000000000000000000000000000",
    "order 4 (b)": "0000000000000000000000000000000000000000000000000000000000000080",
    "order 8 (a)": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "order 8 (b)": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "order 8 (c)": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "order 8 (d)": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
}

# RFC 8032 section 7.1: (message, public key, signature). Every A and every R
# must survive strict decoding -- these are honest, real-world Ed25519 values --
# and test_verify.py additionally checks that the signatures themselves verify.
RFC_8032_7_1 = [
    (
        "",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8"
            "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "72",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a"
            "c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
    (
        "af82",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff"
            "9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    ),
    (
        None,  # the 1023-byte message; not carried here, decode-only vector
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        (
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa53"
            "71b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        ),
    ),
]


def unchecked_decode(h: str) -> GE:
    """Decode without the subgroup check, to BUILD adversarial test points.

    A library that cannot construct these points cannot generate its own
    negative vectors, which is why GE's constructor accepts any curve point and
    only from_bytes is strict.
    """
    b = bytearray.fromhex(h)
    sign = b[31] >> 7
    b[31] &= 0x7F
    y = FE(int.from_bytes(b, "little"))
    x = _recover_x(y, sign)
    assert x is not None
    return GE(x, y)


class SmallOrderTests(unittest.TestCase):
    def test_neutral_is_accepted_only_by_the_with_identity_decoder(self):
        enc = bytes.fromhex(SMALL_ORDER["order 1 (neutral)"])
        self.assertTrue(GE.from_bytes_with_identity(enc).is_identity)
        with self.assertRaises(ValueError):
            GE.from_bytes(enc)

    def test_all_other_small_order_points_are_rejected(self):
        for name, h in SMALL_ORDER.items():
            if name == "order 1 (neutral)":
                continue
            with self.subTest(point=name), self.assertRaises(ValueError):
                GE.from_bytes(bytes.fromhex(h))

    def test_small_order_points_really_are_small_order(self):
        for name, h in SMALL_ORDER.items():
            with self.subTest(point=name):
                t = unchecked_decode(h)
                self.assertTrue((8 * t).is_identity)
                self.assertFalse(t.in_prime_order_subgroup() and not t.is_identity)


class TwoDecodersTests(unittest.TestCase):
    """from_bytes is from_bytes_with_identity plus one
    rejection. This pins that they differ on the identity and NOWHERE else --
    if the strict variant ever grew an extra rule, or the permissive one lost
    the subgroup check, this fails."""

    def _both(self, enc):
        def run(fn):
            try:
                return ("ok", fn(enc).is_identity)
            except ValueError:
                return ("raise", None)
        return run(GE.from_bytes_with_identity), run(GE.from_bytes)

    def test_they_agree_on_everything_except_the_identity(self):
        seed(20)
        cases = [(Scalar(randint(1, L - 1)) * B).to_bytes() for _ in range(20)]
        # every small-order encoding EXCEPT the identity, which is the one
        # input the two decoders are supposed to disagree on
        cases += [
            bytes.fromhex(h)
            for name, h in SMALL_ORDER.items()
            if name != "order 1 (neutral)"
        ]
        cases += [(P + i).to_bytes(32, "little") for i in range(3)]
        cases += [b"", b"\x01" * 31, b"\x01" * 33]
        t = unchecked_decode(SMALL_ORDER["order 8 (a)"])
        cases += [(Scalar(randint(1, L - 1)) * B + t).to_bytes() for _ in range(5)]
        neutral = GE().to_bytes_with_identity()

        differed = []
        for enc in cases:
            lax, strict = self._both(enc)
            if lax != strict:
                differed.append(enc)
        self.assertEqual(differed, [], "the two decoders differ on a non-identity input")

        # ...and they DO differ on the identity.
        lax, strict = self._both(neutral)
        self.assertEqual(lax, ("ok", True))
        self.assertEqual(strict, ("raise", None))

    def test_the_permissive_decoder_is_still_strict_about_everything_else(self):
        for name, h in SMALL_ORDER.items():
            if name == "order 1 (neutral)":
                continue
            with self.subTest(point=name), self.assertRaises(ValueError):
                GE.from_bytes_with_identity(bytes.fromhex(h))
        with self.assertRaises(ValueError):
            GE.from_bytes_with_identity(P.to_bytes(32, "little"))


class MixedOrderTests(unittest.TestCase):
    """P = [k]B + T. Both coordinates are generic, so nothing but an actual
    subgroup check can catch these. This is the real attack shape."""

    def test_mixed_order_points_are_rejected(self):
        seed(11)
        for name in ("order 2", "order 4 (a)", "order 8 (a)"):
            t = unchecked_decode(SMALL_ORDER[name])
            for i in range(10):
                p = Scalar(randint(1, L - 1)) * B + t
                with self.subTest(torsion=name, i=i), self.assertRaises(ValueError):
                    GE.from_bytes(p.to_bytes())


class CanonicalityTests(unittest.TestCase):
    def test_non_canonical_y_is_rejected(self):
        # y in [p, 2**255): every such encoding is non-canonical and must be
        # rejected regardless of whether it happens to land on a curve point.
        tried = 0
        for extra in range(19):
            y = P + extra
            if y >= 2**255:
                break
            tried += 1
            with self.subTest(y=f"p+{extra}"), self.assertRaises(ValueError):
                GE.from_bytes(y.to_bytes(32, "little"))
        self.assertGreater(tried, 0)

    def test_non_canonical_neutral_encoding_is_rejected(self):
        # 0x01 || 31 zero bytes, with the sign bit set: x == 0, so the sign bit
        # carries no information and the encoding is not canonical.
        b = bytearray(b"\x01" + b"\x00" * 31)
        b[31] |= 0x80
        with self.assertRaises(ValueError):
            GE.from_bytes(bytes(b))

    def test_wrong_length_is_rejected(self):
        for b in (b"", b"\x01" * 31, b"\x01" * 33, b"\x01" * 64):
            with self.subTest(n=len(b)), self.assertRaises(ValueError):
                GE.from_bytes(b)

    def test_y_with_no_x_is_rejected(self):
        # Find a y for which (y^2-1)/(d y^2+1) is not a square.
        seed(12)
        found = 0
        for _ in range(200):
            y = randint(0, P - 1)
            if _recover_x(FE(y), 0) is None:
                found += 1
                with self.assertRaises(ValueError):
                    GE.from_bytes(y.to_bytes(32, "little"))
        self.assertGreater(found, 0)


class RFC8032Tests(unittest.TestCase):
    def test_public_keys_decode(self):
        for _, pk, _ in RFC_8032_7_1:
            with self.subTest(pk=pk[:16]):
                a = GE.from_bytes(bytes.fromhex(pk))
                self.assertFalse(a.is_identity)

    def test_signature_r_components_decode(self):
        for _, _, sig in RFC_8032_7_1:
            with self.subTest(sig=sig[:16]):
                GE.from_bytes(bytes.fromhex(sig)[:32])

    def test_signature_s_components_are_valid_scalars(self):
        for _, _, sig in RFC_8032_7_1:
            with self.subTest(sig=sig[:16]):
                Scalar.from_bytes_checked(bytes.fromhex(sig)[32:])


class CofactorTests(unittest.TestCase):
    """The verify equation must be cofactorless, to match Solana.

    RFC 8032 section 5.1.7 gives [8][s]B = [8]R + [8][e]A as the primary form
    and permits [s]B = R + [e]A as an alternative. The RFC's own appendix code
    implements the cofactored one. We need the other one, and the difference is
    observable: adding a torsion point to R is accepted by the cofactored
    equation and rejected by the cofactorless one.
    """

    def setUp(self):
        seed(13)
        self.a = Scalar(randint(1, L - 1))
        self.A = self.a * B
        self.r = Scalar(randint(1, L - 1))
        self.R = self.r * B
        self.e = Scalar(randint(1, L - 1))
        self.s = self.r + self.e * self.a

    def test_honest_signature_satisfies_the_cofactorless_equation(self):
        self.assertEqual(self.s * B, self.R + self.e * self.A)

    def test_torsion_in_R_breaks_cofactorless_but_not_cofactored(self):
        for name in ("order 2", "order 4 (a)", "order 8 (a)"):
            with self.subTest(torsion=name):
                t = unchecked_decode(SMALL_ORDER[name])
                r_bad = self.R + t
                self.assertNotEqual(self.s * B, r_bad + self.e * self.A)
                self.assertEqual(8 * (self.s * B), 8 * r_bad + 8 * (self.e * self.A))

    def test_strict_decode_rejects_the_tainted_R_anyway(self):
        # Belt and braces: even a cofactored verifier would never see it,
        # because R does not survive parsing.
        t = unchecked_decode(SMALL_ORDER["order 8 (a)"])
        with self.assertRaises(ValueError):
            GE.from_bytes((self.R + t).to_bytes())

class ScalarMulReductionTests(unittest.TestCase):
    """`int * GE` reduces the scalar mod L, which is only correct inside the
    prime-order subgroup. in_prime_order_subgroup therefore uses _mul_int, and
    must keep using it: rewriting it as `(self.ORDER * self).is_identity` makes
    it a tautology -- L mod L == 0, so every point passes -- and silently takes
    the decode policy, the ECDH argument and verify_strict parity with it."""

    def test_the_operator_reduces_mod_L_but_the_predicate_must_not(self):
        t = unchecked_decode(SMALL_ORDER["order 2"])
        self.assertTrue((GE.ORDER * t).is_identity)
        self.assertFalse(_mul_int(t, GE.ORDER).is_identity)
        self.assertFalse(t.in_prime_order_subgroup())

    def test_the_two_paths_agree_inside_the_subgroup(self):
        seed(41)
        for _ in range(5):
            p = Scalar(randint(1, L - 1)) * B
            k = randint(1, 3 * L)
            with self.subTest(k=k % 97):
                self.assertEqual(k * p, _mul_int(p, k))


if __name__ == "__main__":
    unittest.main()
