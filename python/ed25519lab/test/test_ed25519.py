"""Test low-level Ed25519 field, scalar and group arithmetic classes."""

import ast
import hashlib
import unittest
from pathlib import Path
from random import randint, seed

from ed25519lab.ed25519 import FAST_B, FE, GE, B, FastGEMul, Scalar
from ed25519lab.keys import pubkey_gen
from ed25519lab.util import (
    bytes_from_int,
    hash_sha512,
    int_from_bytes,
    tagged_hash,
    xor_bytes,
)

P = FE.SIZE
L = Scalar.SIZE

# The base point B, RFC 8032 section 5.1.
B_ENC = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
NEUTRAL_ENC = b"\x01" + b"\x00" * 31


def le(v: int) -> bytes:
    return v.to_bytes(32, "little")


class PrimeFieldTests(unittest.TestCase):
    def test_fe_constructors(self):
        seed(1)
        random_valid = randint(0, P - 1)
        random_overflowing = randint(P, 2**256 - 1)

        for init_value in [0, P - 1, P, P + 1, random_valid, random_overflowing]:
            fe1 = FE(init_value)
            fe2 = FE.from_int_wrapping(init_value)
            self.assertEqual(int(fe1), init_value % P)
            self.assertEqual(int(fe2), init_value % P)

        for init_value in [0, P - 1, random_valid]:
            self.assertEqual(int(FE.from_int_checked(init_value)), init_value)
            self.assertEqual(int(FE.from_bytes_checked(le(init_value))), init_value)

        for init_value in [P, P + 1, random_overflowing]:
            with self.assertRaises(ValueError):
                FE.from_int_checked(init_value)

    def test_fe_byte_order_is_little_endian(self):
        self.assertEqual(FE(1).to_bytes(), le(1))
        self.assertEqual(int(FE.from_bytes_checked(le(258))), 258)

    def test_fe_sqrt(self):
        seed(2)
        squares = nonsquares = 0
        for _ in range(200):
            a = FE(randint(1, P - 1))
            r = (a * a).sqrt()
            self.assertIsNotNone(r)
            self.assertEqual(r * r, a * a)
            squares += 1
            if a.sqrt() is None:
                nonsquares += 1
        self.assertGreater(squares, 0)
        # roughly half of all field elements are non-squares
        self.assertGreater(nonsquares, 50)

    def test_fe_arithmetic_identities(self):
        seed(3)
        for _ in range(50):
            a, b = FE(randint(0, P - 1)), FE(randint(1, P - 1))
            self.assertEqual(a + b - b, a)
            self.assertEqual(a * b / b, a)
            neg_a = -a
            self.assertEqual(-neg_a, a)
            self.assertEqual(a**2, a * a)


class ScalarTests(unittest.TestCase):
    def test_size_is_the_group_order(self):
        self.assertEqual(Scalar.SIZE, 2**252 + 27742317777372353535851937790883648493)
        self.assertEqual(GE.ORDER, Scalar.SIZE)

    def test_from_bytes_checked(self):
        self.assertEqual(int(Scalar.from_bytes_checked(le(L - 1))), L - 1)
        self.assertEqual(int(Scalar.from_bytes_checked(le(0))), 0)
        for bad in (L, L + 7, 2**255 - 1):
            with self.assertRaises(ValueError):
                Scalar.from_bytes_checked(le(bad))

    def test_from_bytes_nonzero_checked(self):
        self.assertEqual(int(Scalar.from_bytes_nonzero_checked(le(1))), 1)
        with self.assertRaises(ValueError):
            Scalar.from_bytes_nonzero_checked(le(0))
        with self.assertRaises(ValueError):
            Scalar.from_bytes_nonzero_checked(le(L))

    def test_from_bytes_wide_requires_64_bytes(self):
        # The whole point of the distinct name: a 32-byte digest must not parse.
        with self.assertRaises(ValueError):
            Scalar.from_bytes_wide(b"\x11" * 32)
        with self.assertRaises(ValueError):
            Scalar.from_bytes_wide(b"\x11" * 63)
        self.assertLess(int(Scalar.from_bytes_wide(b"\x11" * 64)), L)

    def test_from_bytes_wide_reduces(self):
        seed(4)
        for _ in range(50):
            v = randint(0, 2**512 - 1)
            self.assertEqual(int(Scalar.from_bytes_wide(v.to_bytes(64, "little"))), v % L)

    def test_a_random_32_byte_value_is_rarely_a_valid_scalar(self):
        # This is why from_bytes_wide exists. On secp256k1 this fraction is
        # ~1.0; here it is ~1/16, so parsing a digest with from_bytes_checked
        # fails about fifteen sessions out of sixteen.
        seed(5)
        n = 20000
        below = sum(1 for _ in range(n) if randint(0, 2**256 - 1) < L)
        self.assertLess(below / n, 0.08)
        self.assertGreater(below / n, 0.05)

    def test_scalar_byte_order_is_little_endian(self):
        self.assertEqual(Scalar(1).to_bytes(), le(1))

    def test_sum_and_inverse(self):
        seed(6)
        for _ in range(30):
            a, b = Scalar(randint(1, L - 1)), Scalar(randint(1, L - 1))
            self.assertEqual(Scalar.sum(a, b), a + b)
            self.assertEqual(a * (Scalar(1) / a), Scalar(1))
        self.assertEqual(Scalar.sum(), Scalar(0))


class GroupElementTests(unittest.TestCase):
    def test_base_point(self):
        self.assertEqual(B.to_bytes(), B_ENC)
        self.assertEqual(int(B.y), int(FE(4) / FE(5)))
        self.assertTrue(B.x.is_even())

    def test_neutral_element(self):
        self.assertTrue(GE().is_identity)
        self.assertEqual(GE().to_bytes_with_identity(), NEUTRAL_ENC)
        self.assertTrue(GE.from_bytes_with_identity(NEUTRAL_ENC).is_identity)
        with self.assertRaises(ValueError):
            GE.from_bytes(NEUTRAL_ENC)  # strict variant refuses it
        self.assertTrue(GE.sum().is_identity)
        self.assertTrue(GE.batch_mul().is_identity)
    
    def test_to_bytes_refuses_the_identity(self):
        self.assertEqual(GE().to_bytes_with_identity(), NEUTRAL_ENC)
        with self.assertRaises(ValueError):
            GE().to_bytes()

    def test_neutral_is_not_the_order_two_point(self):
        # (0, -1) has x == 0 but is NOT the neutral element. Checking only x
        # would conflate them; this asserts we do not.
        t2 = GE(FE(0), FE(-1))
        self.assertFalse(t2.is_identity)
        self.assertNotEqual(t2, GE())
        self.assertTrue((t2 + t2).is_identity)

    def test_group_law(self):
        seed(7)
        for _ in range(30):
            a, b = Scalar(randint(1, L - 1)), Scalar(randint(1, L - 1))
            pa, pb = a * B, b * B
            self.assertEqual(pa + pb, (a + b) * B)
            self.assertEqual(pa - pa, GE())
            self.assertEqual(-pa, (-a) * B)
            self.assertEqual(b * pa, (a * b) * B)

    def test_order(self):
        self.assertTrue((Scalar(0) * B).is_identity)
        self.assertTrue(B.in_prime_order_subgroup())
        self.assertTrue((GE.ORDER * B).is_identity)

    def test_sum_with_arguments(self):
        # ChillDKG builds sum_coms with this; it was previously only tested
        # with zero arguments, so the loop body never ran.
        seed(15)
        pts = [Scalar(randint(1, L - 1)) * B for _ in range(6)]
        expect = GE()
        for p in pts:
            expect = expect + p
        self.assertEqual(GE.sum(*pts), expect)
        self.assertEqual(GE.sum(pts[0]), pts[0])
        self.assertTrue(GE.sum(pts[0], -pts[0]).is_identity)

    def test_hash_and_str(self):
        seed(16)
        p = Scalar(randint(1, L - 1)) * B
        self.assertEqual(hash(p), hash(GE.from_bytes(p.to_bytes())))
        self.assertEqual({p, p}, {p})
        self.assertEqual(str(p), p.to_bytes().hex())
        self.assertEqual(repr(GE()), "GE()")
        self.assertEqual(hash(FE(5)), hash(FE(5)))
        self.assertTrue(FE(4).is_square())

    def test_error_paths(self):
        from ed25519lab.ed25519 import _mul_int

        with self.assertRaises(ValueError):
            GE(FE(0), None)          # one coordinate given, not both
        with self.assertRaises(ValueError):
            FE.from_bytes_checked(b"\x00" * 31)
        with self.assertRaises(ValueError):
            _mul_int(B, -1)          # negative scalar

    def test_batch_mul(self):
        seed(8)
        pairs = [(Scalar(randint(1, L - 1)), Scalar(randint(1, L - 1)) * B) for _ in range(5)]
        expect = GE()
        for s, p in pairs:
            expect = expect + s * p
        self.assertEqual(GE.batch_mul(*pairs), expect)

    def test_encode_decode_roundtrip(self):
        seed(9)
        for _ in range(50):
            p = Scalar(randint(1, L - 1)) * B
            self.assertEqual(GE.from_bytes(p.to_bytes()), p)

    def test_off_curve_rejected(self):
        with self.assertRaises(ValueError):
            GE(FE(1), FE(1))


class FastGEMulTests(unittest.TestCase):
    """k * B takes a precomputed-table path instead of double-and-add.

    Two code paths for the same operation is the one real cost of the table, so
    the equivalence is pinned rather than assumed: a divergence would only ever
    show up for base-point multiplications, which is exactly the kind of bug
    that hides.
    """

    def test_fast_g_agrees_with_the_generic_path(self):
        from ed25519lab.ed25519 import _mul_int

        seed(17)
        edges = [0, 1, 2, 3, L - 2, L - 1] + [1 << i for i in (0, 1, 8, 127, 251)]
        randoms = [randint(0, L - 1) for _ in range(150)]
        for k in edges + randoms:
            with self.subTest(k=hex(k)[:12]):
                self.assertEqual(FAST_B.mul(k), _mul_int(B, k))

    def test_the_operator_uses_the_table_and_still_agrees(self):
        from ed25519lab.ed25519 import _mul_int

        seed(18)
        for _ in range(30):
            k = Scalar(randint(1, L - 1))
            self.assertEqual(k * B, _mul_int(B, int(k)))
        # A point that merely equals B also takes the fast path; same answer.
        g_copy = GE(B.x, B.y)
        self.assertEqual(Scalar(7) * g_copy, _mul_int(B, 7))

    def test_table_shape(self):
        self.assertEqual(len(FAST_B.table), 256)
        self.assertEqual(FAST_B.table[0], B)
        for i in (1, 2, 3, 10):
            with self.subTest(i=i):
                self.assertEqual(FAST_B.table[i], (1 << i) * B)

    def test_zero_and_negative(self):
        self.assertTrue(FAST_B.mul(0).is_identity)
        self.assertTrue((Scalar(0) * B).is_identity)
        with self.assertRaises(ValueError):
            FAST_B.mul(-1)

    def test_table_for_a_non_generator_point(self):
        from ed25519lab.ed25519 import _mul_int

        seed(19)
        p = Scalar(randint(1, L - 1)) * B
        fast_p = FastGEMul(p)
        for _ in range(10):
            k = randint(0, L - 1)
            with self.subTest(k=hex(k)[:12]):
                self.assertEqual(fast_p.mul(k), _mul_int(p, k))


class KeyTests(unittest.TestCase):
    def test_pubkey_gen(self):
        self.assertEqual(pubkey_gen(le(1)), B_ENC)
        seed(10)
        d = randint(1, L - 1)
        self.assertEqual(pubkey_gen(le(d)), (Scalar(d) * B).to_bytes())

    def test_pubkey_gen_rejects_bad_secrets(self):
        for bad in (le(0), le(L), le(L + 1), b"\x01" * 31):
            with self.assertRaises(ValueError):
                pubkey_gen(bad)


class UtilTests(unittest.TestCase):
    def test_the_library_uses_exactly_one_hash_function(self):
        """SHA-512 everywhere, including the tag digest. A reference
        implementation with two primitives is two things to port correctly.

        Parsed rather than grepped, and over the whole package rather than one
        module: a substring search would be fooled by the word "SHA-256" in a
        docstring (util.py contains several, explaining what BIP340 does) and
        would miss a second primitive introduced in any other file.
        """
        import ed25519lab

        pkg = Path(ed25519lab.__file__).parent
        used = {}
        for path in sorted(pkg.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "hashlib"
                ):
                    used.setdefault(node.attr, set()).add(path.name)
        self.assertEqual(sorted(used), ["sha512"], f"hashlib calls: {used}")

    def test_tagged_hash_digests_the_tag_to_a_fixed_width(self):
        self.assertEqual(
            tagged_hash("proto-v1/nonce", b"\x01\x02", b"\x03"),
            hashlib.sha512(hashlib.sha512(b"proto-v1/nonce").digest()[:32] + b"\x01\x02\x03").digest(),
        )

    def test_tagged_hash_is_not_the_plain_prefix_construction(self):
        # The trap this construction exists to avoid.
        self.assertNotEqual(
            tagged_hash("proto-v1/nonce", b"\x01"),
            hashlib.sha512(b"proto-v1/nonce\x01").digest(),
        )

    def test_tagged_hash_is_not_bip340s_double_tag(self):
        # BIP340 hashes the tag twice to fill SHA-256's 64-byte block. SHA-512
        # has a 128-byte block, so the second copy earns nothing and is dropped.
        # (BIP340 also uses SHA-256 for the tag; we keep one hash function.)
        t = hashlib.sha512(b"proto-v1/nonce").digest()[:32]
        self.assertNotEqual(
            tagged_hash("proto-v1/nonce", b"\x01"),
            hashlib.sha512(t + t + b"\x01").digest(),
        )

    def test_tagged_hash_output_is_64_bytes_and_feeds_from_bytes_wide(self):
        h = tagged_hash("proto-v1/challenge", b"\x00" * 32)
        self.assertEqual(len(h), 64)
        self.assertLess(int(Scalar.from_bytes_wide(h)), L)

    def test_tagged_hash_separates_tags(self):
        self.assertNotEqual(tagged_hash("a", b"x"), tagged_hash("b", b"x"))
        self.assertEqual(tagged_hash("a", b"x"), tagged_hash("a", b"x"))

    def test_tagged_hash_parts_join_like_concatenation(self):
        self.assertEqual(tagged_hash("t", b"ab", b"cd"), tagged_hash("t", b"abcd"))
        self.assertEqual(tagged_hash("t"), tagged_hash("t", b""))

    def test_KNOWN_HAZARD_concatenation_is_not_injective(self):
        """Two variable-length parts collide. The docstring says the caller must
        prevent this; this test exists so nobody discovers it in production."""
        self.assertEqual(tagged_hash("t", b"ab", b"cd"), tagged_hash("t", b"a", b"bcd"))

    def test_a_tag_that_prefixes_another_does_NOT_collide(self):
        """The whole reason the tag is digested rather than prepended.

        Under SHA-512(tag || data) these two are byte-identical inputs. Under
        SHA-512(SHA-512(tag)[:32] || data) they cannot be: the tag always occupies
        exactly 32 bytes, so the data always starts at the same offset.
        """
        self.assertNotEqual(tagged_hash("ab", b"c"), tagged_hash("abc", b""))
        self.assertNotEqual(
            tagged_hash("proto/nonce", b"coef" + b"X"),
            tagged_hash("proto/noncecoef", b"X"),
        )

    def test_hash_sha512(self):
        self.assertEqual(hash_sha512(b"abc"), hashlib.sha512(b"abc").digest())

    def test_byte_helpers_are_little_endian(self):
        self.assertEqual(bytes_from_int(1), le(1))
        self.assertEqual(int_from_bytes(le(258)), 258)

    def test_xor_bytes(self):
        self.assertEqual(xor_bytes(b"\x00" * 32, b"\xff" * 32), b"\xff" * 32)
        with self.assertRaises(AssertionError):
            xor_bytes(b"\x00" * 31, b"\xff" * 31)


class AdditionClosureTests(unittest.TestCase):
    """GE.__add__ skips the curve-equation check on its output, because the
    addition law is closed over the curve. This pins that claim."""

    def test_addition_output_is_always_on_the_curve(self):
        from ed25519lab.ed25519 import _D

        seed(14)
        pts = [Scalar(randint(1, L - 1)) * B for _ in range(6)]
        pts += [GE(), GE(FE(0), FE(-1))]  # neutral and the order-two point
        for a in pts:
            for b in pts:
                c = a + b
                x, y = c.x, c.y
                self.assertEqual(-(x**2) + y**2, 1 + _D * x**2 * y**2)
                # and the public constructor accepts the same coordinates
                GE(x, y)


if __name__ == "__main__":
    unittest.main()
