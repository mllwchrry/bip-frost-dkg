"""Tests for the internal PoP / CertEq signature scheme."""

import hashlib
import unittest
from random import randint, seed

from ed25519lab.ecdh import TAG_ECDH
from ed25519lab.ed25519 import GE, B, Scalar
from ed25519lab.internal_sig import (
    NO_AUX,
    TAG_CHALLENGE,
    TAG_NONCE,
    internal_sign,
    internal_verify,
)
from ed25519lab.keys import pubkey_gen
from ed25519lab.util import tagged_hash

L = Scalar.SIZE


def le(v: int) -> bytes:
    return v.to_bytes(32, "little")


class SignVerifyTests(unittest.TestCase):
    def setUp(self):
        seed(30)
        self.sk = le(randint(1, L - 1))
        self.pk = pubkey_gen(self.sk)

    def test_roundtrip(self):
        for msg in (b"", b"\x00" * 4, b"hello", bytes(range(256))):
            with self.subTest(len=len(msg)):
                sig = internal_sign(msg, self.sk)
                self.assertEqual(len(sig), 64)
                self.assertTrue(internal_verify(msg, self.pk, sig))

    def test_pop_message_shape(self):
        # The PoP message stays bytes(4, participant_index).
        for i in range(5):
            msg = i.to_bytes(4, "big")
            self.assertTrue(internal_verify(msg, self.pk, internal_sign(msg, self.sk)))

    def test_deterministic_without_aux(self):
        m = b"same message"
        self.assertEqual(internal_sign(m, self.sk), internal_sign(m, self.sk))

    def test_aux_changes_the_nonce(self):
        m = b"same message"
        a = internal_sign(m, self.sk, NO_AUX)
        b = internal_sign(m, self.sk, b"\x01" * 32)
        self.assertNotEqual(a[:32], b[:32])  # different R
        self.assertTrue(internal_verify(m, self.pk, a))
        self.assertTrue(internal_verify(m, self.pk, b))

    def test_aux_must_be_32_bytes(self):
        # Not a style rule: variable-width aux makes the nonce input ambiguous
        # and leaks the key. See the docstring.
        for bad in (b"", b"\x01", b"\x01" * 31, b"\x01" * 33):
            with self.subTest(n=len(bad)), self.assertRaises(ValueError):
                internal_sign(b"m", self.sk, bad)

    def test_rejects_bad_secret_keys(self):
        for bad in (le(0), le(L), b"\x01" * 31):
            with self.subTest(sk=bad.hex()[:8]), self.assertRaises(ValueError):
                internal_sign(b"m", bad)

    def test_wrong_message_key_or_signature_fails(self):
        msg = b"authentic"
        sig = internal_sign(msg, self.sk)
        other = pubkey_gen(le(randint(1, L - 1)))
        self.assertFalse(internal_verify(b"forged", self.pk, sig))
        self.assertFalse(internal_verify(msg, other, sig))
        for i in (0, 31, 32, 63):
            tampered = bytearray(sig)
            tampered[i] ^= 0x01
            with self.subTest(byte=i):
                self.assertFalse(internal_verify(msg, self.pk, bytes(tampered)))

    def test_malformed_inputs(self):
        sig = internal_sign(b"m", self.sk)
        with self.assertRaises(ValueError):
            internal_verify(b"m", self.pk[:31], sig)
        with self.assertRaises(ValueError):
            internal_verify(b"m", self.pk, sig[:63])
        # s >= L must be rejected, not reduced
        self.assertFalse(internal_verify(b"m", self.pk, sig[:32] + le(L)))
        # a non-canonical R must be rejected
        self.assertFalse(internal_verify(b"m", self.pk, le(2**255 - 19) + sig[32:]))

    def test_identity_is_rejected_at_this_call_site(self):
        neutral = GE().to_bytes_with_identity()
        sig = internal_sign(b"m", self.sk)
        self.assertFalse(internal_verify(b"m", neutral, sig))
        self.assertFalse(internal_verify(b"m", self.pk, neutral + sig[32:]))

    def test_torsioned_R_is_rejected(self):
        from test.test_strictness import SMALL_ORDER, unchecked_decode

        msg = b"m"
        sig = internal_sign(msg, self.sk)
        r = GE.from_bytes(sig[:32])
        t = unchecked_decode(SMALL_ORDER["order 8 (a)"])
        self.assertFalse(internal_verify(msg, self.pk, (r + t).to_bytes() + sig[32:]))


class NotAnEd25519SignatureTests(unittest.TestCase):
    """The central design claim of the scheme: an internal signature is
    structurally unverifiable outside the protocol, because the domain tag is
    prepended to the challenge input BEFORE R and the public key."""

    def setUp(self):
        seed(31)
        self.sk = le(randint(1, L - 1))
        self.pk = pubkey_gen(self.sk)
        self.msg = b"payload"
        self.sig = internal_sign(self.msg, self.sk)

    def _standard_ed25519_equation_holds(self, msg: bytes) -> bool:
        """[s]B == R + [e]A with the STANDARD challenge, no domain tag."""
        r = GE.from_bytes(self.sig[:32])
        a = GE.from_bytes(self.pk)
        s = Scalar.from_bytes_checked(self.sig[32:])
        e = Scalar.from_bytes_wide(hashlib.sha512(self.sig[:32] + self.pk + msg).digest())
        return s * B == r + e * a

    def test_does_not_verify_as_standard_ed25519(self):
        self.assertFalse(self._standard_ed25519_equation_holds(self.msg))

    def test_does_not_verify_over_the_tag_prefixed_message(self):
        # This is the case that WOULD have worked had the tag been placed after
        # R || A, on the message only. It must not.
        self.assertFalse(
            self._standard_ed25519_equation_holds(TAG_CHALLENGE.encode() + self.msg)
        )

    def test_our_challenge_differs_from_the_standard_one(self):
        standard = hashlib.sha512(self.sig[:32] + self.pk + self.msg).digest()
        ours = hashlib.sha512(TAG_CHALLENGE.encode() + self.sig[:32] + self.pk + self.msg).digest()
        self.assertNotEqual(standard, ours)


class TagSeparationTests(unittest.TestCase):
    """Tag separation is structural, not a caller obligation.

    tagged_hash digests the tag to a fixed 32 bytes, so one tag being a prefix
    of another cannot collide the domains.

    Two different jobs. The adversarial-shape test constructs a prefixing pair
    itself and so actually exercises the property today; swapping the
    construction back to a plain prefix fails it. The real-tag test is a forward
    guard: no current tag prefixes another, so its prefix branch is dormant and
    it would pass under either construction -- it starts biting the day someone
    adds a tag like "<existing>coef".
    """

    TAGS = (TAG_NONCE, TAG_CHALLENGE, TAG_ECDH)

    def test_tags_are_distinct(self):
        self.assertEqual(len(self.TAGS), len(set(self.TAGS)))

    def test_real_tags_never_collide_whatever_the_data(self):
        for a in self.TAGS:
            for b in self.TAGS:
                if a is b:
                    continue
                with self.subTest(a=a, b=b):
                    # If b == a + suffix, a plain-prefix construction would make
                    # these two calls byte-identical. Here they must not be.
                    suffix = b[len(a) :].encode() if b.startswith(a) else b"\x00"
                    self.assertNotEqual(
                        tagged_hash(a, suffix + b"payload"),
                        tagged_hash(b, b"payload"),
                    )

    def test_a_prefixing_tag_pair_is_harmless_by_construction(self):
        # The exact shape found in the FROST reference: "/nonce" is a prefix of
        # "/noncecoef". Under SHA-512(tag || data) these collide outright.
        self.assertNotEqual(
            tagged_hash("p/nonce", b"coef" + b"D"),
            tagged_hash("p/noncecoef", b"D"),
        )
        self.assertNotEqual(tagged_hash("ab", b"c"), tagged_hash("abc", b""))
        self.assertNotEqual(tagged_hash("", b"x"), tagged_hash("x", b""))


if __name__ == "__main__":
    unittest.main()
