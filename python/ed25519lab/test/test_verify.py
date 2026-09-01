"""Tests for standard Ed25519 verification of the fork's final output."""

import hashlib
import unittest
from random import randint, seed

from ed25519lab.ed25519 import FE, GE, B, Scalar
from ed25519lab.verify import ed25519_verify
from test.test_strictness import RFC_8032_7_1, SMALL_ORDER, unchecked_decode

L = Scalar.SIZE


def le(v: int) -> bytes:
    return v.to_bytes(32, "little")


def sign_standard(msg: bytes, d: Scalar, k: Scalar) -> tuple[bytes, bytes]:
    """Produce a standard Ed25519 signature from a raw scalar and nonce.

    Test-only. The library ships no standard signer on purpose: the fork's only
    standard signature is the aggregated FROST one, and a single-party signer
    here would be an invitation to misuse.
    """
    a = d * B
    r = k * B
    pubkey = a.to_bytes()
    r_enc = r.to_bytes()
    e = Scalar.from_bytes_wide(hashlib.sha512(r_enc + pubkey + msg).digest())
    return pubkey, r_enc + (k + e * d).to_bytes()


class RFC8032KnownAnswerTests(unittest.TestCase):
    """The vectors are real Ed25519 signatures produced by an implementation we
    did not write, over messages we did not choose. If the verifier is wrong in
    any way that matters, these fail."""

    def test_rfc_8032_7_1_signatures_verify(self):
        checked = 0
        for msg_hex, pk, sig in RFC_8032_7_1:
            if msg_hex is None:  # the 1023-byte vector, message not carried
                continue
            checked += 1
            with self.subTest(msg=msg_hex or "(empty)"):
                self.assertTrue(
                    ed25519_verify(bytes.fromhex(msg_hex), bytes.fromhex(pk), bytes.fromhex(sig))
                )
        self.assertEqual(checked, 3)

    def test_rfc_vectors_fail_under_a_different_message(self):
        for msg_hex, pk, sig in RFC_8032_7_1:
            if msg_hex is None:
                continue
            with self.subTest(msg=msg_hex or "(empty)"):
                self.assertFalse(
                    ed25519_verify(b"wrong", bytes.fromhex(pk), bytes.fromhex(sig))
                )


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        seed(50)
        self.d = Scalar(randint(1, L - 1))
        self.msg = b"aggregate signature payload"
        self.pk, self.sig = sign_standard(self.msg, self.d, Scalar(randint(1, L - 1)))

    def test_valid_signature_verifies(self):
        self.assertTrue(ed25519_verify(self.msg, self.pk, self.sig))

    def test_tampering_fails(self):
        for i in (0, 31, 32, 63):
            tampered = bytearray(self.sig)
            tampered[i] ^= 0x01
            with self.subTest(byte=i):
                self.assertFalse(ed25519_verify(self.msg, self.pk, bytes(tampered)))

    def test_wrong_key_fails(self):
        other = (Scalar(randint(1, L - 1)) * B).to_bytes()
        self.assertFalse(ed25519_verify(self.msg, other, self.sig))

    def test_malformed_lengths_return_false_rather_than_raising(self):
        for bad_sig in (b"", self.sig[:63], self.sig + b"\x00"):
            with self.subTest(n=len(bad_sig)):
                self.assertFalse(ed25519_verify(self.msg, self.pk, bad_sig))
        for bad_pk in (b"", self.pk[:31], self.pk + b"\x00"):
            with self.subTest(n=len(bad_pk)):
                self.assertFalse(ed25519_verify(self.msg, bad_pk, self.sig))


class StrictnessTests(unittest.TestCase):
    def setUp(self):
        seed(51)
        self.d = Scalar(randint(1, L - 1))
        self.msg = b"m"
        self.pk, self.sig = sign_standard(self.msg, self.d, Scalar(randint(1, L - 1)))

    def test_s_at_or_above_L_is_rejected_not_reduced(self):
        # Malleability: s and s + L would otherwise both verify.
        s = Scalar.from_bytes_checked(self.sig[32:])
        self.assertFalse(ed25519_verify(self.msg, self.pk, self.sig[:32] + le(L)))
        self.assertFalse(
            ed25519_verify(self.msg, self.pk, self.sig[:32] + (int(s) + L).to_bytes(32, "little"))
        )

    def test_non_canonical_R_or_A_is_rejected(self):
        non_canonical = FE.SIZE.to_bytes(32, "little")  # y = p
        self.assertFalse(ed25519_verify(self.msg, self.pk, non_canonical + self.sig[32:]))
        self.assertFalse(ed25519_verify(self.msg, non_canonical, self.sig))

    def test_small_order_R_or_A_is_rejected(self):
        for name, h in SMALL_ORDER.items():
            enc = bytes.fromhex(h)
            with self.subTest(point=name):
                # Includes the neutral element: dalek's is_small_order() is true
                # for all eight torsion points, and so is our policy.
                self.assertFalse(ed25519_verify(self.msg, self.pk, enc + self.sig[32:]))
                self.assertFalse(ed25519_verify(self.msg, enc, self.sig))

    def test_neutral_element_is_rejected_explicitly(self):
        neutral = GE().to_bytes_with_identity()
        # Refused by the strict decoder itself, not by a separate check.
        with self.assertRaises(ValueError):
            GE.from_bytes(neutral)
        self.assertTrue(GE.from_bytes_with_identity(neutral).is_identity)
        self.assertFalse(ed25519_verify(self.msg, neutral, self.sig))
        self.assertFalse(ed25519_verify(self.msg, self.pk, neutral + self.sig[32:]))


def forge_mixed_order_pubkey():
    """Build a signature that satisfies the cofactorless equation under a
    MIXED-order public key, A = [a]B + T.

    Grinds the nonce until the challenge is divisible by the torsion order, at
    which point [e]T vanishes and an ordinary signature over [a]B satisfies the
    equation for the torsioned key too. Expected cost: about eight candidates.

    Returns (msg, pubkey, sig, a, t, r, e). Shared with test_crosscheck, which
    checks what an independent implementation makes of the same bytes.
    """
    a = Scalar(0x1234567)
    t = unchecked_decode(SMALL_ORDER["order 8 (a)"])
    pk_mixed = (a * B + t).to_bytes()
    msg = b"grind"
    for k_int in range(1, 500):
        k = Scalar(k_int)
        r = k * B
        r_enc = r.to_bytes()
        e = Scalar.from_bytes_wide(hashlib.sha512(r_enc + pk_mixed + msg).digest())
        if int(e) % 8 == 0:
            return msg, pk_mixed, r_enc + (k + e * a).to_bytes(), a, t, r, e
    raise AssertionError("no challenge divisible by 8 found")


class KnownDivergenceFromDalekTests(unittest.TestCase):
    """We are STRICTER than dalek verify_strict, in one reachable way.

    dalek rejects SMALL-order A and R and then checks the equation. It does not
    reject MIXED-order points, A = [a]B + T, so a signature with such an A is
    accepted whenever the equation holds -- and it holds whenever the challenge
    is divisible by the order of the torsion component, which an attacker
    reaches by grinding roughly eight candidates.

    Our decoder rejects mixed-order points at parse time, so we say no.

    That is the fork's decode policy working as designed, but it means
    ed25519_verify answers "valid under our rules", not "would Solana accept".
    Pinning it here keeps the distinction from quietly eroding.
    """

    def test_the_group_equation_holds_but_we_reject_at_parse_time(self):
        msg, pk_mixed, sig, a, t, r, e = forge_mixed_order_pubkey()
        big_a = a * B + t

        # The forged key really is mixed order: not in the prime-order subgroup,
        # and not small order either, so dalek's own filter does not catch it.
        self.assertFalse(big_a.in_prime_order_subgroup())
        self.assertFalse((8 * big_a).is_identity)

        # The cofactorless equation nevertheless holds.
        s = Scalar.from_bytes_checked(sig[32:])
        self.assertEqual(s * B, r + e * big_a)

        # And we still say no, because A never survives decoding.
        self.assertFalse(ed25519_verify(msg, pk_mixed, sig))
        with self.assertRaises(ValueError):
            GE.from_bytes(pk_mixed)


if __name__ == "__main__":
    unittest.main()
