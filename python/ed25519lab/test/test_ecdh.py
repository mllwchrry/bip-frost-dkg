"""Tests for ECDH share-encryption key derivation."""

import unittest
from random import randint, seed

from ed25519lab.ecdh import ecdh_ed25519
from ed25519lab.ed25519 import GE, B, Scalar
from ed25519lab.keys import pubkey_gen

L = Scalar.SIZE


def le(v: int) -> bytes:
    return v.to_bytes(32, "little")


class EcdhTests(unittest.TestCase):
    def setUp(self):
        seed(40)
        self.sk_a = le(randint(1, L - 1))
        self.sk_b = le(randint(1, L - 1))
        self.pk_a = pubkey_gen(self.sk_a)
        self.pk_b = pubkey_gen(self.sk_b)
        self.ctx = b"session-context"

    def test_both_sides_derive_the_same_pad(self):
        # A sends to B; B receives from A.
        pad_a = ecdh_ed25519(self.sk_a, self.pk_b, self.ctx, sending=True)
        pad_b = ecdh_ed25519(self.sk_b, self.pk_a, self.ctx, sending=False)
        self.assertEqual(pad_a, pad_b)

    def test_the_sending_flag_actually_matters(self):
        # If both sides pass the same flag they derive different pads. This is
        # the silent failure the flag exists to prevent, so it is pinned.
        same = ecdh_ed25519(self.sk_b, self.pk_a, self.ctx, sending=True)
        self.assertNotEqual(ecdh_ed25519(self.sk_a, self.pk_b, self.ctx, sending=True), same)

    def test_pad_is_bound_to_context(self):
        a = ecdh_ed25519(self.sk_a, self.pk_b, b"ctx-1", sending=True)
        b = ecdh_ed25519(self.sk_a, self.pk_b, b"ctx-2", sending=True)
        self.assertNotEqual(a, b)

    def test_pad_is_bound_to_the_pair(self):
        sk_c = le(randint(1, L - 1))
        pk_c = pubkey_gen(sk_c)
        a = ecdh_ed25519(self.sk_a, self.pk_b, self.ctx, sending=True)
        b = ecdh_ed25519(self.sk_a, pk_c, self.ctx, sending=True)
        self.assertNotEqual(a, b)

    def test_pad_is_a_scalar_below_L(self):
        pad = ecdh_ed25519(self.sk_a, self.pk_b, self.ctx, sending=True)
        self.assertIsInstance(pad, Scalar)
        self.assertLess(int(pad), L)

    def test_additive_encryption_roundtrip(self):
        # The ciphertext is share + pad mod L; this is how EncPedPop uses it.
        share = Scalar(randint(1, L - 1))
        pad_send = ecdh_ed25519(self.sk_a, self.pk_b, self.ctx, sending=True)
        pad_recv = ecdh_ed25519(self.sk_b, self.pk_a, self.ctx, sending=False)
        ciphertext = share + pad_send
        self.assertEqual(ciphertext - pad_recv, share)

    def test_homomorphic_summation(self):
        # The coordinator sums ciphertexts; the recipient subtracts the summed
        # pads. This property is what makes that work.
        seed(41)
        senders = [le(randint(1, L - 1)) for _ in range(4)]
        shares = [Scalar(randint(1, L - 1)) for _ in senders]
        cts, pads = [], []
        for sk, sh in zip(senders, shares):
            pk = pubkey_gen(sk)
            cts.append(sh + ecdh_ed25519(sk, self.pk_b, self.ctx, sending=True))
            pads.append(ecdh_ed25519(self.sk_b, pk, self.ctx, sending=False))
        self.assertEqual(Scalar.sum(*cts) - Scalar.sum(*pads), Scalar.sum(*shares))


class EcdhStrictnessTests(unittest.TestCase):
    """The security argument depends on the peer key being strictly decoded."""

    def setUp(self):
        seed(42)
        self.sk = le(randint(1, L - 1))
        self.ctx = b"ctx"

    def test_small_order_peer_key_is_rejected(self):
        from test.test_strictness import SMALL_ORDER

        for name, h in SMALL_ORDER.items():
            if name == "order 1 (neutral)":
                continue
            with self.subTest(point=name), self.assertRaises(ValueError):
                ecdh_ed25519(self.sk, bytes.fromhex(h), self.ctx, sending=True)

    def test_mixed_order_peer_key_is_rejected(self):
        from test.test_strictness import SMALL_ORDER, unchecked_decode

        t = unchecked_decode(SMALL_ORDER["order 8 (a)"])
        peer = (Scalar(randint(1, L - 1)) * B + t).to_bytes()
        with self.assertRaises(ValueError):
            ecdh_ed25519(self.sk, peer, self.ctx, sending=True)

    def test_neutral_peer_key_is_rejected(self):
        # Encode permissively on purpose: we are testing that ecdh_ed25519
        # rejects the identity, not that to_bytes does.
        with self.assertRaises(ValueError):
            ecdh_ed25519(self.sk, GE().to_bytes_with_identity(), self.ctx, sending=True)

    def test_non_canonical_peer_key_is_rejected(self):
        from ed25519lab.ed25519 import FE

        with self.assertRaises(ValueError):
            ecdh_ed25519(self.sk, FE.SIZE.to_bytes(32, "little"), self.ctx, sending=True)

    def test_bad_secret_keys_are_rejected(self):
        pk = pubkey_gen(le(7))
        for bad in (le(0), le(L), b"\x01" * 31):
            with self.subTest(sk=bad.hex()[:8]), self.assertRaises(ValueError):
                ecdh_ed25519(bad, pk, self.ctx, sending=True)


if __name__ == "__main__":
    unittest.main()
