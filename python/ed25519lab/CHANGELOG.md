# Changelog

## Unreleased

Initial curve and scalar layer.

* `FE`, `Scalar`, `GE`, `B` in `ed25519lab.ed25519`.
* `GE.from_bytes` does RFC 8032 section 5.1.3 decoding plus a
  prime-order-subgroup check, rejecting non-canonical encodings, small-order
  points and mixed-order points.
* `Scalar.from_bytes_wide` replaces secp256k1lab's `Scalar.from_bytes_wrapping`,
  takes exactly 64 bytes, and is the only supported way to turn a hash output
  into a scalar.
* `pubkey_gen` uses raw scalars: no seed, no clamping.
* `tagged_hash(tag, *parts)` is `SHA-512(SHA-512(tag)[:32] || parts...)`. Digesting
  the tag to a fixed 32 bytes makes tag-prefix collisions impossible by
  construction: with a plain `SHA-512(tag || data)` prefix, `"p/nonce"` with
  data `"coef..."` and `"p/noncecoef"` with data `"..."` hash identical inputs,
  and nothing but manual vigilance catches it. This is BIP340's approach with the widths
  adjusted: BIP340 hashes the tag twice to fill SHA-256's 64-byte block, which
  SHA-512's 128-byte block makes pointless, and it digests the tag with SHA-256
  where this library uses SHA-512 so that only one hash function is needed
  anywhere. The caller's remaining obligation is unchanged: at most one part may
  be variable-length and it must be last.
* `GE.from_bytes` now REJECTS the identity, and
  `GE.from_bytes_with_identity` is the variant that accepts it, for
  the call sites where the identity is a real protocol value -- an aggregate
  nonce whose contributions cancel, a sum of VSS commitments. This reverses the
  earlier "delete the variant, check `.is_identity` per call site" design. The
  failure modes are not symmetric: a forgotten `.is_identity` check accepts a value
  that should have been refused and does so SILENTLY, while a forgotten
  `_with_identity` raises at the one site that needed it. Strict by default puts
  the quiet mistake out of reach.

* `internal_sign` / `internal_verify` in `ed25519lab.internal_sig`, replacing
  secp256k1lab's `schnorr_sign` / `schnorr_verify`. The domain tag is prepended
  to the challenge input, before R and the public key, so an internal signature
  is structurally unverifiable as an ordinary Ed25519 signature. The nonce is
  derived deterministically from the raw secret scalar, since the protocol has
  no seeds. `aux` is fixed at 32 bytes -- see below.
* `ecdh_ed25519` in `ed25519lab.ecdh`, replacing `ecdh_libsecp256k1`. The peer
  key goes through strict decoding, which is what closes the small-subgroup
  attack that would otherwise leak `deckey mod 8`. The raw shared point is never
  key material: it is hashed together with both public keys and the context.

Deviation from the spec, deliberate: the spec writes the nonce input as
`tag || d_le || aux || m` with both `aux` and `m` variable-length. Plain
concatenation is not injective, so two different (aux, m) pairs can yield the
same nonce, and two signatures sharing R with different challenges disclose the
secret key. `aux` is therefore required to be exactly 32 bytes, making `m`
unambiguously the tail. The spec should be updated to match.

* `ed25519_verify` in `ed25519lab.verify`: standard, cofactorless Ed25519
  verification for the fork's final aggregate signature. The API mapping table
  has no row for this function; it should, since pitfall 3 requires "our
  verifier" to be the cofactorless form. Verified against the RFC 8032 section
  7.1 vectors and against signatures produced by libsodium.

Known divergence, deliberate and pinned by tests: `ed25519_verify` is STRICTER
than dalek `verify_strict`. dalek rejects only small-order A and R, so a
mixed-order public key `A = [a]B + T` reaches the group equation, which an
attacker can satisfy by grinding until the challenge is divisible by the torsion
order -- about eight candidates. We reject such a key at parse time. libsodium's
`crypto_sign_open` accepts the constructed signature; we do not. This function
therefore answers "valid under our rules", not "would Solana accept"; the second
question needs solders / dalek.

* `FastGEMul` / `FAST_B`: a precomputed table of multiples of the generator,
  used automatically by `k * B`. This was the one function present in
  secp256k1lab that had been left out by accident rather than on purpose.
  Measured: `k*B` 3.6x faster, `pubkey_gen` 3.2x, signing and verification and
  ECDH 1.2-1.5x, and the test suite 11.6 s -> 7.6 s. Strict decoding does NOT
  get faster: its cost is the `[L]P` subgroup check on an arbitrary point, where
  no table applies. Import of `ed25519.py` goes from 1.5 ms to 8.6 ms, once.
  Having two scalar-multiplication paths is the cost; the equivalence against
  `_mul_int` is pinned by tests over random and edge-case scalars.

* The generator is exported as `B`, not `G` as in secp256k1lab, and the
  precomputed table as `FAST_B`. This follows RFC 8032 notation and the spec,
  which is written in `B` throughout and states the rename itself ("the fallback
  substitute is R = B (previously G)"). It also removes a mismatch that had crept
  in: the docstrings already wrote equations as `[s]B == R + [e]A` while the code
  said `G`. The API mapping table has no row for the generator; it should.

* Wycheproof's Ed25519 corpus (151 cases) is vendored under `test/vectors/` and
  run against `ed25519_verify`. All 151 pass with no exceptions. The file's
  SHA-256 and case count are pinned, and a test asserts that it still contains
  no small-order or mixed-order cases -- the property that makes "zero
  exceptions" the correct expectation rather than a coincidence.

All rows of the spec's API mapping table are now implemented.
