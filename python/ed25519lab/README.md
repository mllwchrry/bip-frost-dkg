ed25519lab
==========

![Dependencies: None](https://img.shields.io/badge/dependencies-none-success)

An INSECURE implementation of the Ed25519 curve and related cryptographic
schemes written in Python, intended for prototyping, experimentation and
education.

It is a sibling of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab),
built to support a port of FROST threshold signing and ChillDKG from BIP-340 /
secp256k1 to Ed25519 with Solana-compatible signatures. Class and method names
are kept identical to secp256k1lab wherever the role of a function is unchanged,
so that call sites in the reference implementations stay comparable against
upstream.

Features:
* Low-level Ed25519 field, scalar and group arithmetic.
* Strict point decoding: RFC 8032 section 5.1.3 plus a prime-order-subgroup
  check.
* Raw-scalar key generation (no seeds, no clamping).
* The internal PoP / CertEq signature scheme (`internal_sign`,
  `internal_verify`), deliberately not verifiable as an ordinary Ed25519
  signature.
* ECDH key derivation for encrypted share transport (`ecdh_ed25519`).
* Standard cofactorless Ed25519 verification (`ed25519_verify`) for the final
  aggregate signature.

WARNING: The code in this library is slow and trivially vulnerable to side
channel attacks.

Differences from a standard Ed25519 library
-------------------------------------------

These are deliberate and are what the library exists for.

* **Strict decoding.** `GE.from_bytes` rejects non-canonical
  encodings (`y >= p`, and `x == 0` with the sign bit set), all seven
  non-neutral small-order points, and all mixed-order points `[k]B + T`. Every
  standard library accepts most of these.
* **No cofactor anywhere in the arithmetic.** `ed25519_verify` uses the
  cofactorless `[s]B = R + [e]A`, which is what Solana enforces, not the
  cofactored `[8][s]B = [8]R + [8][e]A` that RFC 8032 gives as its primary form
  and implements in its own appendix code. Note that `ed25519_verify` is
  stricter than dalek `verify_strict` on mixed-order keys, so it answers "valid
  under our rules" rather than "would Solana accept" -- see its docstring.
* **Raw scalars.** Secret keys are uniform scalars mod L, little-endian. There
  is no seed, no SHA-512 expansion, no clamping and no nonce prefix, because the
  protocol needs unclamped scalar signing and keeping one key type avoids
  maintaining two signing constructions.
* **`Scalar.from_bytes_wide` instead of `from_bytes_wrapping`.** It takes
  exactly 64 bytes and raises otherwise. On secp256k1 a random 256-bit hash is
  almost always a valid scalar; on Ed25519 `L ~ 2**252`, so it is valid only
  about 1 time in 16. Reducing a hash the wrong way therefore fails late and
  intermittently. The distinct name plus the length check make it fail
  immediately, at the call site.
* **`tagged_hash` digests the tag.** `SHA-512(SHA-512(tag)[:32] || parts...)`. The
  obvious alternative, a plain `SHA-512(tag || data)` prefix, lets one tag be a
  prefix of another and then the two domains collide outright -- `"p/nonce"`
  with data `"coef..."` is byte-identical to `"p/noncecoef"` with data `"..."`.
  A fixed-width tag makes that impossible rather than merely unlikely. Two
  deliberate departures from BIP340: it hashes the tag twice to fill SHA-256's
  64-byte block, which SHA-512's 128-byte block makes pointless, and it digests
  the tag with SHA-256 where this library uses SHA-512 so that only one hash
  function is needed anywhere. The 64-byte output feeds
  `Scalar.from_bytes_wide` with no length adapter. One caller obligation
  remains: at most one part may be variable-length, and it must be last.
* **The generator is named `B`, not `G`.** This is the one place the library
  deviates from the "keep the upstream name" policy, and it does so to follow
  the document it implements: the spec is written in RFC 8032 notation
  throughout (`R = [k]B`, `hostpubkey = [hostseckey]B`) and states the rename
  explicitly -- "the fallback substitute is R = B (previously G)". Note that
  FROST's binding factor is a lowercase `b`, so expressions like
  `[s]B = R1 + [b]R2` mix the two; that is inherited from the FROST literature,
  not a typo.
* **The identity is an ordinary point, and the decoder is strict by default.**
  `GE()` is `(0, 1)` and encodes as `0x01` followed by 31 zero bytes -- no
  sentinel. `GE.from_bytes` refuses it, because most wire values
  (public keys, public shares, individual public nonces) can never legitimately
  be the identity. Where it IS a real value -- an aggregate nonce whose
  contributions cancel, a sum of VSS commitments -- use
  `GE.from_bytes_with_identity`, which is the same decoder minus that
  one rejection. Strict by default because the mistakes are asymmetric: a
  forgotten `.is_identity` check fails silently, a forgotten `_with_identity`
  raises.

Endianness
----------

All byte input and output in this library is little-endian, by definition of
Ed25519. It is not encoded in any method name. Identifiers, lengths and counts
that go inside hash inputs are big-endian; that mixing is intentional and is the
caller's responsibility.

Testing
-------

No installation needed -- `test/__init__.py` puts `src/` on the path, so a fresh
clone runs as is.

    python3 -m unittest                            # all 119
    python3 -m unittest test.test_strictness -v    # one module, verbose

`test_ed25519.py` covers arithmetic and constructors, `test_strictness.py`
covers everything that must be rejected, `test_internal_sig.py`, `test_ecdh.py`
and `test_verify.py` cover the protocol layer, and `test_crosscheck.py` compares
every primitive against libsodium through PyNaCl (>= 1.6.2 -- CVE-2025-69277
affects exactly the subgroup predicate used here as an oracle).

The cross-check module skips if PyNaCl is absent, so that the library itself can
stay dependency-free. Those are the only tests that check the implementation
against something we did not write, so a silent skip is dangerous in CI: set

    ED25519LAB_REQUIRE_CROSSCHECK=1 python3 -m unittest

to turn the skip into a hard failure. CI sets it.

`test_wycheproof.py` runs Google's Wycheproof Ed25519 corpus -- 151 cases of
malformed, truncated and malleable signatures, vendored verbatim under
`test/vectors/` with its SHA-256 pinned. It is parser breadth, not policy: the
file contains no small-order or mixed-order cases, so it cannot distinguish a
permissive verifier from a strict one, and there are consequently zero
exceptions and no allow-list.

RFC 8032 section 7.1 vectors serve two purposes: every public key and every
signature R must survive strict decoding, and the signatures themselves must
verify under `ed25519_verify`. Note that RFC 8032 key GENERATION is not
reproduced -- it clamps a hashed seed and this library signs with raw scalars,
so only the verification side has common ground.

Timing
------

    python3 bench.py            # all primitives
    python3 bench.py decode     # filter by substring or group name

`k * B` takes a precomputed-table path (`FAST_B`), which makes base-point
multiplication about 3.6x faster and `pubkey_gen` about 3.2x. Signing,
verification and ECDH gain 1.2-1.5x, because they mix base-point and
arbitrary-point multiplications. Strict decoding gains nothing: its cost is
almost entirely the `[L]P` subgroup check on an arbitrary point, for which no
table can exist. Optimise there, or nowhere.

Linting
-------

    uvx ruff@0.16.3 check .
    uvx mypy@2.3.1 .

The versions are pinned in CI on purpose: `uvx ruff` with no version resolves to
the latest release, so a ruff upgrade can turn CI red on a day nobody touched
the code. Bump them deliberately.

Documentation
-------------

`WALKTHROUGH.md` explains every function, why it is written the way it is, what
the tests cover, and what is still missing.
