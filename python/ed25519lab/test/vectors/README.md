Vendored test vectors
=====================

Third-party vector files, committed verbatim so that the test suite is
deterministic and runs offline. Each file's provenance and SHA-256 are asserted
by the test that consumes it, so updating one is a deliberate act rather than
something that can drift in silently.

ed25519_test.json
-----------------

* Source: <https://github.com/C2SP/wycheproof>, `testvectors_v1/ed25519_test.json`
* Commit: `dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166` (2026-08-18)
* SHA-256: `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`
* License: Apache License 2.0, © Google LLC and the Wycheproof authors
* Consumed by: `test/test_wycheproof.py`

151 signature-verification cases: malformed and truncated encodings, signature
malleability (`s >= L`), garbage appended or prepended, and a body of honest
signatures that must verify.

What it does NOT contain: any small-order, mixed-order, torsion, cofactor or
subgroup case -- verified by searching the file for those terms, which return
zero hits. Wycheproof therefore cannot distinguish a permissive verifier from a
strict one, and says nothing about the decode policy that this library exists
for. It is parser and malleability coverage, and complements the strictness
tests rather than replacing them.

To update: re-copy the file from upstream, then update the commit and SHA-256
here and the SHA-256 constant in `test/test_wycheproof.py`. If the update
introduces cases this library legitimately rejects but Wycheproof marks valid,
that is a finding, not a test to relax -- see the note in that file.
