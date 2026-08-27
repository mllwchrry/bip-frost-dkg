"""Run the Wycheproof Ed25519 verification vectors against ed25519_verify.

The vector file is vendored verbatim under test/vectors/; see the README there
for provenance and licence. It is Google's corpus of malformed, truncated and
malleable signatures -- 151 cases, 88 of which must verify and 63 of which must
not.

WHAT THIS COVERS, AND WHAT IT DOES NOT

It is breadth on the PARSER: encodings with a byte prepended or removed, s >= L
malleability, garbage after the signature, truncated inputs, and a large body of
honest signatures produced by an implementation we did not write.

It says nothing about the decode policy this library exists for. The file
contains zero small-order, mixed-order, torsion, cofactor or subgroup cases, so
it cannot tell a permissive verifier from a strict one. Every one of these
vectors would pass under a far looser policy than ours.

That has a useful consequence: because our extra strictness is orthogonal to
everything Wycheproof tests, the expected result is ZERO exceptions. There is no
allow-list here and there should never need to be one. If a future update of the
file produces a case that Wycheproof marks valid and we reject, that is either a
real bug in this library or a genuine new divergence worth documenting -- it is
not an entry to add to a skip list.
"""

import hashlib
import json
import unittest
from pathlib import Path

from ed25519lab.verify import ed25519_verify

VECTORS = Path(__file__).parent / "vectors" / "ed25519_test.json"

# Pinned so that a silently swapped or truncated file fails loudly. Updating the
# vectors means updating this constant on purpose; see vectors/README.md.
EXPECTED_SHA256 = "752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536"
EXPECTED_CASES = 151


def load_cases():
    data = json.loads(VECTORS.read_text())
    for group in data["testGroups"]:
        pk = bytes.fromhex(group["publicKey"]["pk"])
        for t in group["tests"]:
            yield t, pk


class ProvenanceTests(unittest.TestCase):
    def test_vector_file_is_the_pinned_one(self):
        digest = hashlib.sha256(VECTORS.read_bytes()).hexdigest()
        self.assertEqual(
            digest,
            EXPECTED_SHA256,
            "vendored Wycheproof vectors do not match the pinned digest; "
            "if this was an intentional update, refresh EXPECTED_SHA256 and "
            "test/vectors/README.md together",
        )

    def test_case_count(self):
        self.assertEqual(len(list(load_cases())), EXPECTED_CASES)

    def test_the_file_really_has_no_subgroup_cases(self):
        """The claim that Wycheproof cannot test our strictness, made checkable.

        If a future update adds small-order or torsion cases, this fails and the
        module docstring above needs rewriting -- the file would then overlap
        with test_strictness.py and the "zero exceptions" expectation could
        legitimately break.
        """
        haystack = VECTORS.read_text().lower()
        for term in ("small order", "small-order", "mixed order", "mixed-order",
                     "torsion", "cofactor", "subgroup"):
            with self.subTest(term=term):
                self.assertNotIn(term, haystack)


class WycheproofVerificationTests(unittest.TestCase):
    def test_every_case_matches_the_expected_verdict(self):
        checked = 0
        for t, pk in load_cases():
            expected = t["result"] == "valid"
            got = ed25519_verify(bytes.fromhex(t["msg"]), pk, bytes.fromhex(t["sig"]))
            checked += 1
            with self.subTest(tcId=t["tcId"], comment=t["comment"][:60]):
                self.assertEqual(
                    got,
                    expected,
                    f"tcId {t['tcId']} ({t['comment']}) flags={t.get('flags')}: "
                    f"expected {'accept' if expected else 'reject'}",
                )
        self.assertEqual(checked, EXPECTED_CASES)

    def test_both_verdicts_are_actually_exercised(self):
        """A file of all-valid or all-invalid cases would pass vacuously against
        a broken verifier that always returns the same answer."""
        results = [t["result"] for t, _ in load_cases()]
        self.assertGreater(results.count("valid"), 50)
        self.assertGreater(results.count("invalid"), 50)
        self.assertEqual(set(results), {"valid", "invalid"})

    def test_malleability_cases_are_present_and_rejected(self):
        """s >= L is the one Wycheproof class that overlaps our own strictness."""
        found = 0
        for t, pk in load_cases():
            if "SignatureMalleability" in t.get("flags", []):
                found += 1
                with self.subTest(tcId=t["tcId"]):
                    self.assertEqual(t["result"], "invalid")
                    self.assertFalse(
                        ed25519_verify(bytes.fromhex(t["msg"]), pk, bytes.fromhex(t["sig"]))
                    )
        self.assertGreater(found, 0)


if __name__ == "__main__":
    unittest.main()
