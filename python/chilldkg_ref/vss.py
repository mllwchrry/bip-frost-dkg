from __future__ import annotations

from ed25519lab.ed25519 import GE, B, Scalar

from .util import tagged_hash_bip_dkg


class Polynomial:
    # A scalar polynomial.
    #
    # A polynomial f of degree at most t - 1 is represented by a list `coeffs`
    # of t coefficients, i.e., f(x) = coeffs[0] + ... + coeffs[t-1] *
    # x^(t-1)."""
    coeffs: list[Scalar]

    def __init__(self, coeffs: list[Scalar]) -> None:
        self.coeffs = coeffs

    def eval(self, x: Scalar) -> Scalar:
        # Evaluate a polynomial at position x.

        value = Scalar(0)
        # Reverse coefficients to compute evaluation via Horner's method
        for coeff in self.coeffs[::-1]:
            value = value * x + coeff
        return value

    def __call__(self, x: Scalar) -> Scalar:
        return self.eval(x)


class VSSCommitment:
    # Identity GEs are allowed in VSSCommitment to avoid that a participant can
    # force the sum of valid commitments to be invalid.
    ges: list[GE]

    @staticmethod
    def len_bytes(*, t: int) -> int:
        return 32 * t

    @staticmethod
    def from_bytes(b: bytes, *, t: int) -> VSSCommitment:
        if len(b) != VSSCommitment.len_bytes(t=t):
            raise ValueError
        ges = [GE.from_bytes_with_identity(b[i : i + 32]) for i in range(0, 32 * t, 32)]
        return VSSCommitment(ges)

    def __init__(self, ges: list[GE]) -> None:
        self.ges = ges

    def to_bytes(self) -> bytes:
        # Return commitments to the coefficients of f.
        return b"".join([ge.to_bytes_with_identity() for ge in self.ges])

    def t(self) -> int:
        return len(self.ges)

    def pubshare(self, i: int) -> GE:
        pubshare: GE = GE.batch_mul(
            *(((i + 1) ** j, self.ges[j]) for j in range(len(self.ges)))
        )
        return pubshare

    @staticmethod
    def verify_secshare(secshare: Scalar, pubshare: GE) -> bool:
        # The caller needs to provide the correct pubshare(i)
        actual = secshare * B
        valid: bool = actual == pubshare
        return valid

    def __add__(self, other: VSSCommitment) -> VSSCommitment:
        assert self.t() == other.t()
        return VSSCommitment([self.ges[i] + other.ges[i] for i in range(self.t())])

    def commitment_to_secret(self) -> GE:
        return self.ges[0]

    def commitment_to_nonconst_terms(self) -> list[GE]:
        return self.ges[1 : self.t()]


class VSS:
    f: Polynomial

    def __init__(self, f: Polynomial) -> None:
        self.f = f

    @staticmethod
    def generate(seed: bytes, t: int) -> VSS:
        coeffs = [
            Scalar.from_bytes_wide(
                tagged_hash_bip_dkg("vss coeffs", seed + i.to_bytes(4, byteorder="big"))
            )
            for i in range(t)
        ]
        return VSS(Polynomial(coeffs))

    def secshare_for(self, i: int) -> Scalar:
        # Return the secret share for the participant with id i.
        #
        # This computes f(i+1).
        if i < 0:
            raise ValueError(f"Invalid participant id: {i}")
        x = Scalar(i + 1)
        # Ensure we don't compute f(0), which is the secret.
        assert x != Scalar(0)
        return self.f(x)

    def secshares(self, n: int) -> list[Scalar]:
        # Return the secret shares for the participants with ids 0..n-1.
        #
        # This computes [f(1), ..., f(n)].
        return [self.secshare_for(i) for i in range(n)]

    def commit(self) -> VSSCommitment:
        return VSSCommitment([c * B for c in self.f.coeffs])

    def secret(self) -> Scalar:
        # Return the secret to be shared.
        #
        # This computes f(0).
        return self.f.coeffs[0]
