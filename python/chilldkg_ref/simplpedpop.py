from __future__ import annotations

from typing import NamedTuple, NewType, NoReturn

from ed25519lab.ed25519 import GE, Scalar
from ed25519lab.internal_sig import internal_sign, internal_verify

from .util import (
    FaultyCoordinatorError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    MsgParseError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)
from .vss import VSS, VSSCommitment

###
### Exceptions
###


class SecshareSumError(ValueError):
    pass


###
### Proofs of possession (pops)
###


Pop = NewType("Pop", bytes)


def pop_msg(participant_id: int) -> bytes:
    # internal_sign has a fixed challenge tag, so domain separation from other
    # internal signatures in this protocol (e.g. CertEq) lives in the message:
    # the "pop message" tag hash is what gets signed.
    return tagged_hash_bip_dkg(
        "pop message", participant_id.to_bytes(4, byteorder="big")
    )


def pop_prove(seckey: bytes, participant_id: int, aux_rand: bytes) -> Pop:
    sig = internal_sign(pop_msg(participant_id), seckey, aux=aux_rand)
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, participant_id: int) -> bool:
    return internal_verify(pop_msg(participant_id), pubkey, pop)


###
### Messages
###


class ParticipantMsg(NamedTuple):
    com: VSSCommitment
    pop: Pop

    @staticmethod
    def len_bytes(*, t: int) -> int:
        return 32 * t + 64

    @staticmethod
    def from_bytes(b: bytes, *, t: int) -> ParticipantMsg:
        if len(b) != ParticipantMsg.len_bytes(t=t):
            raise ValueError

        # Read com (32*t bytes)
        try:
            com = VSSCommitment.from_bytes(b[: 32 * t], t=t)
        except ValueError as e:
            raise MsgParseError("invalid VSS commitment") from e
        # Read pop (64 bytes)
        pop = Pop(b[32 * t :])

        return ParticipantMsg(com, pop)

    def to_bytes(self) -> bytes:
        return self.com.to_bytes() + self.pop


class CoordinatorMsg(NamedTuple):
    coms_to_secrets: list[GE]
    sum_coms_to_nonconst_terms: list[GE]
    pops: list[Pop]

    @staticmethod
    def len_bytes(*, t: int, n: int) -> int:
        return 96 * n + 32 * (t - 1)

    @staticmethod
    def from_bytes(b: bytes, *, t: int, n: int) -> CoordinatorMsg:
        if len(b) != CoordinatorMsg.len_bytes(t=t, n=n):
            raise ValueError

        # Read coms_to_secrets (32*n bytes)
        try:
            coms_to_secrets, rest = (
                [
                    GE.from_bytes_with_identity(b[i : i + 32])
                    for i in range(0, 32 * n, 32)
                ],
                b[32 * n :],
            )
        except ValueError as e:
            raise MsgParseError("invalid commitment to secret") from e

        # Read sum_coms_to_nonconst_terms (32*(t-1) bytes)
        try:
            sum_coms_to_nonconst_terms, rest = (
                [
                    GE.from_bytes_with_identity(rest[i : i + 32])
                    for i in range(0, 32 * (t - 1), 32)
                ],
                rest[32 * (t - 1) :],
            )
        except ValueError as e:
            raise MsgParseError("invalid sum commitment to non-constant term") from e

        # Read pops (64*n bytes)
        pops = [Pop(rest[i : i + 64]) for i in range(0, 64 * n, 64)]

        return CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops)

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                P.to_bytes()
                for P in self.coms_to_secrets + self.sum_coms_to_nonconst_terms
            ]
        ) + b"".join(self.pops)


class CoordinatorInvestigationMsg(NamedTuple):
    partial_pubshares: list[GE]

    @staticmethod
    def len_bytes(*, n: int) -> int:
        return 32 * n

    @staticmethod
    def from_bytes(b: bytes, *, n: int) -> CoordinatorInvestigationMsg:
        if len(b) != CoordinatorInvestigationMsg.len_bytes(n=n):
            raise ValueError

        # Read partial_pubshares (32*n bytes)
        try:
            partial_pubshares = [
                GE.from_bytes_with_identity(b[i : i + 32]) for i in range(0, 32 * n, 32)
            ]
        except ValueError as e:
            raise MsgParseError("invalid partial pubshare") from e

        return CoordinatorInvestigationMsg(partial_pubshares)

    def to_bytes(self) -> bytes:
        return b"".join([P.to_bytes() for P in self.partial_pubshares])


###
### Other common definitions
###


class DKGOutput(NamedTuple):
    secshare: bytes | None  # None for coordinator
    thresh_pk: bytes
    pubshares: list[bytes]


def assemble_sum_coms(
    coms_to_secrets: list[GE], sum_coms_to_nonconst_terms: list[GE]
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(c for c in coms_to_secrets))] + sum_coms_to_nonconst_terms
    )


###
### Participant
###


class ParticipantState(NamedTuple):
    t: int
    n: int
    participant_id: int
    com_to_secret: GE


class ParticipantInvestigationData(NamedTuple):
    n: int
    participant_id: int
    secshare: Scalar
    pubshare: GE


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive
# computations, we omit explicit invocations of an interactive equality check
# protocol. ChillDKG will take care of invoking the equality check protocol.


def participant_step1(
    seed: bytes, t: int, n: int, participant_id: int, aux_rand: bytes
) -> tuple[
    ParticipantState,
    bytes,
    # The following return value is a list of n partial secret shares generated
    # by this participant. The item at index i is supposed to be made available
    # to participant i privately, e.g., via an external secure channel. See also
    # the function participant_step2_prepare_secshare().
    list[Scalar],
]:
    if t > n:
        raise ValueError
    if participant_id >= n:
        raise IndexError
    if len(seed) != 32:
        raise ValueError
    if len(aux_rand) != 32:
        raise ValueError

    vss = VSS.generate(seed, t)  # OverflowError if t >= 2**32
    partial_secshares_from_me = vss.secshares(n)
    pop = pop_prove(vss.secret().to_bytes(), participant_id, aux_rand)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop).to_bytes()
    state = ParticipantState(t, n, participant_id, com_to_secret)
    return state, msg, partial_secshares_from_me


# Helper function to prepare the secshare for participant id's
# participant_step2() by summing the partial_secshares returned by all
# participants' participant_step1().
#
# In a pure run of SimplPedPop where secret shares are sent via external secure
# channels (i.e., EncPedPop is not used), each participant needs to run this
# function in preparation of their participant_step2(). Since this computation
# involves secret data, it cannot be delegated to the coordinator as opposed to
# other aggregation steps.
#
# If EncPedPop is used instead (as a wrapper of SimplPedPop), the coordinator
# can securely aggregate the encrypted partial secshares into an encrypted
# secshare by exploiting the additively homomorphic property of the encryption.
def participant_step2_prepare_secshare(
    partial_secshares: list[Scalar],
) -> Scalar:
    secshare: Scalar  # REVIEW Work around missing type annotation of Scalar.sum
    secshare = Scalar.sum(*partial_secshares)
    return secshare


def participant_step2(
    state: ParticipantState,
    cmsg: bytes,
    secshare: Scalar,
) -> tuple[DKGOutput, bytes]:
    t, n, participant_id, com_to_secret = state
    try:
        cmsg_parsed = CoordinatorMsg.from_bytes(cmsg, t=t, n=n)
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    coms_to_secrets, sum_coms_to_nonconst_terms, pops = cmsg_parsed

    if coms_to_secrets[participant_id] != com_to_secret:
        raise FaultyCoordinatorError(
            "Coordinator sent unexpected first group element for local participant id"
        )

    for i in range(n):
        if i == participant_id:
            # No need to check our own pop.
            continue
        if coms_to_secrets[i].is_identity:
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid commitment"
            )
        # This can be optimized: We serialize the coms_to_secrets[i] here, but
        # internal_verify (inside pop_verify) will need to deserialize it again.
        if not pop_verify(pops[i], coms_to_secrets[i].to_bytes(), i):
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid proof-of-knowledge"
            )

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms)
    pubshare = sum_coms.pubshare(participant_id)
    if not VSSCommitment.verify_secshare(secshare, pubshare):
        raise UnknownFaultyParticipantOrCoordinatorError(
            ParticipantInvestigationData(n, participant_id, secshare, pubshare),
            "Received invalid secshare; consider using "
            "participant_investigate() to determine a faulty party",
        )

    thresh_pk = sum_coms.commitment_to_secret()
    pubshares = [
        sum_coms.pubshare(i)
        if i != participant_id
        else pubshare  # We have computed our own pubshare already.
        for i in range(n)
    ]
    dkg_output = DKGOutput(
        secshare.to_bytes(),
        thresh_pk.to_bytes(),
        [pubshare.to_bytes() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: bytes,
    partial_secshares: list[Scalar],
) -> NoReturn:
    n, participant_id, secshare, pubshare = error.inv_data
    if len(partial_secshares) != n:
        raise ValueError

    try:
        cinv_parsed = CoordinatorInvestigationMsg.from_bytes(cinv, n=n)
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    partial_pubshares = cinv_parsed.partial_pubshares

    if GE.sum(*partial_pubshares) != pubshare:
        raise FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")

    if Scalar.sum(*partial_secshares) != secshare:
        raise SecshareSumError("Sum of partial secshares not equal to secshare")

    for i in range(n):
        if not VSSCommitment.verify_secshare(
            partial_secshares[i], partial_pubshares[i]
        ):
            if i != participant_id:
                raise FaultyParticipantOrCoordinatorError(
                    i, "Participant sent invalid partial secshare"
                )
            else:
                # We are not faulty, so the coordinator must be.
                raise FaultyCoordinatorError(
                    "Coordinator fiddled with the share from me to myself"
                )

    # We now know:
    #  - The sum of the partial secshares is equal to the secshare.
    #  - The sum of the partial pubshares is equal to the pubshare.
    #  - Every partial secshare matches its corresponding partial pubshare.
    # Hence, the secshare matches the pubshare.
    assert VSSCommitment.verify_secshare(secshare, pubshare)

    # This should never happen (unless the caller fiddled with the inputs).
    raise RuntimeError(
        "participant_investigate() was called, but all inputs are consistent."
    )


###
### Coordinator
###


def coordinator_step(
    pmsgs: list[bytes], t: int, n: int
) -> tuple[bytes, DKGOutput, bytes]:
    if len(pmsgs) != n:
        raise ValueError
    pmsgs_parsed = []
    for i, pmsg in enumerate(pmsgs):
        try:
            parsed = ParticipantMsg.from_bytes(pmsg, t=t)
        except MsgParseError as e:
            raise FaultyParticipantError(i, *e.args) from e
        pmsgs_parsed.append(parsed)
    # Sum the commitments to the i-th coefficients for i > 0
    #
    # This procedure corresponds to the one described by Pedersen in Section 5.1
    # of "Non-Interactive and Information-Theoretic Secure Verifiable Secret
    # Sharing". However, we don't sum the commitments to the secrets (i == 0)
    # because they'll be necessary to check the pops.
    coms_to_secrets = [pmsg.com.commitment_to_secret() for pmsg in pmsgs_parsed]
    # But we can sum the commitments to the non-constant terms.
    sum_coms_to_nonconst_terms = [
        GE.sum(*(pmsg.com.commitment_to_nonconst_terms()[j] for pmsg in pmsgs_parsed))
        for j in range(t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs_parsed]
    cmsg = CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops).to_bytes()

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms)
    thresh_pk = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]

    dkg_output = DKGOutput(
        None,
        thresh_pk.to_bytes(),
        [pubshare.to_bytes() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input


def coordinator_investigate(pmsgs: list[bytes], t: int) -> list[bytes]:
    n = len(pmsgs)
    pmsgs_parsed = [ParticipantMsg.from_bytes(pmsg, t=t) for pmsg in pmsgs]
    all_partial_pubshares = [
        [pmsg.com.pubshare(i) for pmsg in pmsgs_parsed] for i in range(n)
    ]
    return [
        CoordinatorInvestigationMsg(all_partial_pubshares[i]).to_bytes()
        for i in range(n)
    ]
