from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from chilldkg_ref import chilldkg, encpedpop

from ed25519lab.ed25519 import B, FE, GE, Scalar

ErrorInfo: TypeAlias = "dict[str, int | str | ErrorInfo]"

# GE forms of the off-subgroup points, for the list[GE] VSS-commitment fields.
# Both are canonically encoded but sit outside the prime-order subgroup.
TORSION_GE = GE(FE(0), FE(-1))  # order-2 torsion point (0, -1)
MIXED_ORDER_GE = Scalar(5) * B + TORSION_GE  # [k]B + torsion

# Adversarial 32-byte Ed25519 point encodings, for the byte-typed fields. All five
# are refused by both GE.from_bytes and its _with_identity variant:
NONCANONICAL_Y = b"\xff" * 32  # y >= p (non-canonical y coordinate)
NO_VALID_X = (2).to_bytes(32, "little")  # canonical y, no valid x (off-curve)
SMALL_ORDER_POINT = bytes(32)  # y == 0: an order-4 torsion point
MIXED_ORDER_POINT = MIXED_ORDER_GE.to_bytes()  # bytes of MIXED_ORDER_GE
NONCANONICAL_IDENTITY = bytes([1]) + bytes(30) + bytes([0x80])  # x == 0, sign bit set
# The canonical neutral element: refused by the strict from_bytes (used for
# individual keys/nonces, which can never be it) but ACCEPTED by _with_identity (used for
# aggregate/summed commitments, which may legitimately cancel to it).
IDENTITY_POINT = bytes([1]) + bytes(31)  # (0, 1), the neutral element


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: list[bytes]) -> list[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: list[str]) -> list[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def write_json(filename: Path, data: dict) -> None:
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def exception_asdict(e: Exception) -> dict:
    error_info: ErrorInfo = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int)):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        elif isinstance(value, encpedpop.ParticipantInvestigationData):
            continue
        else:
            raise NotImplementedError(
                f"Conversion for type {type(value).__name__} is not implemented"
            )

    # The last argument might contain the error message. Bare ValueError is the suite's
    # generic low-level rejection (secp256k1lab's core raises it bare; ed25519lab attaches
    # a message), so its text is a library detail, not part of the error contract; record
    # messages only for the typed exceptions (FaultyCoordinatorError, HostSeckeyError, etc.).
    if type(e) is not ValueError and len(e.args) > 0 and isinstance(e.args[-1], str):
        error_info.setdefault("message", e.args[-1])

    # Update snake case keys into camel case keys to match the JSON vector format
    for key in list(error_info.keys()):
        if "_" in key:
            camel_case_key = "".join(
                word.capitalize() if i > 0 else word
                for i, word in enumerate(key.split("_"))
            )
            error_info[camel_case_key] = error_info.pop(key)

    return error_info


def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")


def expect_faulty_exception(try_fn, expected_exception, expected_participant_id):
    error = expect_exception(try_fn, expected_exception)
    actual = error.get("participantId")
    assert actual == expected_participant_id, (
        f"expected faulty participant {expected_participant_id}, got {actual}"
    )
    return error


def params_asdict(params: chilldkg.SessionParams) -> dict:
    return {"hostpubkeys": bytes_list_to_hex(params.hostpubkeys), "t": params.t}


def dkg_output_asdict(dkg_output: chilldkg.DKGOutput) -> dict:
    secshare = bytes_to_hex(dkg_output.secshare) if dkg_output.secshare else None
    return {
        "secshare": secshare,
        "threshPk": bytes_to_hex(dkg_output.thresh_pk),
        "pubshares": bytes_list_to_hex(dkg_output.pubshares),
    }


def assign_tc_ids(groups):
    tc_id = 1
    for group in groups:
        for key in ("validTestCases", "errorTestCases"):
            for i, case in enumerate(group.get(key, [])):
                assert "tcId" not in case
                group[key][i] = {"tcId": tc_id, **case}
                tc_id += 1
    return tc_id - 1


# functions below are used to test JSON vectors with chilldkg_ref
# in tests.py


def assert_raises(try_fn, expected_error: dict):
    try:
        try_fn()
    except Exception as e:
        assert expected_error == exception_asdict(e)
    else:
        raise AssertionError("Expected exception")


def params_from_dict(params: dict) -> chilldkg.SessionParams:
    return chilldkg.SessionParams(
        hex_list_to_bytes(params["hostpubkeys"]),
        params["t"],
    )
