"""Unit tests for verification messages and the FR-3 response mapping (D2, D3)."""

import re

import pytest

from audit_log_service.api.schemas import represent_verification
from audit_log_service.application.verification import VIOLATION_MESSAGES, ChainVerification
from audit_log_service.integrity.verification import (
    AnchorStatus,
    ChainHead,
    VerificationResult,
    Violation,
    ViolationType,
)

VERIFIED_AT = "2026-09-28T19:45:00.123456Z"
RESPONSE_FIELDS = [
    "intact",
    "scheme",
    "verifiedAt",
    "recordsChecked",
    "head",
    "anchor",
    "violationCount",
    "firstViolation",
]


def _report(result: VerificationResult) -> dict[str, object]:
    return represent_verification(ChainVerification(verified_at=VERIFIED_AT, result=result))


def test_messages_cover_exactly_the_approved_violation_types() -> None:
    # The eight Phase 7 types, PAYLOAD_VALUE_MISSING (Phase 8), and the checkpoint types (Phase 10).
    assert set(VIOLATION_MESSAGES) == set(ViolationType)
    assert {t.value for t in VIOLATION_MESSAGES} == {
        "SEQUENCE_DUPLICATE",
        "SEQUENCE_GAP",
        "GENESIS_MISMATCH",
        "PREVIOUS_HASH_MISMATCH",
        "CONTENT_HASH_MISMATCH",
        "PAYLOAD_VALUE_MISMATCH",
        "PAYLOAD_VALUE_MISSING",
        "RECORD_HASH_MISMATCH",
        "RECORDED_AT_REGRESSION",
        "ANCHOR_MISMATCH",
        "CHAIN_TRUNCATED",
    }


def test_messages_are_the_approved_wording() -> None:
    assert dict(VIOLATION_MESSAGES) == {
        ViolationType.SEQUENCE_DUPLICATE: (
            "The record's sequence number repeats that of an earlier record."
        ),
        ViolationType.SEQUENCE_GAP: (
            "The record's sequence number does not directly follow the preceding record, "
            "or the chain does not start at sequence 1."
        ),
        ViolationType.GENESIS_MISMATCH: "The first record's previousHash is not the genesis value.",
        ViolationType.PREVIOUS_HASH_MISMATCH: (
            "The record's previousHash does not match the preceding record's recordHash."
        ),
        ViolationType.CONTENT_HASH_MISMATCH: "The record's content does not match its contentHash.",
        ViolationType.PAYLOAD_VALUE_MISMATCH: (
            "A stored payload value does not match its commitment."
        ),
        ViolationType.PAYLOAD_VALUE_MISSING: (
            "A payload value is missing without an authorizing redaction or retention event."
        ),
        ViolationType.RECORD_HASH_MISMATCH: (
            "The record's recordHash does not match its sequence, previousHash, and contentHash."
        ),
        ViolationType.RECORDED_AT_REGRESSION: (
            "The record's recordedAt is earlier than the preceding record's recordedAt."
        ),
        ViolationType.ANCHOR_MISMATCH: (
            "The record at the latest checkpoint's sequence does not match the checkpoint's "
            "recordHash."
        ),
        ViolationType.CHAIN_TRUNCATED: (
            "Records up to the latest checkpoint's sequence are missing from the end of the chain."
        ),
    }
    assert not any(re.search(r"[{}%]", message) for message in VIOLATION_MESSAGES.values())


def test_empty_chain_report() -> None:
    report = _report(
        VerificationResult(
            intact=True, records_checked=0, head=None, violation_count=0, first_violation=None
        )
    )

    assert list(report) == RESPONSE_FIELDS
    assert report == {
        "intact": True,
        "scheme": "audit-log/v1",
        "verifiedAt": VERIFIED_AT,
        "recordsChecked": 0,
        "head": None,
        "anchor": {"status": "NONE", "sequence": None},
        "violationCount": 0,
        "firstViolation": None,
    }


def test_intact_chain_report_names_the_head() -> None:
    report = _report(
        VerificationResult(
            intact=True,
            records_checked=3,
            head=ChainHead(sequence=3, record_hash="a" * 64),
            violation_count=0,
            first_violation=None,
        )
    )
    assert report["head"] == {"sequence": 3, "recordHash": "a" * 64}
    assert report["firstViolation"] is None


@pytest.mark.parametrize("violation_type", list(ViolationType))
def test_broken_chain_report_uses_the_fixed_message(violation_type: ViolationType) -> None:
    record_id = "0f8fad5b-d9cb-469f-a165-70867728950e"
    report = _report(
        VerificationResult(
            intact=False,
            records_checked=4,
            head=ChainHead(sequence=4, record_hash="b" * 64),
            violation_count=2,
            first_violation=Violation(type=violation_type, sequence=2, record_id=record_id),
        )
    )

    assert report["intact"] is False
    assert report["violationCount"] == 2
    assert report["firstViolation"] == {
        "type": violation_type.value,
        "sequence": 2,
        "recordId": record_id,
        "message": VIOLATION_MESSAGES[violation_type],
    }
    assert report["anchor"] == {"status": "NONE", "sequence": None}


@pytest.mark.parametrize(
    ("status", "sequence"),
    [
        (AnchorStatus.VERIFIED, 3),
        (AnchorStatus.MISMATCH, 3),
        (AnchorStatus.TRUNCATED, 7),
    ],
)
def test_report_renders_the_anchor_status_and_checkpoint_sequence(
    status: AnchorStatus, sequence: int
) -> None:
    report = _report(
        VerificationResult(
            intact=status is AnchorStatus.VERIFIED,
            records_checked=3,
            head=ChainHead(sequence=3, record_hash="a" * 64),
            violation_count=0 if status is AnchorStatus.VERIFIED else 1,
            first_violation=None,
            anchor_status=status,
            anchor_sequence=sequence,
        )
    )
    assert report["anchor"] == {"status": status.value, "sequence": sequence}


def test_truncation_report_has_a_null_record_id() -> None:
    report = _report(
        VerificationResult(
            intact=False,
            records_checked=2,
            head=ChainHead(sequence=2, record_hash="a" * 64),
            violation_count=1,
            first_violation=Violation(
                type=ViolationType.CHAIN_TRUNCATED, sequence=3, record_id=None
            ),
            anchor_status=AnchorStatus.TRUNCATED,
            anchor_sequence=5,
        )
    )
    assert report["firstViolation"] == {
        "type": "CHAIN_TRUNCATED",
        "sequence": 3,
        "recordId": None,
        "message": VIOLATION_MESSAGES[ViolationType.CHAIN_TRUNCATED],
    }
    assert report["anchor"] == {"status": "TRUNCATED", "sequence": 5}
