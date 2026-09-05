"""governed-core — shared PII/PHI detection is deeper and does not leak.

Gap (2026-09-05): mask_pii sent only Text=case[:99000] to Comprehend but returned the FULL string, so
the tail of a record larger than Comprehend's sync limit came back UNMASKED; and there was no backstop
for structured identifiers Comprehend misses in tabular text. pii_detect now (a) chunks by UTF-8 byte
windows and masks EVERY window, and (b) adds a deterministic regex/Luhn backstop. Comprehend is mocked.
"""
import governed_core  # noqa: F401
import pii_detect  # noqa: E402
import mask_pii  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402


class FakeComprehend:
    def __init__(self, entities=None):
        self.calls = []
        self._ents = entities if entities is not None else []

    def detect_pii_entities(self, Text, LanguageCode="en"):
        self.calls.append(Text)
        return {"Entities": self._ents}


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


def test_long_input_is_chunked_with_no_tail_leak():
    filler = "x" * (pii_detect.COMPREHEND_BYTE_LIMIT + 5000)
    text = filler + " contact bob@example.com END"
    cm = FakeComprehend([])                      # Comprehend finds nothing; regex must still catch the tail
    masked, meta = pii_detect.redact(text, comprehend_client=cm)
    assert len(cm.calls) >= 2                     # the input was chunked into multiple byte windows
    assert "bob@example.com" not in masked        # the tail email (beyond the old 99000 head) is masked
    assert "[REDACTED:EMAIL]" in masked


def test_regex_backstop_catches_structured_identifiers():
    cm = FakeComprehend([])
    text = "SSN 123-45-6789 mail a@b.co tel 415-555-2671 ip 10.0.0.1"
    masked, meta = pii_detect.redact(text, comprehend_client=cm)
    for token in ("123-45-6789", "a@b.co", "415-555-2671", "10.0.0.1"):
        assert token not in masked
    assert meta["regex_backstop"] >= 4


def test_luhn_only_valid_card_is_redacted():
    cm = FakeComprehend([])
    valid, invalid = "4111111111111111", "4111111111111112"
    m1, _ = pii_detect.redact("card " + valid, comprehend_client=cm)
    m2, _ = pii_detect.redact("card " + invalid, comprehend_client=cm)
    assert valid not in m1 and "[REDACTED:CARD]" in m1
    assert invalid in m2                          # fails the Luhn check -> not a card -> not redacted


def test_overlapping_comprehend_and_regex_spans_merge():
    text = "SSN 123-45-6789 here"
    b = text.index("123")
    cm = FakeComprehend([{"BeginOffset": b, "EndOffset": b + 11, "Type": "SSN"}])
    masked, meta = pii_detect.redact(text, comprehend_client=cm)
    assert masked.count("[REDACTED") == 1         # merged, not double-redacted / corrupted
    assert "123-45-6789" not in masked


def test_mask_pii_fails_closed_when_detector_errors(monkeypatch):
    def boom(text, comprehend_client=None, language="en"):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "DetectPiiEntities")
    monkeypatch.setattr(mask_pii.pii_detect, "redact", boom)
    out = mask_pii.handler({"case": "John Doe SSN 123-45-6789"}, _Ctx())
    assert out["deidentified"] is False and out["masked_case"] is None
