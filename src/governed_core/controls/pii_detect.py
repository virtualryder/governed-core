"""pii_detect — shared, fail-closed PII/PHI de-identification used by the mask_pii control AND its
per-pack domain overrides (so the detection logic is fixed in ONE place, not copied per vertical).

Amazon Comprehend DetectPiiEntities is the PRIMARY detector. Two coverage hardenings (2026-09-05):

  * LONG INPUT is chunked by UTF-8 BYTE windows and EVERY window is masked, so text beyond Comprehend's
    ~100 KB synchronous limit is never returned unmasked (the previous `Text=case[:99000]` sent only the
    head to Comprehend while returning the FULL string -> the tail of a large record leaked unmasked);
  * a deterministic REGEX BACKSTOP redacts high-precision structured identifiers Comprehend can miss in
    non-narrative / tabular text: US SSN, email, phone, IPv4, and Luhn-valid card numbers.

FAIL-CLOSED: Comprehend errors are raised to the caller, which returns deidentified=false and NO masked
text. The regex backstop is defense-in-depth ON TOP of Comprehend, never a substitute for it.
"""
import re
import boto3

COMPREHEND_BYTE_LIMIT = 90000   # under the 100 KB sync cap, headroom for multibyte

# Conservative, high-precision structured identifiers (deterministic; chosen to avoid over-redaction).
_REGEX = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")


def _luhn_ok(digits):
    if len(digits) < 13:
        return False
    s, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _byte_windows(text, limit):
    """Yield (start, end) char indices whose UTF-8 encoding is <= limit bytes, never splitting a char."""
    n, i = len(text), 0
    while i < n:
        j, b = i, 0
        while j < n:
            cb = len(text[j].encode("utf-8"))
            if b + cb > limit and j > i:
                break
            b += cb
            j += 1
        yield i, j
        i = j


def _comprehend_spans(cm, text, language):
    spans = []
    for a, z in _byte_windows(text, COMPREHEND_BYTE_LIMIT):
        ents = cm.detect_pii_entities(Text=text[a:z], LanguageCode=language).get("Entities", [])
        for ent in ents:
            b, e = ent.get("BeginOffset"), ent.get("EndOffset")
            if b is None or e is None:
                continue
            spans.append((a + b, a + e, ent.get("Type", "PII")))
    return spans


def _regex_spans(text):
    spans = []
    for label, rx in _REGEX:
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), label))
    for m in _CARD.finditer(text):
        if _luhn_ok(re.sub(r"\D", "", m.group())):
            spans.append((m.start(), m.end(), "CARD"))
    return spans


def _merge(spans):
    """Merge overlapping/adjacent spans (keep the first label); return descending for back-to-front edit."""
    merged = []
    for b, e, t in sorted(spans):
        if merged and b <= merged[-1][1]:
            pb, pe, pt = merged[-1]
            merged[-1] = (pb, max(pe, e), pt)
        else:
            merged.append((b, e, t))
    return sorted(merged, reverse=True)


def redact(text, comprehend_client=None, language="en"):
    """De-identify `text`. Returns (masked_text, meta). Raises the Comprehend error to the caller on a
    detector failure so the caller fails closed (never emits partially-masked text)."""
    cm = comprehend_client or boto3.client("comprehend")
    c_spans = _comprehend_spans(cm, text, language)
    r_spans = _regex_spans(text)
    spans = _merge(c_spans + r_spans)
    masked = text
    for b, e, _t in spans:
        masked = masked[:b] + ("[REDACTED:%s]" % _t) + masked[e:]
    return masked, {"entities_masked": len(spans), "comprehend_entities": len(c_spans),
                    "regex_backstop": len(r_spans), "masked_by": "comprehend:DetectPiiEntities+regex-backstop"}
