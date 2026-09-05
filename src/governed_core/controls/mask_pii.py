import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import telemetry
import pii_detect

# mask_pii — fail-closed general PII de-identification. The detection logic (Comprehend primary +
# byte-window chunking so long input never leaks its tail + a deterministic regex/Luhn backstop) lives
# in the SHARED pii_detect module so it is fixed once and reused by every per-pack domain override.
# FAIL-CLOSED: if detection cannot run, NO masked text is returned and deidentified=false.

def _coerce(e):
    e = e or {}
    if isinstance(e, str):
        try:
            return json.loads(e)
        except Exception:
            return {"case": e}
    return e

@telemetry.instrument('mask_pii')
def handler(event, context):
    e = _coerce(event)
    case = e.get("case", e.get("application", ""))
    if not isinstance(case, str):
        case = json.dumps(case, ensure_ascii=False)
    if not case.strip():
        return {"deidentified": False, "masked_case": None, "error": "empty input"}
    try:
        masked, meta = pii_detect.redact(case)
    except (BotoCoreError, ClientError) as exc:
        # Fail-closed: never emit unmasked text if the primary detector fails.
        return {"deidentified": False, "masked_case": None,
                "error": "pii detection failed: %s" % type(exc).__name__}
    return {"deidentified": True, "masked_case": masked, **meta}
