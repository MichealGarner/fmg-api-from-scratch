"""fmg_redact.py - strip secrets from FortiManager responses before they are
printed, logged or saved.

Management-plane APIs return credential material in routine reads. A device
list carries each device's encrypted admin password; an admin profile carries
an encrypted key. Redact by key name AND by value shape, because a name list
alone will eventually miss one.
"""
from __future__ import annotations

import re
from typing import Any

MASK = "******"
_SECRET_KEY = re.compile(r"pass|psk|secret|private|token|key|session|cookie", re.I)


def _looks_encrypted(value: Any) -> bool:
    """FortiManager marks encrypted values with an 'ENC' prefix."""
    if isinstance(value, str):
        return value.startswith("ENC ") and len(value) > 12
    if isinstance(value, list) and value:
        return value[0] == "ENC"
    return False


def redact(obj: Any) -> Any:
    """Return a copy of `obj` with secret-looking values masked."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            secret_key = isinstance(key, str) and _SECRET_KEY.search(key)
            if (secret_key and value not in (None, "", [], 0, False)) or _looks_encrypted(value):
                out[key] = MASK
            else:
                out[key] = redact(value)
        return out
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    return obj
