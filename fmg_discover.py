"""Discovery helpers: ask an endpoint what it is, without leaking what it holds.

Nothing here writes. `probe` reports the *shape* of a response (type, count,
field names), never the values, so its output is safe to paste or log.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fmg_client import FMGError, FMGShapeError

# (label, url template). {adom} and {device} are filled from the command line.
# Some of these will fail on your box: that is the point of running them.
CANDIDATES = [
    ("system status",       "/sys/status"),
    ("ADOM list",           "/dvmdb/adom"),
    ("one ADOM",            "/dvmdb/adom/{adom}"),
    ("devices in ADOM",     "/dvmdb/adom/{adom}/device"),
    ("all devices",         "/dvmdb/device"),
    ("scripts (dvmdb)",     "/dvmdb/adom/{adom}/script"),
    ("scripts (objects)",   "/pm/config/adom/{adom}/obj/fmg/script"),
    ("policy packages",     "/pm/pkg/adom/{adom}"),
    ("firewall addresses",  "/pm/config/adom/{adom}/obj/firewall/address"),
    ("device DNS",          "/pm/config/device/{device}/global/system/dns"),
    ("device interfaces",   "/pm/config/device/{device}/global/system/interface"),
    ("last script log",     "/dvmdb/adom/{adom}/script/log/latest/device/{device}"),
]


@dataclass
class Outcome:
    url: str
    kind: str      # data | empty | denied | missing | error
    detail: str

    def line(self) -> str:
        return f"[{self.kind.upper():<7}] {self.url}  {self.detail}"


def shape(data: Any) -> str:
    """Describe a response without quoting any value."""
    if isinstance(data, list):
        if not data:
            return "list, 0 items"
        first = data[0]
        keys = sorted(first) if isinstance(first, dict) else []
        return f"list, {len(data)} items; item keys: {', '.join(keys) or type(first).__name__}"
    if isinstance(data, dict):
        return f"object; keys: {', '.join(sorted(data))}"
    return f"scalar ({type(data).__name__})"


def probe(fmg, url: str, **extra: Any) -> Outcome:
    try:
        return Outcome(url, "data", shape(fmg.get(url, **extra)))
    except FMGShapeError:
        # Status OK with no data key: on the lab box this is what a
        # non-existent endpoint looked like, so do not read it as success.
        return Outcome(url, "empty", "status OK but no data (endpoint may not exist)")
    except FMGError as err:
        if err.code == -11:
            return Outcome(url, "denied", "no permission (or no such path)")
        if err.code == -3:
            return Outcome(url, "missing", "object does not exist")
        return Outcome(url, "error", f"code {err.code}: {err.message}")


def fields_filter_honoured(fmg, url: str, field: str) -> bool | None:
    """Does asking for one field really return only that field?

    True/False, or None if the answer can't be judged (nothing came back).
    """
    data = fmg.get(url, fields=[field])
    rows = data if isinstance(data, list) else [data]
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        return None
    return all(set(r) <= {field, "oid"} for r in rows)


def endpoints_from_bodies(text: str) -> list[tuple[str, str]]:
    """List (method, url) pairs from JSON-RPC request bodies copied out of
    the browser's network tab. Accepts one body, a JSON list of bodies, or one
    body per line. Values and session tokens are ignored, so nothing sensitive
    is carried into the result.
    """
    text = text.strip()
    docs: list[Any] = []
    try:
        docs.append(json.loads(text))
    except ValueError:
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    docs.append(json.loads(line))
                except ValueError:
                    pass
    found: dict[tuple[str, str], None] = {}
    for doc in docs:
        for body in doc if isinstance(doc, list) else [doc]:
            if not isinstance(body, dict):
                continue
            method = body.get("method", "?")
            for p in body.get("params", []) or []:
                if isinstance(p, dict) and "url" in p:
                    found[(method, p["url"])] = None
    return list(found)
