"""Preview and install, with a guard: install only what you previewed.

The sequence below was captured from the FortiManager 7.6.6 GUI and confirmed
by hand on a lab box. `install/device` with the `preview` flag only builds a
summary. The text the GUI shows behind the eye icon comes from a second call,
`install/preview`, read back with `preview/result`. Both need the numeric ADOM
id and a numeric device/vdom scope: names are refused.

Nothing here is installed unless `install` is called, and `install` refuses
unless the diff it is about to send hashes to the one you approved.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from fmg_client import FMGError
from fmg_logs import succeeded, wait_for_task

MARKER_MAX_AGE = 1800        # seconds an approved preview stays valid
NO_RESULT = "=== No preview result ==="


class InstallRefused(RuntimeError):
    """Raised when the guard will not let an install go ahead."""


def resolve(fmg, adom: str, device: str, vdom: str = "root") -> tuple[int, list[dict]]:
    """Numeric ADOM id and the install scope for one device's vdom."""
    adom_oid = fmg.get(f"/dvmdb/adom/{adom}", fields=["oid"])["oid"]
    rows = fmg.get(f"/dvmdb/adom/{adom}/device", fields=["name", "oid", "vdom"],
                   filter=["name", "==", device])
    if not rows:
        raise FMGError(-3, f"device {device!r} not found in ADOM {adom!r}", "/dvmdb")
    dev = rows[0]
    for v in dev.get("vdom") or []:
        if v.get("name") == vdom:
            return adom_oid, [{"oid": dev["oid"], "vdom_oid": v["oid"]}]
    raise FMGError(-3, f"vdom {vdom!r} not found on {device!r}", "/dvmdb")


def _task(fmg, url: str, body: dict) -> int:
    task = (fmg.execute(url, body).get("data") or {}).get("task")
    if task is None:
        raise RuntimeError(f"{url} returned no task id")
    return task


def parse_preview(message: str) -> str:
    """The diff text from preview/result's JSON-string `message`.

    Returns "" when FortiManager reports no preview result, so callers cannot
    mistake "nothing to show" for "nothing to change" without checking.
    """
    try:
        entries = json.loads(message)
    except (TypeError, ValueError) as err:
        raise RuntimeError(f"preview/result message was not JSON: {err}") from err
    texts = [e.get("result", "") for e in entries if isinstance(e, dict)]
    texts = [t for t in texts if t.strip() and not t.strip().startswith(NO_RESULT)]
    return "\n".join(texts)


def diff_hash(diff: str) -> str:
    return hashlib.sha256(diff.encode()).hexdigest()


def cancel(fmg, adom_oid: int) -> None:
    fmg.execute("/securityconsole/package/cancel/install", {"adom": adom_oid})


def build_preview(fmg, adom_oid: int, scope: list[dict], comment: str) -> str:
    """Run the preview chain and return the diff text. Caller cancels."""
    cancel(fmg, adom_oid)
    t1 = _task(fmg, "/securityconsole/install/device",
               {"adom": adom_oid, "flags": ["preview"], "dev_rev_comments": comment, "scope": scope})
    if not succeeded(wait_for_task(fmg, t1)):
        raise RuntimeError(f"install/device preview task {t1} failed")
    t2 = _task(fmg, "/securityconsole/install/preview",
               {"adom": adom_oid, "scope": scope, "flags": []})
    if not succeeded(wait_for_task(fmg, t2)):
        raise RuntimeError(f"install/preview task {t2} failed")
    res = fmg.execute("/securityconsole/preview/result", {"adom": adom_oid, "scope": scope})
    return parse_preview((res.get("data") or {}).get("message"))


def preview(fmg, adom: str, device: str, comment: str = "fmg_push preview") -> dict:
    """What would be installed on `device`. Never installs; always cancels."""
    adom_oid, scope = resolve(fmg, adom, device)
    try:
        diff = build_preview(fmg, adom_oid, scope, comment)
    finally:
        cancel(fmg, adom_oid)
    return {"device": device, "diff": diff, "sha256": diff_hash(diff) if diff else None}


# -- the guard -------------------------------------------------------------

def marker_path(state_dir: Path, device: str) -> Path:
    return Path(state_dir) / f"preview_{device}.json"


def write_marker(state_dir: Path, result: dict, now: float | None = None) -> Path | None:
    """Record an approved preview. No diff, no marker: there is nothing to approve."""
    if not result["diff"]:
        return None
    path = marker_path(state_dir, result["device"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"device": result["device"], "sha256": result["sha256"],
                                "at": now if now is not None else time.time()}))
    return path


def check_marker(state_dir: Path, device: str, now: float | None = None) -> str:
    """The approved hash for `device`, or InstallRefused."""
    path = marker_path(state_dir, device)
    if not path.exists():
        raise InstallRefused(f"no preview on record for {device}; run preview first")
    rec = json.loads(path.read_text())
    age = (now if now is not None else time.time()) - rec["at"]
    if age > MARKER_MAX_AGE:
        raise InstallRefused(f"the preview for {device} is {int(age)}s old (limit {MARKER_MAX_AGE}s); run preview again")
    return rec["sha256"]


def install(fmg, adom: str, device: str, state_dir: Path, comment: str = "fmg_push install",
            now: float | None = None) -> dict:
    """Install to `device` only if the diff hashes to the one previewed.

    The diff is rebuilt in the same session as the commit, so the hash checked
    is of what is about to be sent, not of what was sent last time.
    """
    approved = check_marker(state_dir, device, now)
    adom_oid, scope = resolve(fmg, adom, device)
    try:
        diff = build_preview(fmg, adom_oid, scope, comment)
        if not diff:
            raise InstallRefused("the preview is empty: nothing to install")
        if diff_hash(diff) != approved:
            raise InstallRefused("the diff has changed since you previewed it; "
                                 "run preview again and read it")
        commit = _task(fmg, "/securityconsole/package/commit", {"adom": adom_oid, "scope": scope})
        status = wait_for_task(fmg, commit, timeout=300)
    finally:
        cancel(fmg, adom_oid)
    marker_path(state_dir, device).unlink(missing_ok=True)
    return {"device": device, "task": commit, "ok": succeeded(status), "sha256": approved}
