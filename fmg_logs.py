"""Read back what a staged script did: the task, the log, and the state it changed.

A finished task and a log that says "success" are not evidence that anything
was written. `changed_keys` compares the Device Database before and after,
which is.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from fmg_client import FMGShapeError

TASK_OK, TASK_FAILED = 4, 5      # the two terminal states seen on 7.6.6; others are unconfirmed


def task_state(fmg, task: int) -> dict:
    return fmg.get(f"/task/task/{task}")


def wait_for_task(fmg, task: int, *, timeout: float = 180, interval: float = 2,
                  sleep: Callable[[float], None] = time.sleep) -> dict:
    """Poll until the task reaches a terminal state; raise TimeoutError if it doesn't."""
    waited = 0.0
    while True:
        status = task_state(fmg, task)
        if status.get("state") in (TASK_OK, TASK_FAILED):
            return status
        if waited >= timeout:
            raise TimeoutError(f"task {task} still in state {status.get('state')!r} after {timeout}s")
        sleep(interval)
        waited += interval


def succeeded(status: dict) -> bool:
    return status.get("state") == TASK_OK


def device_summary(fmg, adom: str, device: str) -> list[dict]:
    """Every recorded script run for one device. Empty list if it has none."""
    try:
        return fmg.get(f"/dvmdb/adom/{adom}/script/log/summary/device/{device}")
    except FMGShapeError:
        return []


def log_id_for_task(task: int, *, real_device: bool = False) -> int:
    """The documented rule: log_id is the task id followed by 1 for a run
    against the Device Database, or 0 for a run on the real device."""
    return int(f"{task}{0 if real_device else 1}")


def log_output(fmg, adom: str, device: str, log_id: int) -> dict:
    """Output of one run. Use the per-device path: the ADOM-wide one returns -3
    for device runs because it only covers ADOM-level runs."""
    return fmg.get(f"/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{log_id}")


def latest_log(fmg, adom: str, device: str, log_id: int | None = None) -> dict | None:
    """A recorded script run for a device, or None if it has none.

    With no log_id, the run with the highest log_id in the per-device summary
    (sorted by log_id, never by seq). Pass log_id (see log_id_for_task) to read
    exactly the run you just made. The `latest/device` endpoint is not used: on
    my box it returned a run from weeks earlier while newer ones existed.
    """
    if log_id is None:
        runs = device_summary(fmg, adom, device)
        if not runs:
            return None
        log_id = max(r["log_id"] for r in runs)
    try:
        return log_output(fmg, adom, device, log_id)
    except FMGShapeError:
        return None


def summary_newest(summary: list[dict], device: str) -> int | None:
    """Highest log_id in the summary whose script name ends in __<device>.

    Shown for comparison, not for use: on my box the summary omitted the newest
    runs, and script names did not always match the device name's case.
    """
    suffix = f"__{device}".lower()
    ids = [e["log_id"] for e in summary if e.get("script_name", "").lower().endswith(suffix)]
    return max(ids, default=None)


def changed_keys(before: Any, after: Any) -> list[str]:
    """Names of the top-level fields that differ. Names only: values may be secrets."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [] if before == after else ["(whole value)"]
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
