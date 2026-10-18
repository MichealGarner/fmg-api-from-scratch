#!/usr/bin/env python3
"""fmg_push.py - render, push, stage and inspect FortiManager CLI scripts.

    python fmg_push.py devices
    python fmg_push.py push  --template dns.j2 --vars vars.json --device DEV            (dry run)
    python fmg_push.py push  --template dns.j2 --vars vars.json --device DEV --apply
    python fmg_push.py stage --script dns__DEV --device DEV --watch /pm/config/device/DEV/global/system/dns --apply
    python fmg_push.py log   --device DEV
    python fmg_push.py preview --device DEV                      (read-only: shows the install diff)
    python fmg_push.py install --device DEV --apply             (only if the diff matches the last preview)

Nothing here reaches a live device. Writes are off unless --apply is given.
Rendered CLI is never printed, only its size and a SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import jinja2

sys.path.insert(0, str(Path(__file__).resolve().parent / "examples"))

from fmg_client import FMGClient, FMGError                       # noqa: E402
from fmg_install import InstallRefused, install, preview, write_marker  # noqa: E402
from fmg_logs import (changed_keys, latest_log, succeeded,       # noqa: E402
                      wait_for_task)
from fmg_scripts import push, render, stage                      # noqa: E402

SUPPORTED = ((7, 6),)          # (major, minor) pairs this tool has been tested against
AUDIT_LOG = "fmg_push_audit.jsonl"


def check_version(status: dict, supported=SUPPORTED) -> None:
    """Refuse to run against a FortiManager version the tool has not been tested on."""
    have = (status.get("Major"), status.get("Minor"))
    if have not in supported:
        raise SystemExit(f"FortiManager {have[0]}.{have[1]} is not one of the tested versions "
                         f"{list(supported)}; refusing to continue.")


def audit_record(action: str, adom: str, device: str, script: str, content: str = "") -> dict:
    """What to remember about an action. Never the content itself, only its hash and size."""
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action, "adom": adom, "device": device, "script": script,
            "sha256": hashlib.sha256(content.encode()).hexdigest() if content else None,
            "lines": content.count("\n") if content else 0}


def write_audit(path: str, record: dict) -> None:
    with open(path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


def cmd_devices(fmg, args) -> int:
    for d in fmg.get(f"/dvmdb/adom/{args.adom}/device", fields=["name", "os_ver", "conn_status"]):
        print(f"{d.get('name', '?'):<28} os_ver={d.get('os_ver')}  conn_status={d.get('conn_status')}")
    return 0


def cmd_push(fmg, args) -> int:
    template = Path(args.template).read_text()
    variables = json.loads(Path(args.vars).read_text())
    try:
        content = render(template, variables)      # raises on any missing variable
    except jinja2.UndefinedError as err:
        print(f"Not pushed: {err}. Add it to {args.vars} or fix the template.", file=sys.stderr)
        return 2
    name = args.name or f"{Path(args.template).stem}__{args.device}"
    rec = audit_record("push", args.adom, args.device, name, content)
    print(f"Rendered {args.template} for {args.device}: {rec['lines']} lines, sha256 {rec['sha256'][:12]}")
    if not args.apply:
        print(f"Dry run. Would push script '{name}'. Add --apply to do it.")
        return 0
    desc = f"{args.template} | sha {rec['sha256'][:12]} | pushed {rec['ts']} | device {args.device}"
    push(fmg, args.adom, name, content, desc)
    write_audit(args.audit, rec)
    print(f"Pushed script '{name}' to the ADOM database. No device has been touched.")
    return 0


def cmd_stage(fmg, args) -> int:
    if not args.apply:
        print(f"Dry run. Would stage '{args.script}' against {args.device}'s Device Database.")
        return 0
    before = fmg.get(args.watch) if args.watch else None
    task = stage(fmg, args.adom, args.script, args.device)
    status = wait_for_task(fmg, task)
    write_audit(args.audit, audit_record("stage", args.adom, args.device, args.script))
    print(f"Task {task} finished, state {status.get('state')} "
          f"({'success' if succeeded(status) else 'FAILED'}).")
    if not succeeded(status):
        return 1
    if args.watch:
        keys = changed_keys(before, fmg.get(args.watch))
        print("Fields changed in the Device Database:", ", ".join(keys) if keys else "NONE")
        if not keys:
            print("A green task with no change: the script set what was already there, "
                  "or nothing was written. Do not install on the strength of this.")
    return 0


def cmd_log(fmg, args) -> int:
    rec = latest_log(fmg, args.adom, args.device, args.log_id)
    if not rec:
        print(f"No recorded script run for {args.device}.")
        return 0
    content = rec.get("content") or ""
    print(f"log_id {rec.get('log_id')}  script {rec.get('script_name')}  at {rec.get('exec_time')}  "
          f"({content.count(chr(10))} lines)")
    if args.show:
        print("(this log contains the rendered CLI, secrets included: treat it as sensitive)")
        print(content)
    return 0


STATE_DIR = Path.home() / ".cache" / "fmg_push"


def cmd_preview(fmg, args) -> int:
    result = preview(fmg, args.adom, args.device)
    if not result["diff"]:
        print(f"No changes would be installed on {args.device}. Nothing to approve.")
        return 0
    print("(this diff is the CLI that install would send, secrets included: treat it as sensitive)")
    print(result["diff"])
    write_marker(STATE_DIR, result)
    write_audit(args.audit, audit_record("preview", args.adom, args.device, "", result["diff"]))
    print(f"\nsha256 {result['sha256'][:12]}. Read it, then: install --device {args.device} --apply")
    return 0


def cmd_install(fmg, args) -> int:
    if not args.apply:
        print(f"Dry run. Would install to {args.device} if the diff still matches your last preview. "
              "Add --apply to do it.")
        return 0
    try:
        out = install(fmg, args.adom, args.device, STATE_DIR)
    except InstallRefused as err:
        print(f"Not installed: {err}", file=sys.stderr)
        return 2
    write_audit(args.audit, {**audit_record("install", args.adom, args.device, ""), "sha256": out["sha256"],
                             "task": out["task"], "ok": out["ok"]})
    print(f"Install task {out['task']} {'succeeded' if out['ok'] else 'FAILED'}.")
    return 0 if out["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file")
    ap.add_argument("--adom", help="default: the first ADOM this account can see")
    ap.add_argument("--audit", default=AUDIT_LOG, help="append-only action log (no content)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("devices")
    p = sub.add_parser("push")
    p.add_argument("--template", required=True)
    p.add_argument("--vars", required=True)
    p.add_argument("--device", required=True)
    p.add_argument("--name")
    p.add_argument("--apply", action="store_true")
    s = sub.add_parser("stage")
    s.add_argument("--script", required=True)
    s.add_argument("--device", required=True)
    s.add_argument("--watch", help="Device Database path to compare before and after")
    s.add_argument("--apply", action="store_true")
    g = sub.add_parser("log")
    g.add_argument("--device", required=True)
    g.add_argument("--log-id", type=int, help="read this run (task id followed by 1); default: newest")
    g.add_argument("--show", action="store_true", help="print the log text (contains rendered CLI)")
    for name in ("preview", "install"):
        q = sub.add_parser(name)
        q.add_argument("--device", required=True)
        if name == "install":
            q.add_argument("--apply", action="store_true")
    return ap


COMMANDS = {"devices": cmd_devices, "push": cmd_push, "stage": cmd_stage, "log": cmd_log,
            "preview": cmd_preview, "install": cmd_install}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    from dotenv import load_dotenv
    from first_call import tls_settings
    load_dotenv(args.env_file or Path(__file__).resolve().parent / ".env")
    if tls_settings().get("verify") is False:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        host, user, pw = (os.environ[k] for k in ("FMG_HOST", "FMG_USER", "FMG_PASSWORD"))
    except KeyError as missing:
        print(f"Missing {missing}", file=sys.stderr)
        return 2
    try:
        with FMGClient(host, **tls_settings()) as fmg:
            fmg.login(user, pw)
            check_version(fmg.get("/sys/status"))
            args.adom = args.adom or fmg.get("/dvmdb/adom")[0]["name"]
            return COMMANDS[args.command](fmg, args)
    except FMGError as err:
        print(f"Stopped: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
