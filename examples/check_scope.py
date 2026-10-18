#!/usr/bin/env python3
"""Audit an API account: read its own record and profile, judge them, and
prove the ADOM restriction by trying to read outside it.

    python examples/check_scope.py --other-adom root
    python examples/check_scope.py --env-file auditor.env --user svc-push --other-adom root

Read-only. Once an account really is least-privilege it may not be allowed to
read its own profile; run this with a separate, read-only auditor login (via
--env-file and --user) or as an administrator.
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests                         # noqa: E402
from dotenv import load_dotenv          # noqa: E402

from fmg_audit import audit             # noqa: E402
from fmg_client import FMGClient, FMGError   # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from first_call import tls_settings     # noqa: E402


def read(fmg, url):
    try:
        return fmg.get(url, verbose=True)
    except FMGError as err:
        print(f"  (could not read {url}: {err.message})")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", help="read credentials from this file instead of .env")
    parser.add_argument("--user", help="account to audit (default: the login user)")
    parser.add_argument("--other-adom", help="an ADOM the account must NOT be able to read")
    args = parser.parse_args()

    load_dotenv(args.env_file)
    if tls_settings().get("verify") is False:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        host, login = os.environ["FMG_HOST"], os.environ["FMG_USER"]
        password = os.environ["FMG_PASSWORD"]
    except KeyError as missing:
        print(f"Missing {missing}", file=sys.stderr)
        return 2
    target = args.user or login

    try:
        with FMGClient(host, **tls_settings()) as fmg:
            fmg.login(login, password)
            user = read(fmg, f"/cli/global/system/admin/user/{target}")
            profile = read(fmg, f"/cli/global/system/admin/profile/{user['profileid']}") if user else None
            glob = read(fmg, "/cli/global/system/global")
            setting = read(fmg, "/cli/global/system/admin/setting")
            findings = audit(user, profile, glob, setting)

            denied = None
            if args.other_adom:
                try:
                    fmg.get(f"/dvmdb/adom/{args.other_adom}/device", fields=["name"])
                    denied = False
                except FMGError as err:
                    denied = err.code == -11
    except (FMGError, requests.RequestException) as err:
        print(f"Failed: {err}", file=sys.stderr)
        return 1

    print(f"\nAudit of {target}:")
    for f in findings:
        print(f"  [{f.level:<4}] {f.item}: {f.detail}")
    if denied is not None:
        verdict = "OK  " if denied else "FAIL"
        print(f"  [{verdict}] read outside scope ({args.other_adom}): "
              f"{'refused' if denied else 'ALLOWED'}")
    return 1 if any(f.level == "FAIL" for f in findings) or denied is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
