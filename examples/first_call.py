#!/usr/bin/env python3
"""First call: log in, read the FortiManager version, read one device's DNS
settings from its Device Database, log out.

    cp .env.example .env      # then edit .env
    python examples/first_call.py --device MY-FORTIGATE

Read-only. Nothing here changes any configuration.
"""
import argparse
import json
import os
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests                         # noqa: E402
from dotenv import load_dotenv          # noqa: E402

from fmg_client import FMGClient, FMGError   # noqa: E402


def tls_settings() -> dict:
    """Strongest setting wins: pinned fingerprint, then CA bundle, then verify
    unless explicitly told not to."""
    fingerprint = os.environ.get("FMG_FINGERPRINT")
    if fingerprint:
        return {"fingerprint": fingerprint}
    bundle = os.environ.get("FMG_CA_BUNDLE")
    if bundle:
        return {"verify": bundle}
    return {"verify": os.environ.get("FMG_VERIFY_SSL", "true").lower() != "false"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device", required=True, help="exact device name as shown in FortiManager")
    args = parser.parse_args()

    load_dotenv()
    if tls_settings().get("verify") is False:
        # FMGClient already warned once; hide urllib3's per-request repeat.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        host = os.environ["FMG_HOST"]
        user = os.environ["FMG_USER"]
        password = os.environ["FMG_PASSWORD"]
    except KeyError as missing:
        print(f"Missing {missing} - copy .env.example to .env and fill it in.", file=sys.stderr)
        return 2

    try:
        with FMGClient(host, **tls_settings()) as fmg:
            fmg.login(user, password)

            status = fmg.get("/sys/status")
            print(f"FortiManager {status['Version']}")

            dns = fmg.get(f"/pm/config/device/{args.device}/global/system/dns")
            print(f"\nDevice Database copy of system dns for {args.device}:")
            print(json.dumps(dns, indent=2))
    except FMGError as err:
        print(f"FortiManager said no: {err}", file=sys.stderr)
        return 1
    except requests.RequestException as err:
        print(f"Could not talk to FortiManager: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
