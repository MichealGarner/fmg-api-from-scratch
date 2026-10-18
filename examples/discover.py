#!/usr/bin/env python3
"""Read-only discovery: probe a list of endpoints and report what each one is.

    python examples/discover.py --adom LAB --device <device-name>   (both optional)
    python examples/discover.py --path /dvmdb/adom/LAB/device
    python examples/discover.py --parse captured.txt        # offline, no login

Output shows shapes (types, counts, field names), never values.
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv                       # noqa: E402

from fmg_client import FMGClient, FMGError           # noqa: E402
from fmg_discover import (CANDIDATES, endpoints_from_bodies,   # noqa: E402
                          fields_filter_honoured, probe)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from first_call import tls_settings                  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file")
    ap.add_argument("--adom", help="default: the first ADOM this account can see")
    ap.add_argument("--device", help="default: the first device in that ADOM")
    ap.add_argument("--path", action="append", help="probe this URL instead of the built-in list")
    ap.add_argument("--fields-test", metavar="URL", help="check whether `fields` is honoured here ({adom}/{device} allowed)")
    ap.add_argument("--parse", metavar="FILE", help="list endpoints in copied request bodies (offline)")
    args = ap.parse_args()

    if args.parse:
        for method, url in endpoints_from_bodies(Path(args.parse).read_text()):
            print(f"{method:<7} {url}")
        return 0

    load_dotenv(args.env_file or Path(__file__).resolve().parent.parent / ".env")
    if tls_settings().get("verify") is False:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        host, user, password = (os.environ[k] for k in ("FMG_HOST", "FMG_USER", "FMG_PASSWORD"))
    except KeyError as missing:
        print(f"Missing {missing}", file=sys.stderr)
        return 2

    try:
        with FMGClient(host, **tls_settings()) as fmg:
            fmg.login(user, password)
            adom = args.adom or fmg.get("/dvmdb/adom")[0]["name"]
            device = args.device or fmg.get(f"/dvmdb/adom/{adom}/device")[0]["name"]
            print(f"(using ADOM and device chosen automatically: {adom!r}, {device!r})"
                  if not (args.adom and args.device) else "")
            urls = args.path or [t.format(adom=adom, device=device) for _, t in CANDIDATES]
            for url in urls:
                print(probe(fmg, url).line())
            if args.fields_test:
                url = args.fields_test.format(adom=adom, device=device)
                print(f"`fields` honoured on {url}: {fields_filter_honoured(fmg, url, 'name')}")
    except FMGError as err:
        print(f"Stopped: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
