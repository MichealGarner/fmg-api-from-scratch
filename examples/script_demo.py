#!/usr/bin/env python3
"""Push a harmless scratch script, read it back, test set-as-merge, delete it.

    python examples/script_demo.py --env-file .env [--adom ADOM]

Also compares the script-log endpoints for every device (read-only; log
text is never printed).
Writes only ONE scratch object, and always deletes it.
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv                              # noqa: E402

from fmg_client import FMGClient, FMGError                  # noqa: E402
from fmg_scripts import SCRIPT_URL, push                    # noqa: E402
from first_call import tls_settings                         # noqa: E402

NAME = "zz-api-blog-scratch"


def read_back(fmg, adom):
    rows = fmg.get(SCRIPT_URL.format(adom=adom), verbose=True, filter=["name", "==", NAME])
    if not rows:
        return None
    r = rows[0]
    return {"type": r.get("type"), "target": r.get("target"), "desc": r.get("desc"),
            "content_chars": len(r.get("content") or "")}


def logs(fmg, adom):
    """Compare the script-log endpoints for every device. Read-only; log text is never printed.

    The per-device summary is the reliable one. The 'latest/device' endpoint can
    return an older run than the summary shows, and the ADOM-level summary
    covers ADOM-level runs, not device runs. Run this on your own box and see.
    """
    adom_runs = fmg.get(f"/dvmdb/adom/{adom}/script/log/summary")
    print(f"ADOM-level summary: {len(adom_runs)} entries (ADOM-level runs, not device runs)")
    for dev in [d["name"] for d in fmg.get(f"/dvmdb/adom/{adom}/device")]:
        try:
            runs = fmg.get(f"/dvmdb/adom/{adom}/script/log/summary/device/{dev}")
            newest = max((r["log_id"] for r in runs), default=None)
        except FMGError as err:
            newest = f"no data ({type(err).__name__})"
        try:
            got = fmg.get(f"/dvmdb/adom/{adom}/script/log/latest/device/{dev}").get("log_id")
        except FMGError as err:
            got = f"no data ({type(err).__name__})"
        flag = "  <-- latest endpoint is stale" if (isinstance(newest, int) and isinstance(got, int) and got < newest) else ""
        print(f"  {dev}: per-device summary newest log_id={newest}  latest endpoint log_id={got}{flag}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file")
    ap.add_argument("--adom")
    args = ap.parse_args()
    load_dotenv(args.env_file or Path(__file__).resolve().parent.parent / ".env")
    if tls_settings().get("verify") is False:
        warnings.filterwarnings("ignore")
    host, user, pw = (os.environ[k] for k in ("FMG_HOST", "FMG_USER", "FMG_PASSWORD"))
    with FMGClient(host, **tls_settings()) as fmg:
        fmg.login(user, pw)
        adom = args.adom or fmg.get("/dvmdb/adom")[0]["name"]
        logs(fmg, adom)
        url = SCRIPT_URL.format(adom=adom)
        try:
            push(fmg, adom, NAME, "# scratch object\n", "first description")
            print("after push 1:      ", read_back(fmg, adom))
            fmg.set(url, {"name": NAME, "content": "# scratch object, second push\n# more\n"})
            print("after set (no desc):", read_back(fmg, adom))
        finally:
            try:
                fmg.delete(f"{url}/{NAME}")
            except FMGError as err:
                print("cleanup failed:", err)
        print("after delete:      ", read_back(fmg, adom))
    return 0


if __name__ == "__main__":
    sys.exit(main())
