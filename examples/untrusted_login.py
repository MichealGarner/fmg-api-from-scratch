#!/usr/bin/env python3
"""Make exactly ONE login attempt, to prove a trusted-host fence holds.

    python examples/untrusted_login.py FMG_HOST USER

Run it from a machine that is NOT in the account's trusted hosts. The password
is asked for without echo and never printed. It is a single attempt on purpose:
lockout is by source IP, so retrying would lock out that machine.

Standard library only, so it runs on a host that has nothing installed.
Prints the HTTP status and the JSON status, because a refused login is still
HTTP 200 and the refusal is only in the JSON.
"""
import getpass
import json
import ssl
import sys
import urllib.request


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    host, user = sys.argv[1], sys.argv[2]
    body = {"id": 1, "method": "exec", "params": [{"url": "/sys/login/user",
            "data": {"user": user, "passwd": getpass.getpass(f"Password for {user}: ")}}]}
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE        # lab only: this is a fence test, not a client
    req = urllib.request.Request(f"https://{host}/jsonrpc", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        payload = json.load(resp)
        status = payload["result"][0]["status"]
        print(f"HTTP status {resp.status}; JSON status code {status['code']} ({status['message']}); "
              f"session issued: {'session' in payload}")
    if "session" in payload:        # do not leave a session open
        out = {"id": 2, "method": "exec", "session": payload["session"],
               "params": [{"url": "/sys/logout"}]}
        urllib.request.urlopen(urllib.request.Request(f"https://{host}/jsonrpc", json.dumps(out).encode(),
                                                      {"Content-Type": "application/json"}),
                               context=ctx, timeout=15).read()
    return 0


if __name__ == "__main__":
    sys.exit(main())
