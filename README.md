# fmg-api-from-scratch

Code for the "FMG API From Scratch" series on [michealgarner.co.uk](https://michealgarner.co.uk):
driving FortiManager's JSON-RPC API from a first call to a tool that pushes, stages,
previews and installs CLI scripts, and refuses to install anything it has not shown you.

Each part of the series is a git tag. Check out the tag that matches the post you are reading.

| Tag | Adds |
|---|---|
| `part-03` | `fmg_client.py`, `examples/first_call.py`: login, read, logout, every status checked |
| `part-04` | `fmg_audit.py`, `fmg_redact.py`, `examples/check_scope.py`, `examples/untrusted_login.py`: audit the API account, prove its fences, pin a certificate |
| `part-05` | `fmg_discover.py`, `examples/discover.py`: survey the box by shape, never by value |
| `part-06` | `fmg_scripts.py`, `examples/script_demo.py`: render Jinja locally, push and stage a CLI script |
| `part-07` | `fmg_logs.py`: poll the task, read the log by its id, see what changed |
| `part-08` | `fmg_install.py`: preview the diff, install only what you previewed |
| `part-09` | `fmg_push.py`: the command that ties it together, with an audit trail |

Tested against FortiManager 7.6.6, and `fmg_push.py` refuses any other major.minor.
Some endpoints used later in the series are undocumented and may change between releases.

## Quick start

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    python -m unittest                         # no FortiManager needed
    cp .env.example .env                       # then edit it
    python examples/first_call.py --device MY-FORTIGATE

## The finished tool (`part-09`)

Every command is a dry run unless it has `--apply`. Options that apply to every
command (`--env-file`, `--adom`, `--audit`) go before the command name.

    python fmg_push.py devices
    python fmg_push.py push    --template dns.j2 --vars vars.json --device MY-FORTIGATE
    python fmg_push.py push    --template dns.j2 --vars vars.json --device MY-FORTIGATE --apply
    python fmg_push.py stage   --script dns__MY-FORTIGATE --device MY-FORTIGATE \
                               --watch /pm/config/device/MY-FORTIGATE/global/system/dns --apply
    python fmg_push.py log     --device MY-FORTIGATE --show
    python fmg_push.py preview --device MY-FORTIGATE
    python fmg_push.py install --device MY-FORTIGATE --apply

`install` runs only if a `preview` of the same device was made in the last 30 minutes
and the diff it rebuilds still matches the one you were shown.

## Safety notes

* The rendered CLI, the preview diff and the script log can all contain secrets
  (pre-shared keys, passwords). `log --show` and `preview` print them on purpose; nothing
  else does, and the audit file (`fmg_push_audit.jsonl`) holds only hashes and sizes.
* Keep your variables file and `.env` out of the repository. Do not commit `.env`.
* Use a dedicated API account built up from nothing, limited to one ADOM and one source
  address. Part 4 shows how to audit it with `examples/check_scope.py`.
* Do not leave TLS verification off. Pin the certificate fingerprint or issue a proper one.
* Lockout is by source address on a default FortiManager. Never retry a failed login in a loop.
* `install` changes a live device. Try everything on a lab unit first.
