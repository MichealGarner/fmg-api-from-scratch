"""fmg_audit.py - judge a FortiManager API account from its own records.

Pure functions: give them the dicts FortiManager returned (read with
verbose=True so enums are words) and get findings back. No network here,
which is what makes them testable.
"""
from __future__ import annotations

from typing import Any, NamedTuple

FAIL, WARN, OK, INFO = "FAIL", "WARN", "OK", "INFO"

# Profile permissions that an automation account for pushing config should
# not need. Anything other than none/disable on these is reported.
SENSITIVE_PERMISSIONS = (
    "super-user-profile", "adom-admin", "system-setting", "term-access",
    "fgd_center", "fgd-center-advanced", "fgd-center-fmw-mgmt",
    "fgd-center-licensing", "device-revision-deletion",
)
_OFF = ("none", "disable")
_UNSET_HOSTS = ("0.0.0.0", "255.255.255.255")


class Finding(NamedTuple):
    level: str
    item: str
    detail: str


def _trusted_hosts(user: dict[str, Any]) -> list[tuple[str, str]]:
    hosts = []
    for n in range(1, 11):
        pair = user.get(f"trusthost{n}")
        if isinstance(pair, list) and len(pair) == 2 and pair[0] not in _UNSET_HOSTS:
            hosts.append((pair[0], pair[1]))
    return hosts


def audit(user: dict | None, profile: dict | None,
          glob: dict | None = None, setting: dict | None = None,
          max_api_idle: int = 1800) -> list[Finding]:
    out: list[Finding] = []

    if user is None:
        out.append(Finding(INFO, "account record", "not readable by this account"))
    else:
        if user.get("profileid") == "Super_User":
            out.append(Finding(FAIL, "admin profile", "account uses Super_User"))
        if user.get("adom-access") != "specify":
            out.append(Finding(FAIL, "ADOM scope", f"adom-access is {user.get('adom-access')!r}, not 'specify'"))
        else:
            adoms = [a.get("adom-name") for a in user.get("adom") or []]
            level = OK if len(adoms) == 1 else WARN
            out.append(Finding(level, "ADOM scope", f"{len(adoms)} ADOM(s): {', '.join(map(str, adoms))}"))
        hosts = _trusted_hosts(user)
        if not hosts:
            out.append(Finding(FAIL, "trusted hosts", "none set: any source address may log in"))
        elif any(mask != "255.255.255.255" for _, mask in hosts):
            out.append(Finding(WARN, "trusted hosts", "at least one entry is a subnet, not a single host"))
        else:
            out.append(Finding(OK, "trusted hosts", f"{len(hosts)} single host(s)"))
        out.append(Finding(INFO, "JSON API access", f"rpc-permit is {user.get('rpc-permit')!r}"))

    if profile is None:
        out.append(Finding(INFO, "profile record", "not readable by this account"))
    else:
        broad = [f"{p}={profile[p]}" for p in SENSITIVE_PERMISSIONS
                 if p in profile and profile[p] not in _OFF]
        # write-passwd-access only means something when change-password is on;
        # otherwise it is a dormant default (the CLI will not even accept it).
        if profile.get("change-password") == "enable" and profile.get("write-passwd-access") not in (None, *_OFF):
            broad.append(f"write-passwd-access={profile['write-passwd-access']}")
        if broad:
            out.append(Finding(WARN, "profile permissions", "beyond a push account's needs: " + ", ".join(broad)))
        else:
            out.append(Finding(OK, "profile permissions", "no sensitive permissions granted"))

    if glob is not None:
        if glob.get("jsonapi-log") in (None, "disable"):
            out.append(Finding(WARN, "API logging", "jsonapi-log is disabled: API calls are not logged"))
        else:
            out.append(Finding(OK, "API logging", f"jsonapi-log is {glob['jsonapi-log']}"))
        threshold = glob.get("admin-lockout-threshold")
        if threshold:
            out.append(Finding(INFO, "lockout", f"{threshold} failures, by {glob.get('admin-lockout-method')}"))
        else:
            out.append(Finding(WARN, "lockout", "no lockout threshold set"))

    if setting is not None:
        idle = setting.get("idle_timeout_api")
        if isinstance(idle, int) and idle > max_api_idle:
            out.append(Finding(WARN, "API idle timeout", f"{idle}s is longer than {max_api_idle}s"))
        elif isinstance(idle, int):
            out.append(Finding(OK, "API idle timeout", f"{idle}s"))
    return out
