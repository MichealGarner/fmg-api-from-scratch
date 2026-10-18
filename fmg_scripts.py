"""Push and stage CLI scripts on FortiManager (7.6.5+ script endpoint).

Two steps, kept separate on purpose:
  * push  - create/update a script *object* in the ADOM database. Changes nothing on any device.
  * stage - run that object against ONE device's Device Database. Still nothing on the live device.

Jinja is rendered here, locally. FortiManager only ever receives finished CLI text.
"""
from __future__ import annotations

from typing import Any

import jinja2

SCRIPT_URL = "/pm/config/adom/{adom}/obj/fmg/script"
EXECUTE_URL = "/dvmdb/adom/{adom}/script/execute"


def render(template_text: str, variables: dict[str, Any]) -> str:
    """Render a Jinja template locally. A missing variable is an error, never an empty string."""
    env = jinja2.Environment(undefined=jinja2.StrictUndefined,
                             trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    return env.from_string(template_text).render(**variables)


def script_object(name: str, content: str, desc: str = "") -> dict:
    """The body of a script object that can be run against a Device Database."""
    return {"name": name, "type": "cli", "target": "device_database",
            "content": content, "desc": desc}


def push(fmg, adom: str, name: str, content: str, desc: str = "") -> None:
    """Create or update the script object, then read it back and check it.

    The server silently turns an unrecognised `target` into the default, so a
    successful `set` proves nothing about what was stored.
    """
    url = SCRIPT_URL.format(adom=adom)
    fmg.set(url, script_object(name, content, desc))
    rows = fmg.get(url, verbose=True, filter=["name", "==", name])
    if not rows:
        raise RuntimeError(f"script {name!r} not found after set")
    row = rows[0]
    if row.get("type") != "cli" or row.get("target") in ("adomdb", 2):
        raise RuntimeError(
            f"script {name!r} was stored as type={row.get('type')!r}, "
            f"target={row.get('target')!r}; expected a CLI script for a device database")


def stage(fmg, adom: str, script: str, device: str) -> int:
    """Run `script` against one device's Device Database and return the task id.

    `vdom` must be "global": leaving it out makes FortiManager read `name`
    as a device *group*, not a device.
    """
    body = {"adom": adom, "script": script, "scope": [{"name": device, "vdom": "global"}]}
    result = fmg.execute(EXECUTE_URL.format(adom=adom), body)
    task = (result.get("data") or {}).get("task")
    if task is None:
        raise RuntimeError("script execute returned no task id; nothing was staged")
    return task
