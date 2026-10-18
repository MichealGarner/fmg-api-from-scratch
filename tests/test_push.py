import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import fmg_push
from tests.test_scripts import Fake as ScriptFake

SECRET = "s3cr3t-psk-value"


class Fake(ScriptFake):
    """Script fake plus task state and a Device Database path that can change."""
    def __init__(self, *a, before=None, after=None, task_state=4, **kw):
        super().__init__(*a, **kw)
        self.values, self.task_state = [before or {}, after or {}], task_state
        self.reads = 0

    def get(self, url, **extra):
        if url.startswith("/task/task/"):
            return {"state": self.task_state}
        if url.startswith("/pm/config/device/"):
            v = self.values[min(self.reads, 1)]
            self.reads += 1
            return v
        return super().get(url, **extra)

    def writes(self):
        return [c for c in self.calls if c[0] in ("set", "exec")]


def run(fn, fmg, argv):
    args = fmg_push.build_parser().parse_args(argv)
    args.adom = "A"
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = fn(fmg, args)
    return code, out.getvalue()


class Workdir(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.tpl = self.dir / "t.j2"
        self.tpl.write_text("config vpn\n set psk {{ psk }}\nend\n")
        self.vars = self.dir / "v.json"
        self.vars.write_text(json.dumps({"psk": SECRET}))
        self.audit = str(self.dir / "audit.jsonl")

    def push_argv(self, *extra, vars_file=None):
        return ["--audit", self.audit, "push", "--template", str(self.tpl),
                "--vars", str(vars_file or self.vars), "--device", "D", *extra]


class PushCommandTests(Workdir):
    def parse(self, argv):
        # global options sit before the command, as in real use
        return fmg_push.build_parser().parse_args(argv)

    def go(self, fn, fmg, argv):
        args = self.parse(argv)
        args.adom = "A"
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = fn(fmg, args)
        return code, out.getvalue()

    def test_dry_run_makes_no_write_and_prints_no_content(self):
        f = Fake([{"name": "n", "type": "cli", "target": "device_database"}])
        code, out = self.go(fmg_push.cmd_push, f, self.push_argv())
        self.assertEqual(code, 0)
        self.assertEqual(f.writes(), [])
        self.assertNotIn(SECRET, out)
        self.assertFalse(Path(self.audit).exists())

    def test_missing_variable_stops_before_any_request(self):
        empty = self.dir / "e.json"
        empty.write_text("{}")
        f = Fake()
        code, out = self.go(fmg_push.cmd_push, f, self.push_argv(vars_file=empty))
        self.assertEqual(code, 2)
        self.assertEqual(f.calls, [])
        self.assertIn("psk", out)

    def test_apply_pushes_and_keeps_secret_out_of_output_and_audit(self):
        f = Fake([{"name": "t__D", "type": "cli", "target": "device_database"}])
        code, out = self.go(fmg_push.cmd_push, f, self.push_argv("--apply"))
        self.assertEqual(code, 0)
        self.assertEqual(len(f.writes()), 1)
        self.assertNotIn(SECRET, out)
        audit = Path(self.audit).read_text()
        self.assertNotIn(SECRET, audit)
        rec = json.loads(audit.splitlines()[0])
        self.assertEqual((rec["action"], len(rec["sha256"])), ("push", 64))

    def stage_argv(self, *extra):
        return ["--audit", self.audit, "stage", "--script", "s", "--device", "D", *extra]

    def test_dry_run_stage_sends_nothing(self):
        f = Fake()
        code, _ = self.go(fmg_push.cmd_stage, f, self.stage_argv())
        self.assertEqual((code, f.calls), (0, []))

    def test_green_task_with_no_change_says_so(self):
        f = Fake(before={"domain": "x"}, after={"domain": "x"})
        code, out = self.go(fmg_push.cmd_stage, f, self.stage_argv("--apply", "--watch", "/pm/config/device/D/global/system/dns"))
        self.assertEqual(code, 0)
        self.assertIn("NONE", out)

    def test_changed_fields_are_named(self):
        f = Fake(before={"domain": "x"}, after={"domain": "y"})
        _, out = self.go(fmg_push.cmd_stage, f, self.stage_argv("--apply", "--watch", "/pm/config/device/D/global/system/dns"))
        self.assertIn("domain", out)

    def test_failed_task_returns_1(self):
        f = Fake(task_state=5)
        code, _ = self.go(fmg_push.cmd_stage, f, self.stage_argv("--apply"))
        self.assertEqual(code, 1)


class SmallFunctionTests(unittest.TestCase):
    def test_audit_record_holds_hash_and_size_never_content(self):
        rec = fmg_push.audit_record("push", "A", "D", "s", f"x {SECRET}\ny\n")
        self.assertNotIn(SECRET, json.dumps(rec))
        self.assertEqual((len(rec["sha256"]), rec["lines"]), (64, 2))

    def test_untested_version_is_refused(self):
        with self.assertRaises(SystemExit):
            fmg_push.check_version({"Major": 7, "Minor": 4})
        fmg_push.check_version({"Major": 7, "Minor": 6})


if __name__ == "__main__":
    unittest.main()
