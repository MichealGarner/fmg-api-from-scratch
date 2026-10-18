import json
import tempfile
import unittest
from pathlib import Path

import fmg_install as inst
from fmg_client import FMGError

DIFF = "=== Preview result ===\nconfig system dns\n set domain \"lab.test\"\nend"


def message(text=DIFF):
    return json.dumps([{"name": "D", "oid": 206, "result": text}])


class Fake:
    """Scripted FMG: records every call so tests can assert on what was sent."""
    def __init__(self, diff_text=DIFF, task_state=4, commit_state=4):
        self.calls, self.diff_text = [], diff_text
        self.task_state, self.commit_state, self.n = task_state, commit_state, 100

    def get(self, url, **extra):
        self.calls.append(("get", url))
        if url == "/dvmdb/adom/A":
            return {"oid": 169}
        if url == "/dvmdb/adom/A/device":
            return [{"name": "D", "oid": 206, "vdom": [{"name": "root", "oid": 3}]}]
        if url.startswith("/task/task/"):
            tid = int(url.rsplit("/", 1)[1])
            return {"state": self.commit_state if tid in self.commit_ids else self.task_state}
        raise AssertionError(url)

    commit_ids: set = set()

    def execute(self, url, data=None, **extra):
        self.calls.append(("exec", url, data))
        if url == "/securityconsole/preview/result":
            return {"data": {"message": message(self.diff_text)}}
        if url == "/securityconsole/package/cancel/install":
            return {}
        self.n += 1
        if url == "/securityconsole/package/commit":
            self.commit_ids = self.commit_ids | {self.n}
        return {"data": {"task": self.n}}

    def urls(self, kind="exec"):
        return [c[1] for c in self.calls if c[0] == kind]


class ParseTests(unittest.TestCase):
    def test_diff_text(self):
        self.assertIn("lab.test", inst.parse_preview(message()))

    def test_no_result_is_empty(self):
        self.assertEqual(inst.parse_preview(message("=== No preview result ===")), "")

    def test_not_json(self):
        with self.assertRaises(RuntimeError):
            inst.parse_preview("nope")


class ResolveTests(unittest.TestCase):
    def test_numeric_scope(self):
        self.assertEqual(inst.resolve(Fake(), "A", "D"), (169, [{"oid": 206, "vdom_oid": 3}]))


class PreviewTests(unittest.TestCase):
    def test_never_commits_and_always_cancels(self):
        f = Fake()
        r = inst.preview(f, "A", "D")
        self.assertNotIn("/securityconsole/package/commit", f.urls())
        self.assertEqual(f.urls()[-1], "/securityconsole/package/cancel/install")
        self.assertEqual(r["sha256"], inst.diff_hash(r["diff"]))

    def test_sequence_and_numeric_scope(self):
        f = Fake()
        inst.preview(f, "A", "D")
        self.assertEqual(f.urls(), ["/securityconsole/package/cancel/install",
                                    "/securityconsole/install/device",
                                    "/securityconsole/install/preview",
                                    "/securityconsole/preview/result",
                                    "/securityconsole/package/cancel/install"])
        sent = [c[2] for c in f.calls if c[0] == "exec" and c[1].endswith("install/device")][0]
        self.assertEqual(sent["adom"], 169)
        self.assertEqual(sent["scope"], [{"oid": 206, "vdom_oid": 3}])

    def test_cancels_even_when_a_task_fails(self):
        f = Fake(task_state=5)
        with self.assertRaises(RuntimeError):
            inst.preview(f, "A", "D")
        self.assertEqual(f.urls()[-1], "/securityconsole/package/cancel/install")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def approve(self, diff=DIFF, now=1000.0):
        f = Fake(diff)
        inst.write_marker(self.dir, inst.preview(f, "A", "D"), now=now)

    def test_no_marker_no_install(self):
        f = Fake()
        with self.assertRaises(inst.InstallRefused):
            inst.install(f, "A", "D", self.dir)
        self.assertEqual(f.calls, [])

    def test_empty_diff_writes_no_marker(self):
        f = Fake("=== No preview result ===")
        self.assertIsNone(inst.write_marker(self.dir, inst.preview(f, "A", "D")))

    def test_expired_marker(self):
        self.approve(now=1000.0)
        with self.assertRaises(inst.InstallRefused):
            inst.install(Fake(), "A", "D", self.dir, now=1000.0 + inst.MARKER_MAX_AGE + 1)

    def test_changed_diff_is_refused_and_not_committed(self):
        self.approve()
        f = Fake(DIFF + "\nconfig system ntp\nend")
        with self.assertRaises(inst.InstallRefused):
            inst.install(f, "A", "D", self.dir, now=1001.0)
        self.assertNotIn("/securityconsole/package/commit", f.urls())
        self.assertEqual(f.urls()[-1], "/securityconsole/package/cancel/install")

    def test_matching_diff_commits_once_and_consumes_marker(self):
        self.approve()
        f = Fake()
        out = inst.install(f, "A", "D", self.dir, now=1001.0)
        self.assertTrue(out["ok"])
        self.assertEqual(f.urls().count("/securityconsole/package/commit"), 1)
        self.assertFalse(inst.marker_path(self.dir, "D").exists())
        with self.assertRaises(inst.InstallRefused):
            inst.install(Fake(), "A", "D", self.dir, now=1002.0)

    def test_failed_commit_reported(self):
        self.approve()
        out = inst.install(Fake(commit_state=5), "A", "D", self.dir, now=1001.0)
        self.assertFalse(out["ok"])


if __name__ == "__main__":
    unittest.main()
