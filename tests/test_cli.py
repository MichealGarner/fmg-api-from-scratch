import contextlib
import io
import unittest
from unittest import mock

import fmg_push
from tests.test_install import Fake


class DryRunTests(unittest.TestCase):
    def args(self, **kw):
        ns = fmg_push.build_parser().parse_args(["install", "--device", "D"])
        ns.adom, ns.audit = "A", "/dev/null"
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_install_without_apply_sends_nothing(self):
        f = Fake()
        with contextlib.redirect_stdout(io.StringIO()):
            code = fmg_push.cmd_install(f, self.args())
        self.assertEqual(code, 0)
        self.assertEqual(f.calls, [])

    def test_install_without_preview_is_refused(self):
        f = Fake()
        with mock.patch.object(fmg_push, "STATE_DIR", __import__("pathlib").Path("/nonexistent-fmg")):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = fmg_push.cmd_install(f, self.args(apply=True))
            self.assertEqual(code, 2)
        self.assertNotIn("/securityconsole/package/commit", f.urls())

    def test_parser_knows_preview_and_install(self):
        p = fmg_push.build_parser()
        self.assertEqual(p.parse_args(["preview", "--device", "D"]).command, "preview")
        self.assertEqual(p.parse_args(["install", "--device", "D", "--apply"]).apply, True)


if __name__ == "__main__":
    unittest.main()
