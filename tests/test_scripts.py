import unittest

import jinja2

from fmg_scripts import EXECUTE_URL, SCRIPT_URL, push, render, script_object, stage


class RenderTests(unittest.TestCase):
    def test_renders(self):
        self.assertEqual(render("set domain {{ d }}", {"d": "x"}), "set domain x")

    def test_missing_variable_is_an_error_not_blank(self):
        with self.assertRaises(jinja2.UndefinedError):
            render("set domain {{ d }}", {})


class ObjectTests(unittest.TestCase):
    def test_script_targets_device_database_as_cli(self):
        o = script_object("n", "config x", "d")
        self.assertEqual((o["type"], o["target"]), ("cli", "device_database"))


class Fake:
    def __init__(self, stored=None, task=7):
        self.stored, self.task, self.calls = stored, task, []

    def set(self, url, data, **extra):
        self.calls.append(("set", url, data))
        return {}

    def get(self, url, **extra):
        self.calls.append(("get", url))
        return self.stored

    def execute(self, url, data=None, **extra):
        self.calls.append(("exec", url, data))
        return {"data": {"task": self.task}} if self.task is not None else {}


class PushTests(unittest.TestCase):
    def test_reads_back_after_set(self):
        f = Fake([{"name": "n", "type": "cli", "target": "device_database"}])
        push(f, "A", "n", "config x")
        self.assertEqual([c[0] for c in f.calls], ["set", "get"])
        self.assertEqual(f.calls[0][1], SCRIPT_URL.format(adom="A"))

    def test_unrecognised_target_that_was_silently_coerced_is_caught(self):
        f = Fake([{"name": "n", "type": "cli", "target": "adomdb"}])
        with self.assertRaises(RuntimeError):
            push(f, "A", "n", "config x")

    def test_missing_after_set_is_caught(self):
        with self.assertRaises(RuntimeError):
            push(Fake([]), "A", "n", "config x")


class StageTests(unittest.TestCase):
    def test_scope_uses_global_vdom(self):
        f = Fake()
        self.assertEqual(stage(f, "A", "s", "D"), 7)
        _, url, body = f.calls[0]
        self.assertEqual(url, EXECUTE_URL.format(adom="A"))
        self.assertEqual(body["scope"], [{"name": "D", "vdom": "global"}])

    def test_no_task_id_is_an_error(self):
        with self.assertRaises(RuntimeError):
            stage(Fake(task=None), "A", "s", "D")


if __name__ == "__main__":
    unittest.main()
