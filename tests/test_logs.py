import unittest

from fmg_client import FMGShapeError
from fmg_logs import (TASK_FAILED, TASK_OK, changed_keys, latest_log, log_id_for_task,
                      succeeded, summary_newest, wait_for_task)


class Fake:
    def __init__(self, routes):
        self.routes, self.asked = routes, []

    def get(self, url, **extra):
        self.asked.append(url)
        if url not in self.routes:
            raise FMGShapeError("no data", url)
        return self.routes[url]


S = "/dvmdb/adom/A/script/log/summary/device/D"
O = "/dvmdb/adom/A/script/log/output/device/D/logid/"


class LogTests(unittest.TestCase):
    def test_log_id_follows_task_id(self):
        self.assertEqual(log_id_for_task(127), 1271)
        self.assertEqual(log_id_for_task(127, real_device=True), 1270)

    def test_newest_is_highest_log_id_not_first_or_seq(self):
        fake = Fake({S: [{"log_id": 801, "seq": 9}, {"log_id": 1271, "seq": 1}, {"log_id": 1121, "seq": 5}],
                     O + "1271": {"log_id": 1271, "content": "new"}})
        self.assertEqual(latest_log(fake, "A", "D")["content"], "new")

    def test_never_uses_latest_endpoint(self):
        fake = Fake({S: [{"log_id": 5}], O + "5": {"log_id": 5}})
        latest_log(fake, "A", "D")
        self.assertFalse(any("/log/latest" in u for u in fake.asked))

    def test_explicit_log_id_skips_summary(self):
        fake = Fake({O + "1271": {"log_id": 1271}})
        self.assertEqual(latest_log(fake, "A", "D", 1271)["log_id"], 1271)
        self.assertEqual(fake.asked, [O + "1271"])

    def test_no_runs_is_none(self):
        self.assertIsNone(latest_log(Fake({}), "A", "D"))

    def test_summary_newest_suffix_match(self):
        s = [{"log_id": 3, "script_name": "x__d"}, {"log_id": 9, "script_name": "y__D"}]
        self.assertEqual(summary_newest(s, "D"), 9)


class TaskFake:
    def __init__(self, states):
        self.states, self.polls = list(states), 0

    def get(self, url, **extra):
        self.polls += 1
        return {"state": self.states.pop(0) if len(self.states) > 1 else self.states[0]}


class WaitTests(unittest.TestCase):
    def test_polls_through_non_terminal_states_then_stops(self):
        f = TaskFake([0, 1, 2, TASK_OK])
        slept = []
        out = wait_for_task(f, 7, sleep=slept.append, interval=1)
        self.assertEqual((out["state"], f.polls, len(slept)), (TASK_OK, 4, 3))

    def test_failed_task_is_terminal_and_not_success(self):
        out = wait_for_task(TaskFake([TASK_FAILED]), 7, sleep=lambda s: None)
        self.assertEqual(out["state"], TASK_FAILED)
        self.assertFalse(succeeded(out))
        self.assertTrue(succeeded({"state": TASK_OK}))

    def test_task_that_never_finishes_raises_instead_of_hanging(self):
        with self.assertRaises(TimeoutError):
            wait_for_task(TaskFake([1]), 7, timeout=5, interval=2, sleep=lambda s: None)


class ChangedKeysTests(unittest.TestCase):
    def test_reports_names_not_values(self):
        out = changed_keys({"a": "SECRET-1", "b": 1}, {"a": "SECRET-2", "b": 1, "c": "SECRET-3"})
        self.assertEqual(out, ["a", "c"])
        self.assertNotIn("SECRET", " ".join(out))

    def test_no_change_is_empty(self):
        self.assertEqual(changed_keys({"a": 1}, {"a": 1}), [])

    def test_non_dict_values(self):
        self.assertEqual(changed_keys("x", "x"), [])
        self.assertEqual(changed_keys("x", "y"), ["(whole value)"])


if __name__ == "__main__":
    unittest.main()
