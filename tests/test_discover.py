import unittest

from fmg_client import FMGError, FMGShapeError
from fmg_discover import endpoints_from_bodies, fields_filter_honoured, probe, shape


class Fake:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.asked = result, error, []

    def get(self, url, **extra):
        self.asked.append((url, extra))
        if self.error:
            raise self.error
        return self.result


class ShapeTests(unittest.TestCase):
    def test_list_reports_count_and_keys_not_values(self):
        out = shape([{"name": "SECRET-DEVICE", "ip": "10.1.1.1"}] * 3)
        self.assertIn("3 items", out)
        self.assertIn("ip, name", out)
        self.assertNotIn("SECRET", out)
        self.assertNotIn("10.1.1.1", out)

    def test_object_and_empty(self):
        self.assertEqual(shape({"b": 1, "a": 2}), "object; keys: a, b")
        self.assertEqual(shape([]), "list, 0 items")


class ProbeTests(unittest.TestCase):
    def test_data(self):
        self.assertEqual(probe(Fake([{"name": "x"}]), "/u").kind, "data")

    def test_no_data_is_not_success(self):
        self.assertEqual(probe(Fake(error=FMGShapeError("no data", "/u")), "/u").kind, "empty")

    def test_denied_missing_and_other(self):
        self.assertEqual(probe(Fake(error=FMGError(-11, "no perm", "/u")), "/u").kind, "denied")
        self.assertEqual(probe(Fake(error=FMGError(-3, "gone", "/u")), "/u").kind, "missing")
        self.assertEqual(probe(Fake(error=FMGError(-9, "odd", "/u")), "/u").kind, "error")


class FieldsTests(unittest.TestCase):
    def test_honoured(self):
        self.assertTrue(fields_filter_honoured(Fake([{"name": "a"}]), "/u", "name"))

    def test_ignored(self):
        self.assertFalse(fields_filter_honoured(Fake([{"name": "a", "ip": "b"}]), "/u", "name"))

    def test_nothing_returned(self):
        self.assertIsNone(fields_filter_honoured(Fake([]), "/u", "name"))


class CaptureTests(unittest.TestCase):
    BODY = ('{"id":3,"method":"get","params":[{"url":"/dvmdb/adom"}],"session":"TOKEN"}')

    def test_single_body_drops_token(self):
        self.assertEqual(endpoints_from_bodies(self.BODY), [("get", "/dvmdb/adom")])

    def test_one_per_line_and_dedupe(self):
        text = self.BODY + "\n" + self.BODY + '\n{"method":"exec","params":[{"url":"/x/y"}]}'
        self.assertEqual(endpoints_from_bodies(text),
                         [("get", "/dvmdb/adom"), ("exec", "/x/y")])

    def test_list_and_junk(self):
        self.assertEqual(endpoints_from_bodies('[{"method":"set","params":[{"url":"/a"}]}, 5]'),
                         [("set", "/a")])
        self.assertEqual(endpoints_from_bodies("not json"), [])


if __name__ == "__main__":
    unittest.main()
