import unittest

from fmg_audit import FAIL, OK, WARN, audit
from fmg_redact import MASK, redact


def levels(findings, item):
    return [f.level for f in findings if f.item == item]


GOOD_USER = {"profileid": "svc", "adom-access": "specify", "adom": [{"adom-name": "A"}],
             "trusthost1": ["192.0.2.6", "255.255.255.255"], "rpc-permit": "read-write"}


class AuditTests(unittest.TestCase):
    def test_super_user_fails(self):
        self.assertIn(FAIL, levels(audit({**GOOD_USER, "profileid": "Super_User"}, {}), "admin profile"))

    def test_all_adoms_fails(self):
        self.assertIn(FAIL, levels(audit({**GOOD_USER, "adom-access": "all"}, {}), "ADOM scope"))

    def test_no_trusted_host_fails_and_subnet_warns_and_single_host_ok(self):
        self.assertIn(FAIL, levels(audit({**GOOD_USER, "trusthost1": ["0.0.0.0", "0.0.0.0"]}, {}), "trusted hosts"))
        self.assertIn(WARN, levels(audit({**GOOD_USER, "trusthost1": ["192.0.2.0", "255.255.255.0"]}, {}), "trusted hosts"))
        self.assertIn(OK, levels(audit(GOOD_USER, {}), "trusted hosts"))

    def test_sensitive_permission_warns(self):
        self.assertIn(WARN, levels(audit(GOOD_USER, {"system-setting": "read-write"}), "profile permissions"))
        self.assertIn(OK, levels(audit(GOOD_USER, {"system-setting": "none"}), "profile permissions"))

    def test_api_logging_disabled_warns(self):
        self.assertIn(WARN, levels(audit(GOOD_USER, {}, {"jsonapi-log": "disable"}), "API logging"))

    def test_long_api_idle_timeout_warns(self):
        self.assertIn(WARN, levels(audit(GOOD_USER, {}, None, {"idle_timeout_api": 7200}), "API idle timeout"))
        self.assertIn(OK, levels(audit(GOOD_USER, {}, None, {"idle_timeout_api": 900}), "API idle timeout"))

    def test_write_passwd_access_only_counts_when_change_password_is_enabled(self):
        dormant = {"change-password": "disable", "write-passwd-access": "all"}
        live = {"change-password": "enable", "write-passwd-access": "all"}
        self.assertIn(OK, levels(audit(GOOD_USER, dormant), "profile permissions"))
        self.assertIn(WARN, levels(audit(GOOD_USER, live), "profile permissions"))

    def test_no_lockout_threshold_warns(self):
        self.assertIn(WARN, levels(audit(GOOD_USER, {}, {"admin-lockout-threshold": 0}), "lockout"))
        self.assertIn("INFO", levels(audit(GOOD_USER, {}, {"admin-lockout-threshold": 3,
                                                           "admin-lockout-method": "ip"}), "lockout"))

    def test_unreadable_records_are_info_not_a_pass(self):
        out = audit(None, None)
        self.assertEqual({f.level for f in out}, {"INFO"})


class RedactTests(unittest.TestCase):
    def test_masks_by_key_name(self):
        self.assertEqual(redact({"passwd": "hunter2"})["passwd"], MASK)

    def test_masks_by_value_shape_under_an_innocent_key(self):
        self.assertEqual(redact({"note": "ENC abcdefghijklmnop"})["note"], MASK)

    def test_recurses_and_leaves_ordinary_values(self):
        out = redact({"a": [{"psk": "x", "name": "dev"}]})
        self.assertEqual(out["a"][0], {"psk": MASK, "name": "dev"})

    def test_does_not_mutate_input(self):
        src = {"token": "t"}
        redact(src)
        self.assertEqual(src["token"], "t")


if __name__ == "__main__":
    unittest.main()
