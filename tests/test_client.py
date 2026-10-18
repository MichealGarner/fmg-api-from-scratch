"""Tests for fmg_client.py. No network and no FortiManager needed.

The canned responses below are shaped like real responses captured from a
FortiManager 7.6.6 lab (values sanitised).  Run with:

    python -m unittest -v
"""
import unittest
import warnings

import requests

from fmg_client import FMGClient, FMGError, FMGShapeError


def ok(url, data=None, **top):
    result = {"status": {"code": 0, "message": "OK"}, "url": url}
    if data is not None:
        result["data"] = data
    return {"id": 1, "result": [result], **top}


def failed(url, code, message):
    return {"id": 1, "result": [{"status": {"code": code, "message": message}, "url": url}]}


LOGIN_OK = ok("/sys/login/user", session="SESSION-TOKEN")
LOGIN_FAIL = failed("/sys/login/user", -22, "Login fail")
NO_PERMISSION = failed("/pm/config/device/DEV/global/system/dns", -11,
                       "No permission for the resource")
LOGOUT_OK = ok("/sys/logout")
DNS_OK = ok("/pm/config/device/DEV/global/system/dns",
            {"primary": "192.0.2.53", "secondary": "198.51.100.53",
             "domain": ["lab.local"], "protocol": 1, "oid": 153})
# Status 0 but no data key at all: what a non-existent endpoint returned on the real box.
OK_NO_DATA = ok("/dvmdb/adom/A/script/log/latest/device/DEV")


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeHTTP:
    """Stands in for requests.Session: replays canned responses, records what was sent."""

    def __init__(self, *responses):
        self.queue = [r if isinstance(r, FakeResponse) else FakeResponse(r) for r in responses]
        self.sent = []

    def post(self, url, json=None, timeout=None):
        self.sent.append(json)
        return self.queue.pop(0)


def logged_in_client(*more):
    http = FakeHTTP(LOGIN_OK, *more)
    client = FMGClient("fmg.example", http=http)
    client.login("svc-api", "s3cret-password")
    return client, http


class LoginTests(unittest.TestCase):
    def test_login_sends_expected_body_and_keeps_session(self):
        client, http = logged_in_client()
        body = http.sent[0]
        self.assertEqual(body["method"], "exec")
        self.assertEqual(body["params"][0]["url"], "/sys/login/user")
        self.assertEqual(body["params"][0]["data"]["user"], "svc-api")
        self.assertNotIn("session", body)          # nothing to send before login
        self.assertIn("logged_in=True", repr(client))

    def test_failed_login_raises_even_though_http_was_200(self):
        http = FakeHTTP(FakeResponse(LOGIN_FAIL, status_code=200))
        client = FMGClient("fmg.example", http=http)
        with self.assertRaises(FMGError) as cm:
            client.login("svc-api", "wrong")
        self.assertEqual(cm.exception.code, -22)
        self.assertIn("logged_in=False", repr(client))

    def test_password_never_appears_in_errors_or_repr(self):
        http = FakeHTTP(LOGIN_FAIL)
        client = FMGClient("fmg.example", http=http)
        with self.assertRaises(FMGError) as cm:
            client.login("svc-api", "hunter2-super-secret")
        self.assertNotIn("hunter2-super-secret", str(cm.exception))
        self.assertNotIn("hunter2-super-secret", repr(client))

    def test_login_ok_but_no_session_token_is_an_error(self):
        http = FakeHTTP(ok("/sys/login/user"))      # status 0, no session
        client = FMGClient("fmg.example", http=http)
        with self.assertRaises(FMGShapeError):
            client.login("svc-api", "pw")


class ReadTests(unittest.TestCase):
    def test_get_returns_data_and_sends_session(self):
        client, http = logged_in_client(DNS_OK)
        data = client.get("/pm/config/device/DEV/global/system/dns")
        self.assertEqual(data["primary"], "192.0.2.53")
        self.assertEqual(http.sent[1]["session"], "SESSION-TOKEN")
        self.assertEqual(http.sent[1]["method"], "get")

    def test_get_before_login_sends_nothing(self):
        http = FakeHTTP()
        client = FMGClient("fmg.example", http=http)
        with self.assertRaises(FMGError) as cm:
            client.get("/sys/status")
        self.assertIsNone(cm.exception.code)
        self.assertEqual(http.sent, [])

    def test_status_zero_without_data_is_not_trusted(self):
        client, _ = logged_in_client(OK_NO_DATA)
        with self.assertRaises(FMGShapeError):
            client.get("/dvmdb/adom/A/script/log/latest/device/DEV")

    def test_non_zero_status_raises_with_code(self):
        client, _ = logged_in_client(NO_PERMISSION)
        with self.assertRaises(FMGError) as cm:
            client.get("/pm/config/device/DEV/global/system/dns")
        self.assertEqual(cm.exception.code, -11)

    def test_http_error_is_raised_as_such(self):
        client, _ = logged_in_client(FakeResponse({}, status_code=500))
        with self.assertRaises(requests.HTTPError):
            client.get("/sys/status")

    def test_empty_result_list_is_a_shape_error(self):
        client, _ = logged_in_client({"id": 2, "result": []})
        with self.assertRaises(FMGShapeError):
            client.get("/sys/status")

    def test_request_ids_increase(self):
        client, http = logged_in_client(DNS_OK, DNS_OK)
        client.get("/a")
        client.get("/b")
        self.assertEqual([b["id"] for b in http.sent], [1, 2, 3])


class LogoutTests(unittest.TestCase):
    def test_logout_clears_session(self):
        client, _ = logged_in_client(LOGOUT_OK)
        client.logout()
        self.assertIn("logged_in=False", repr(client))

    def test_logout_without_login_is_a_no_op(self):
        http = FakeHTTP()
        FMGClient("fmg.example", http=http).logout()
        self.assertEqual(http.sent, [])

    def test_context_manager_logs_out_even_when_body_raises(self):
        http = FakeHTTP(LOGIN_OK, LOGOUT_OK)
        with self.assertRaises(ValueError):
            with FMGClient("fmg.example", http=http) as client:
                client.login("svc-api", "pw")
                raise ValueError("something in my own code went wrong")
        self.assertEqual(http.sent[-1]["params"][0]["url"], "/sys/logout")

    def test_logout_failure_does_not_hide_the_original_exception(self):
        http = FakeHTTP(LOGIN_OK, failed("/sys/logout", -11, "No permission"))
        with self.assertRaises(ValueError):
            with FMGClient("fmg.example", http=http) as client:
                client.login("svc-api", "pw")
                raise ValueError("original problem")


class TlsTests(unittest.TestCase):
    def test_verification_is_on_by_default(self):
        client = FMGClient("fmg.example")
        self.assertIs(client._http.verify, True)

    def test_disabling_verification_warns(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            client = FMGClient("fmg.example", verify=False)
        self.assertIs(client._http.verify, False)
        self.assertTrue(any("TLS verification" in str(w.message) for w in caught))

    def test_ca_bundle_path_is_accepted(self):
        client = FMGClient("fmg.example", verify="/etc/ssl/certs/lab-ca.pem")
        self.assertEqual(client._http.verify, "/etc/ssl/certs/lab-ca.pem")


if __name__ == "__main__":
    unittest.main()
