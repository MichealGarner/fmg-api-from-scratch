"""fmg_client.py - a minimal FortiManager JSON-RPC client.

Rules this client enforces (each one is a lesson from the series):

* HTTP 200 proves nothing. Success or failure lives in the response body,
  so every call checks the status code inside `result[0].status`.
* A status of 0 is necessary, not sufficient. `get()` also insists that a
  `data` key is present, because a guessed endpoint can return "OK" with no
  data at all.
* A failed login stops everything. Nothing is ever sent with an empty session.
* Secrets never appear in exceptions or in repr().
* TLS verification is on by default. Turning it off is explicit and warns.
"""
from __future__ import annotations

import re
import warnings
from typing import Any

import requests
from requests.adapters import HTTPAdapter


class FMGError(RuntimeError):
    """FortiManager answered, but the body reported a failure (or we refused to send)."""

    def __init__(self, code: int | None, message: str, url: str | None = None):
        self.code = code
        self.message = message
        self.url = url
        detail = f"FMG error {code}: {message}" if code is not None else f"FMG client error: {message}"
        if url:
            detail += f" ({url})"
        super().__init__(detail)


class FMGShapeError(FMGError):
    """The status said OK but the response is not shaped the way it should be."""

    def __init__(self, message: str, url: str | None = None):
        super().__init__(None, message, url)


class _PinnedAdapter(HTTPAdapter):
    """Accept exactly one certificate, identified by its SHA-256 fingerprint."""

    def __init__(self, fingerprint: str, **kwargs: Any):
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["assert_fingerprint"] = self._fingerprint
        super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn: Any, url: str, verify: Any, cert: Any) -> None:
        # requests lets REQUESTS_CA_BUNDLE override a session's verify=False,
        # so switch chain checking off here, where nothing can override it.
        super().cert_verify(conn, url, False, cert)


def _clean_fingerprint(value: str) -> str:
    fp = value.replace(":", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fp):
        raise ValueError("fingerprint must be a SHA-256 value: 64 hex characters")
    return fp


class FMGClient:
    def __init__(self, host: str, *, verify: bool | str = True,
                 fingerprint: str | None = None,
                 timeout: float = 30, http: Any = None):
        self.url = f"https://{host}/jsonrpc"
        self.timeout = timeout
        if http is None:
            http = requests.Session()
            if fingerprint:
                # A pinned certificate replaces chain and hostname checks.
                http.mount("https://", _PinnedAdapter(_clean_fingerprint(fingerprint)))
                http.verify = False
            else:
                http.verify = verify
        if verify is False:
            warnings.warn(
                "TLS verification is disabled. Fine for a throwaway lab, "
                "not for anything else.",
                UserWarning,
                stacklevel=2,
            )
        self._http = http
        self._session: str | None = None
        self._id = 0

    def __repr__(self) -> str:
        return f"FMGClient(url={self.url!r}, logged_in={self._session is not None})"

    def __enter__(self) -> "FMGClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Always try to log out, but never let a logout failure hide the
        # exception that got us here.
        try:
            self.logout()
        except (FMGError, requests.RequestException):
            if exc_type is None:
                raise

    def _request(self, method: str, url: str, data: Any = None, *,
                 top: dict | None = None, **extra: Any) -> dict:
        """POST one JSON-RPC request; return the whole payload once its status is OK.

        `extra` goes inside params[0]; `top` goes at the top level of the body.
        """
        self._id += 1
        params: dict[str, Any] = {"url": url}
        if data is not None:
            params["data"] = data
        params.update(extra)

        body: dict[str, Any] = {"id": self._id, "method": method, "params": [params]}
        if self._session:
            body["session"] = self._session
        if top:
            body.update(top)

        resp = self._http.post(self.url, json=body, timeout=self.timeout)
        resp.raise_for_status()          # HTTP-level problems only
        payload = resp.json()

        results = payload.get("result")
        if not results:
            raise FMGShapeError("response has no 'result' list", url)
        status = results[0].get("status", {})
        code = status.get("code")
        if code != 0:                    # the check that actually matters
            raise FMGError(code, status.get("message", "(no message)"),
                           results[0].get("url", url))
        return payload

    def _call(self, method: str, url: str, data: Any = None, *,
              top: dict | None = None, **extra: Any) -> dict:
        return self._request(method, url, data, top=top, **extra)["result"][0]

    def _require_login(self, url: str) -> None:
        if not self._session:
            raise FMGError(None, "not logged in - call login() first", url)

    def login(self, user: str, password: str) -> None:
        payload = self._request("exec", "/sys/login/user",
                                data={"user": user, "passwd": password})
        session = payload.get("session")
        if not session:
            raise FMGShapeError("login reported success but returned no session token",
                                "/sys/login/user")
        self._session = session

    def logout(self) -> None:
        if not self._session:
            return
        try:
            self._call("exec", "/sys/logout")
        finally:
            self._session = None

    def get(self, url: str, *, verbose: bool = False, **extra: Any) -> Any:
        """Read. Returns the `data` block; raises if it is missing.

        verbose=True asks for enum values as CLI names ("cleartext") instead of
        integers (1). It must sit at the top level of the request body.
        """
        self._require_login(url)
        result = self._call("get", url, top={"verbose": 1} if verbose else None, **extra)
        if "data" not in result:
            raise FMGShapeError(
                "status was OK but the response has no 'data' key - "
                "does this endpoint really exist?", url)
        return result["data"]

    def execute(self, url: str, data: Any = None, **extra: Any) -> dict:
        """Run an action. Returns the whole first result (some actions have no data)."""
        self._require_login(url)
        return self._call("exec", url, data, **extra)

    def set(self, url: str, data: Any, **extra: Any) -> dict:
        """Create-or-update (`set`). On the script object endpoint this
        merges rather than replaces, so verify with a `get` afterwards."""
        self._require_login(url)
        return self._call("set", url, data, **extra)

    def delete(self, url: str, **extra: Any) -> dict:
        self._require_login(url)
        return self._call("delete", url, **extra)
