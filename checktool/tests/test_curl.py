"""Unit tests for curl rendering and request recording (no network)."""

import httpx

import checktool.client as client_mod
from checktool.client import ApiClient, RequestSpec


def _api() -> ApiClient:
    return ApiClient("http://127.0.0.1:9999")


class TestCurlRendering:
    def test_get_with_bearer(self):
        cmd = _api().curl(
            RequestSpec(
                method="GET",
                path="/api/users/me",
                headers={"Authorization": "Bearer tok"},
            ),
            shell="bash",
        )
        assert cmd == (
            "curl -sS 'http://127.0.0.1:9999/api/users/me' -H 'Authorization: Bearer tok'"
        )

    def test_post_json_body(self):
        cmd = _api().curl(
            RequestSpec(
                method="POST",
                path="/api/keys",
                json={"name": "x", "scopes": ["read"]},
                headers={"Authorization": "Bearer t"},
            ),
            shell="bash",
        )
        assert "-X POST" in cmd
        assert "-H 'Content-Type: application/json'" in cmd
        assert "-d '{\"name\":\"x\",\"scopes\":[\"read\"]}'" in cmd

    def test_form_body(self):
        cmd = _api().curl(
            RequestSpec(
                method="POST",
                path="/oauth2/par",
                data={"client_id": "c", "scope": "read"},
                headers={},
            ),
            shell="bash",
        )
        assert "-H 'Content-Type: application/x-www-form-urlencoded'" in cmd
        assert "--data-urlencode 'client_id=c'" in cmd
        assert "--data-urlencode 'scope=read'" in cmd

    def test_basic_auth(self):
        cmd = _api().curl(
            RequestSpec(
                method="POST",
                path="/oauth2/token",
                data={"grant_type": "x"},
                auth=("id", "sec"),
            ),
            shell="bash",
        )
        assert "-u 'id:sec'" in cmd

    def test_bash_escapes_single_quotes(self):
        cmd = _api().curl(
            RequestSpec(method="POST", path="/x", json={"a": "it's"}, headers={}),
            shell="bash",
        )
        assert "it'\\''s" in cmd

    def test_powershell_uses_double_quotes(self):
        cmd = _api().curl(
            RequestSpec(
                method="GET",
                path="/api/users/me",
                headers={"Authorization": "Bearer tok"},
            ),
            shell="powershell",
        )
        assert cmd == (
            'curl.exe -sS "http://127.0.0.1:9999/api/users/me" '
            '-H "Authorization: Bearer tok"'
        )

    def test_powershell_escapes_double_quotes(self):
        cmd = _api().curl(
            RequestSpec(
                method="POST",
                path="/x",
                data={"q": 'say "hi"'},
                headers={},
            ),
            shell="powershell",
        )
        assert '--data-urlencode "q=say `"hi`""' in cmd

    def test_empty_without_request(self):
        assert _api().curl() == ""

    def test_detect_shell_by_platform(self, monkeypatch):
        monkeypatch.setattr(client_mod.os, "name", "nt")
        assert client_mod._detect_shell() == "powershell"
        monkeypatch.setattr(client_mod.os, "name", "posix")
        assert client_mod._detect_shell() == "bash"


class TestRequestRecording:
    def _api_with_transport(self) -> ApiClient:
        api = ApiClient("http://x")
        transport = httpx.MockTransport(lambda _req: httpx.Response(200, json={"ok": True}))
        api._client = httpx.Client(base_url="http://x", transport=transport)
        return api

    def test_records_last_request_and_invokes_observer(self):
        seen = []
        api = self._api_with_transport()
        api.access_token = "tok"
        api.on_request = lambda spec, resp: seen.append((spec, resp.status_code))

        resp = api.post("/api/keys", json={"name": "n"})

        assert resp.status_code == 200
        assert api.last_request is not None
        assert api.last_request.method == "POST"
        assert api.last_request.path == "/api/keys"
        assert api.last_request.headers["Authorization"] == "Bearer tok"
        assert seen and seen[0][1] == 200

    def test_observer_failure_does_not_break_request(self):
        api = self._api_with_transport()

        def boom(_spec, _resp):
            raise RuntimeError("observer down")

        api.on_request = boom
        assert api.get("/health").status_code == 200
