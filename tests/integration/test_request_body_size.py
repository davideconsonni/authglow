"""Integration tests for request body size limiter middleware.

Verifies 413 Payload Too Large responses from a FastAPI app
that includes MaxBodySizeMiddleware.
"""

import pytest


@pytest.fixture
def client():
    from starlette.testclient import TestClient
    from fastapi import FastAPI

    settings = _make_settings(max_request_body_size_mb=1)

    from authglow.middleware.request_body_size import MaxBodySizeMiddleware

    app = FastAPI()
    app.add_middleware(MaxBodySizeMiddleware, settings=settings)

    @app.post("/upload")
    async def upload():
        return {"status": "uploaded"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    return TestClient(app)


class TestBodySizeEnforcement:
    def test_small_body_passes(self, client):
        response = client.post("/upload", content="a" * 512)
        assert response.status_code == 200
        assert response.json() == {"status": "uploaded"}

    def test_body_over_limit_413(self, client):
        payload = "x" * (1 * 1024 * 1024 + 100)  # just over 1 MB
        response = client.post("/upload", content=payload)
        assert response.status_code == 413

    def test_413_response_is_json(self, client):
        payload = "x" * (2 * 1024 * 1024)  # 2 MB
        response = client.post("/upload", content=payload)
        assert response.status_code == 413
        assert response.headers["content-type"] == "application/json"
        data = response.json()
        assert "detail" in data
        assert "exceeds" in data["detail"]

    def test_get_request_not_affected(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_body_at_limit_passes(self, client):
        payload = "x" * (1 * 1024 * 1024)  # exactly 1 MB
        response = client.post("/upload", content=payload)
        assert response.status_code == 200

    def test_empty_body_passes(self, client):
        response = client.post("/upload")
        assert response.status_code == 200

    def test_json_body_over_limit_413(self, client):
        entry = '{"key": "' + "x" * 100 + '"},\n'
        entries = entry * 20000
        payload = '{"data": [\n' + entries + "]}"
        response = client.post("/upload", content=payload)
        assert response.status_code == 413


class TestCustomLimit:
    @pytest.fixture
    def tiny_client(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI

        settings = _make_settings(
            max_request_body_size_mb=1
        )  # 1 byte limit via settings
        # Actually test with a 0 MB limit instead
        settings = _make_settings(max_request_body_size_mb=0)

        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        app = FastAPI()
        app.add_middleware(MaxBodySizeMiddleware, settings=settings)

        @app.post("/upload")
        async def upload():
            return {"status": "uploaded"}

        return TestClient(app)

    def test_zero_limit_rejects_any_body(self, tiny_client):
        response = tiny_client.post("/upload", content="a")
        assert response.status_code == 413


def _make_settings(**overrides):
    defaults = {"max_request_body_size_mb": 10}

    class FakeSettings:
        pass

    settings = FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    return settings
