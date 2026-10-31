"""Configuration-only pool transport selection. No sockets or real host calls."""

from types import SimpleNamespace

import pytest
import requests

from core import auth, proxima_client
from tests.test_pool_foundation import env  # noqa: F401


def send(server, mode):
    if mode == "bootstrap":
        return proxima_client.request(server, "POST", "/api/vpn/auth/login",
                                      body={"username": "fixture", "password": "fixture-password"}, credential_bootstrap=True)
    return proxima_client.request(server, "PUT", "/api/vpn/pool-attachments/11111111-1111-4111-8111-111111111111",
                                  body={"state": "active"}, management_write=True)


@pytest.fixture
def transport(env):
    calls = []
    def request(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=200)
    env.monkeypatch.setattr(requests, "post", request)
    env.monkeypatch.setattr(requests, "put", request)
    return calls


@pytest.mark.parametrize("mode", ["bootstrap", "delivery"])
@pytest.mark.parametrize("url,public,expected", [
    ("http://localhost:5050", "https://home.example.invalid", "http://127.0.0.1:5050"),
    ("http://10.23.45.10:5050", "https://test.example.invalid", "https://test.example.invalid"),
    ("http://LOCALHOST:5050/base/", "https://unused.example.invalid", "http://127.0.0.1:5050/base"),
    ("http://127.0.0.1:5050", None, "http://127.0.0.1:5050"),
    ("http://[::1]:5050", None, "http://[::1]:5050"),
    ("https://management.example.invalid", "https://unused.example.invalid", "https://management.example.invalid"),
    ("http://private.example.invalid:5050", "https://public.example.invalid:5443/base/", "https://public.example.invalid:5443/base"),
])
def test_registered_configuration_selects_one_safe_transport(env, transport, mode, url, public, expected):
    server = {"url": url, "public_url": public, "api_token_enc": auth.encrypt_value("site-admin")}
    assert send(server, mode).status_code == 200
    assert len(transport) == 1
    destination, kwargs = transport[0]
    assert destination.startswith(expected + "/api/vpn/")
    assert kwargs["verify"] is True and kwargs["allow_redirects"] is False
    assert kwargs["headers"] == ({} if mode == "bootstrap" else {"Authorization": "Bearer site-admin"})


@pytest.mark.parametrize("mode", ["bootstrap", "delivery"])
@pytest.mark.parametrize("public", [None, "", "http://public.example.invalid", "http://127.0.0.1:5050",
    "https://user:password@public.example.invalid", "https://@public.example.invalid", "https://public.example.invalid?next=x",
    "https://public.example.invalid#fragment", "https://public.example.invalid:99999", "ftp://public.example.invalid",
    "https:///missing-host", "https://public.example.invalid\\other", "https://public.example.invalid\n", " https://public.example.invalid"])
def test_public_tls_fallback_validation_rejects_before_request(env, transport, mode, public):
    server = {"url": "http://10.23.45.10:5050", "public_url": public, "api_token_enc": auth.encrypt_value("site-admin")}
    with pytest.raises(ValueError):
        send(server, mode)
    assert transport == []


@pytest.mark.parametrize("url", ["http://localhost.evil.invalid:5050", "http://localhost.:5050"])
def test_only_exact_localhost_normalized(env, transport, url):
    with pytest.raises(ValueError):
        send({"url": url}, "bootstrap")
    assert transport == []


@pytest.mark.parametrize("url", ["http://user:pass@private.example.invalid", "http://private.example.invalid?x=y",
    "http://private.example.invalid#x", "ftp://private.example.invalid", "http://private.example.invalid:bad"])
def test_invalid_management_configuration_does_not_fall_back(env, transport, url):
    with pytest.raises(ValueError):
        send({"url": url, "public_url": "https://public.example.invalid"}, "bootstrap")
    assert transport == []


@pytest.mark.parametrize("mode", ["bootstrap", "delivery"])
@pytest.mark.parametrize("url", ["https://management.example.invalid", "http://10.23.45.10:5050", "http://localhost:5050"])
@pytest.mark.parametrize("outcome", [401, 403, 307, "tls_failure"])
def test_runtime_failure_never_selects_another_url(env, transport, mode, url, outcome):
    calls = []
    def fail(destination, **kwargs):
        calls.append(destination)
        if outcome == "tls_failure":
            raise requests.exceptions.SSLError("fixture certificate rejection")
        return SimpleNamespace(status_code=outcome)
    env.monkeypatch.setattr(requests, "post", fail)
    env.monkeypatch.setattr(requests, "put", fail)
    server = {"url": url, "public_url": "https://public.example.invalid", "api_token_enc": auth.encrypt_value("site-admin")}
    if outcome == "tls_failure":
        with pytest.raises(requests.exceptions.SSLError):
            send(server, mode)
    else:
        assert send(server, mode).status_code == outcome
    assert len(calls) == 1


@pytest.mark.parametrize("url", ["http://localhost:5050", "http://10.23.45.10:5050"])
def test_legacy_transport_keeps_original_url_and_options(env, transport, url):
    server = {"url": url, "public_url": "https://unused.example.invalid", "api_token_enc": auth.encrypt_value("site-admin")}
    proxima_client.request(server, "POST", "/api/legacy", body={})
    assert len(transport) == 1
    destination, kwargs = transport[0]
    assert destination == url + "/api/legacy"
    assert "allow_redirects" not in kwargs
    assert kwargs["verify"] is proxima_client.VERIFY_TLS
    assert kwargs["headers"] == {"Authorization": "Bearer site-admin"}
