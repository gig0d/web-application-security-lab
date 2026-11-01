import asyncio

import httpx
import pytest
from fastapi import HTTPException

from apps.core.config import Settings
from apps.core.security import PASSWORDS, SecurePolicy, fetch_simulation, verify_password


def test_password_hashes_are_argon2id_and_salted():
    first = PASSWORDS.hash("synthetic-fixture")
    second = PASSWORDS.hash("synthetic-fixture")
    assert first.startswith("$argon2id$") and first != second
    assert verify_password(first, "synthetic-fixture")
    assert not verify_password(first, "wrong")


def test_secure_html_encoding():
    assert (
        str(SecurePolicy().render('<script a="x">&</script>'))
        == "&lt;script a=&#34;x&#34;&gt;&amp;&lt;/script&gt;"
    )


@pytest.mark.parametrize(
    "origin", ["http://0.0.0.0:18081", "https://example.com", "http://127.0.0.1:9999"]
)
def test_nonlocal_configuration_rejected(origin):
    with pytest.raises(ValueError):
        Settings(origin=origin)


def test_arbitrary_preview_destinations_never_call_network(monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Network client must not be created for unapproved input")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden)
    for selector in (
        "https://example.com",
        "http://169.254.169.254/",
        "file:///etc/passwd",
        "metadata?redirect=anything",
        "127.0.0.1",
    ):
        with pytest.raises(HTTPException) as error:
            asyncio.run(fetch_simulation(selector))
        assert error.value.status_code == 422


def test_preview_response_bound(monkeypatch):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"a" * 4097)),
            **kwargs,
        ),
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(fetch_simulation("handbook"))
    assert error.value.status_code == 502
