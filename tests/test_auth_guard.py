"""Comprehensive Unit Tests for Python SDK v2.0 (mr_john_auth).

All external HTTP calls are strictly mocked.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import gc
import importlib.util
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

import mr_john_auth
from mr_john_auth import (
    PLAN_HIERARCHY,
    AsyncJWKSStore,
    AuthUser,
    MrJohnAuthClient,
    ServiceEntitlement,
    auth_guard,
    configure,
    get_current_user,
    get_optional_user,
    jwks_store,
    require_claim,
    require_global_admin,
    require_mfa,
    require_plan,
    require_role,
)


@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate ephemeral RSA key pair for unit tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = "test-key-01"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"

    return {
        "private_pem": pem_private,
        "jwk": jwk_dict,
        "jwks": {"keys": [jwk_dict]},
        "kid": "test-key-01",
    }


@pytest.fixture(autouse=True)
def reset_sdk_globals():
    """Snapshot and restore SDK global state so configure() calls never leak across tests."""
    saved_api_url = auth_guard.AUTH_API_URL
    saved_jwks_url = auth_guard.AUTH_JWKS_URL
    saved_issuer = auth_guard.AUTH_ISSUER
    saved_audience = auth_guard.AUTH_AUDIENCE
    saved_client_id = auth_guard.SERVICE_CLIENT_ID
    saved_client_secret = auth_guard.SERVICE_CLIENT_SECRET
    saved_overrides = dict(auth_guard._configured_overrides)
    saved_store_url = jwks_store.jwks_url

    auth_guard.AUTH_API_URL = auth_guard._DEFAULT_AUTH_API_URL
    auth_guard.AUTH_JWKS_URL = f"{auth_guard._DEFAULT_AUTH_API_URL}/.well-known/jwks.json"
    auth_guard.AUTH_ISSUER = auth_guard._DEFAULT_AUTH_ISSUER
    auth_guard.AUTH_AUDIENCE = auth_guard._DEFAULT_AUTH_AUDIENCE
    auth_guard.SERVICE_CLIENT_ID = auth_guard._DEFAULT_CLIENT_ID
    auth_guard.SERVICE_CLIENT_SECRET = ""
    auth_guard._configured_overrides.clear()
    jwks_store.jwks_url = None
    jwks_store.clear()
    try:
        yield
    finally:
        auth_guard.AUTH_API_URL = saved_api_url
        auth_guard.AUTH_JWKS_URL = saved_jwks_url
        auth_guard.AUTH_ISSUER = saved_issuer
        auth_guard.AUTH_AUDIENCE = saved_audience
        auth_guard.SERVICE_CLIENT_ID = saved_client_id
        auth_guard.SERVICE_CLIENT_SECRET = saved_client_secret
        auth_guard._configured_overrides.clear()
        auth_guard._configured_overrides.update(saved_overrides)
        jwks_store.jwks_url = saved_store_url
        jwks_store.clear()


def _make_sdk_token(
    rsa_key_pair: dict,
    *,
    sub: str = "u-1",
    email: str = "sdk@example.com",
    iss: str | None = None,
    aud: str = "mr-john-auth",
    global_role: str = "user",
    mfa_verified: bool = False,
    custom_claims: dict | None = None,
    services: dict | None = None,
    ttl: int = 900,
    include_kid: bool = True,
) -> str:
    now = int(time.time())
    payload = {
        "iss": auth_guard._DEFAULT_AUTH_ISSUER if iss is None else iss,
        "sub": sub,
        "aud": aud,
        "exp": now + ttl,
        "iat": now,
        "email": email,
        "email_verified": True,
        "name": "SDK User",
        "picture": "https://example.com/p.png",
        "global_role": global_role,
        "mfa_verified": mfa_verified,
        "amr": ["pwd", "totp"] if mfa_verified else ["pwd"],
        "custom_claims": custom_claims or {},
        "services": services or {},
        "ver": 1,
    }
    headers = {"kid": rsa_key_pair["kid"]} if include_kid else None
    return jwt.encode(
        payload,
        rsa_key_pair["private_pem"],
        algorithm="RS256",
        headers=headers,
    )


def _make_mock_http_client(
    rsa_key_pair: dict,
    *,
    payload: dict | None = None,
    delay: float = 0.0,
    error: Exception | None = None,
):
    """Build a mocked async httpx client without making real network calls."""
    requested_urls: list[str] = []
    state: dict = {"payload": payload, "delay": delay, "error": error}

    async def _fake_get(url: str):
        requested_urls.append(url)
        if state["delay"] > 0:
            await asyncio.sleep(state["delay"])
        if state["error"] is not None:
            raise state["error"]
        active_payload = state["payload"]
        return MagicMock(
            raise_for_status=lambda: None,
            json=lambda: active_payload if active_payload is not None else rsa_key_pair["jwks"],
        )

    mock_http = AsyncMock()
    mock_http.__aenter__.return_value = mock_http
    mock_http.__aexit__.return_value = False
    mock_http.get.side_effect = _fake_get
    return mock_http, requested_urls, state


@pytest.mark.asyncio
async def test_jwks_store_caching_cooldown_and_stale_while_revalidate(rsa_key_pair):
    """Verify AsyncJWKSStore caching, unknown-kid cooldown, and Stale-While-Revalidate."""
    store = AsyncJWKSStore(
        jwks_url="https://auth.api.mr-john-it.com/.well-known/jwks.json",
        cache_ttl=3600,
        min_refetch_cooldown=300,
    )
    mock_http, _, http_state = _make_mock_http_client(rsa_key_pair)

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        key1 = await store.get_signing_key(rsa_key_pair["kid"])
        key2 = await store.get_signing_key(rsa_key_pair["kid"])
        assert key1 is key2
        assert mock_http.get.call_count == 1

        # Unknown kid blocked during cooldown
        with pytest.raises(jwt.InvalidKeyError, match="cooldown"):
            await store.get_signing_key("unknown-kid")
        assert mock_http.get.call_count == 1

        # Expire cache TTL and simulate upstream error -> Stale-While-Revalidate serves cached key
        store._last_fetched_at -= 4000
        http_state["error"] = RuntimeError("transient network error")
        stale_key = await store.get_signing_key(rsa_key_pair["kid"])
        assert stale_key is key1

        # Clear cache -> network failure now raises InvalidKeyError
        store.clear()
        with pytest.raises(jwt.InvalidKeyError, match="Failed to fetch JWKS"):
            await store.get_signing_key(rsa_key_pair["kid"])


@pytest.mark.asyncio
async def test_get_current_user_valid_token_and_helpers(rsa_key_pair):
    """Verify valid RS256 token is decoded and all AuthUser helper methods work."""
    client_id = "stock-research"
    configure(client_id=client_id)

    now = int(time.time())
    payload = {
        "sub": "user-uuid-123",
        "email": "user@example.com",
        "name": "Jane Trader",
        "global_role": "user",
        "mfa_verified": True,
        "amr": ["pwd", "totp"],
        "ver": 1,
        "custom_claims": {"beta": True, "tier_level": 2},
        "services": {
            client_id: {
                "plan": "pro",
                "roles": ["analyst", "trader"],
                "daily_quota": 500,
            }
        },
        "iss": auth_guard._DEFAULT_AUTH_ISSUER,
        "aud": client_id,
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(
        payload,
        rsa_key_pair["private_pem"],
        algorithm="RS256",
        headers={"kid": rsa_key_pair["kid"]},
    )

    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])
    with patch.object(auth_guard.jwks_store, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
        mock_get_key.return_value = mock_key

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        user = await get_current_user(creds)

        assert isinstance(user, AuthUser)
        assert user.id == "user-uuid-123"
        assert user.email == "user@example.com"
        assert user.display_name == "Jane Trader"
        assert user.mfa_verified is True
        assert user.is_global_admin is False
        assert user.get_claim("beta") is True
        assert user.get_claim("missing", "fallback") == "fallback"
        assert user.has_claim("beta", True) is True
        assert user.has_claim("beta", 1) is False  # Strict bool vs int
        assert user.has_claim("tier_level", 2) is True
        assert user.has_claim("tier_level", True) is False
        assert user.has_claim("missing", True) is False
        assert user.get_service_plan(client_id) == "pro"
        assert user.get_service_roles(client_id) == ["analyst", "trader"]
        assert user.has_service_role("analyst", client_id) is True
        assert user.has_service_role("admin", client_id) is False
        assert user.has_any_service_role(["admin", "trader"], client_id) is True
        assert user.has_minimum_plan("starter", client_id) is True
        assert user.has_minimum_plan("enterprise", client_id) is False
        assert user.get_custom_claim("daily_quota", service_id=client_id) == 500
        assert user.get_custom_claim("missing_key", default=10, service_id=client_id) == 10

        entitlement = user.get_service_entitlement(client_id)
        assert isinstance(entitlement, ServiceEntitlement)
        assert entitlement.plan == "pro"
        assert entitlement.roles == ["analyst", "trader"]
        assert entitlement.custom_claims == {"daily_quota": 500}

        # Non-dict service value fallback
        user.services["broken"] = "invalid"
        assert user.get_service_entitlement("broken").plan == "free"
        assert user.get_service_plan("broken") == "free"
        assert user.get_service_roles("broken") == []

        # Test get_optional_user
        assert await get_optional_user(None) is None
        opt_user = await get_optional_user(creds)
        assert opt_user is not None and opt_user.id == "user-uuid-123"
        bad_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.jwt.token")
        assert await get_optional_user(bad_creds) is None


@pytest.mark.asyncio
async def test_get_current_user_error_cases(rsa_key_pair):
    """Verify missing credentials, missing kid, expired token, and audience mismatch raise 401."""
    # 1. Missing credentials
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(None)
    assert exc_info.value.status_code == 401
    assert "Authorization header missing" in exc_info.value.detail

    # 2. Missing kid in header
    no_kid_token = _make_sdk_token(rsa_key_pair, include_kid=False)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=no_kid_token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(creds)
    assert exc_info.value.status_code == 401

    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])
    with patch.object(auth_guard.jwks_store, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
        mock_get_key.return_value = mock_key

        # 3. Expired token
        expired_token = _make_sdk_token(rsa_key_pair, ttl=-3600)
        expired_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(expired_creds)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail

        # 4. Audience mismatch
        bad_aud_token = _make_sdk_token(rsa_key_pair, aud="attacker-wrong-service")
        bad_aud_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=bad_aud_token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(bad_aud_creds)
        assert exc_info.value.status_code == 401
        assert "Token verification failed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_require_mfa_global_admin_plan_and_role_dependencies():
    """Verify require_mfa, require_global_admin, require_plan, and require_role dependencies."""
    client_id = "stock-research"
    verified_user = AuthUser(id="u1", email="a@b.com", mfa_verified=True, global_role="user")
    unverified_user = AuthUser(id="u2", email="b@b.com", mfa_verified=False, global_role="user")
    pro_user = AuthUser(
        id="u3",
        email="trader@b.com",
        services={client_id: {"plan": "pro", "roles": ["trader", "analyst"]}},
    )
    admin_user = AuthUser(id="admin1", email="admin@b.com", mfa_verified=False, global_role="admin")

    # require_mfa
    assert await require_mfa(verified_user) == verified_user
    with pytest.raises(HTTPException) as exc_info:
        await require_mfa(unverified_user)
    assert exc_info.value.status_code == 403
    assert "Two-factor authentication" in exc_info.value.detail

    # require_global_admin
    assert await require_global_admin(admin_user) == admin_user
    with pytest.raises(HTTPException) as exc_info:
        await require_global_admin(verified_user)
    assert exc_info.value.status_code == 403
    assert "Global administrator" in exc_info.value.detail

    # require_plan
    assert await require_plan("free", client_id)(pro_user) == pro_user
    assert await require_plan("starter", client_id)(pro_user) == pro_user
    assert await require_plan("pro", client_id)(pro_user) == pro_user
    with pytest.raises(HTTPException) as exc_info:
        await require_plan("enterprise", client_id)(pro_user)
    assert exc_info.value.status_code == 403
    assert "requires at least 'enterprise' plan" in exc_info.value.detail
    assert await require_plan("enterprise", client_id)(admin_user) == admin_user

    # require_role
    assert await require_role("trader", client_id)(pro_user) == pro_user
    assert await require_role(["editor", "analyst"], client_id)(pro_user) == pro_user
    with pytest.raises(HTTPException) as exc_info:
        await require_role("super_editor", client_id)(pro_user)
    assert exc_info.value.status_code == 403
    assert await require_role("super_editor", client_id)(admin_user) == admin_user


@pytest.mark.asyncio
async def test_sdk_guards_multi_audience_custom_claims_and_backward_compat(rsa_key_pair):
    """Verify v2.0.0 require_claim, multi-audience tolerance, and backward-compatible guards."""
    assert mr_john_auth.__version__ == "2.0.0"
    assert PLAN_HIERARCHY["max"] == 3
    assert PLAN_HIERARCHY["enterprise"] == 4

    configure(
        audience="mr-john-auth",
        client_id="stock-research",
        api_url="https://auth.api.mr-john-it.com",
        issuer=auth_guard._DEFAULT_AUTH_ISSUER,
    )

    mock_http, _, _ = _make_mock_http_client(rsa_key_pair)
    jwks_store.clear()

    def _creds(tok: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        assert await get_optional_user(None) is None
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(None)
        assert exc_info.value.status_code == 401

        pro_checker = require_claim("pro", True)
        legacy_plan_checker = require_plan("pro")
        legacy_role_checker = require_role("editor")

        # 1. Token with v2.0 audience ("mr-john-auth") + custom_claims (bool vs int test)
        tok_int_1 = _make_sdk_token(rsa_key_pair, custom_claims={"pro": 1, "roles": ["editor"]})
        user_int_1 = await get_current_user(_creds(tok_int_1))
        with pytest.raises(HTTPException) as exc_info:
            await pro_checker(user_int_1)
        assert exc_info.value.status_code == 403  # 1 != True in strict claim check

        tok_pro = _make_sdk_token(
            rsa_key_pair,
            aud="mr-john-auth",
            custom_claims={"pro": True, "plan": "pro", "roles": ["editor"]},
        )
        user_pro = await get_current_user(_creds(tok_pro))
        assert user_pro.id == "u-1"
        assert user_pro.get_claim("pro") is True
        assert await pro_checker(user_pro) == user_pro
        assert await legacy_plan_checker(user_pro) == user_pro
        assert await legacy_role_checker(user_pro) == user_pro
        with pytest.raises(HTTPException) as exc_info:
            await require_mfa(user_pro)
        assert exc_info.value.status_code == 403
        with pytest.raises(HTTPException) as exc_info:
            await require_global_admin(user_pro)
        assert exc_info.value.status_code == 403

        # 2. Multi-audience tolerance: legacy child client_id ("stock-research") also accepted
        tok_legacy_aud = _make_sdk_token(
            rsa_key_pair,
            aud="stock-research",
            global_role="admin",
            mfa_verified=True,
            services={"stock-research": {"plan": "enterprise", "roles": ["admin"]}},
        )
        user_legacy_aud = await get_current_user(_creds(tok_legacy_aud))
        assert await require_mfa(user_legacy_aud) == user_legacy_aud
        assert await require_global_admin(user_legacy_aud) == user_legacy_aud
        assert await pro_checker(user_legacy_aud) == user_legacy_aud  # Admin bypasses require_claim

        # 3. Unknown audience rejected 401
        tok_bad_aud = _make_sdk_token(rsa_key_pair, aud="other-app")
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_creds(tok_bad_aud))
        assert exc_info.value.status_code == 401

    with pytest.raises(ValueError, match="Unknown plan tier"):
        AuthUser(id="u1", email="a@b.com").has_minimum_plan("platinum")


@pytest.mark.asyncio
async def test_sdk_default_issuer_and_rejects_old_or_invalid_issuer(
    rsa_key_pair,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify SDK default issuer matches API URL and rejects stale UI-domain or unknown issuers."""
    for env_key in (
        "MR_JOHN_AUTH_ISSUER",
        "MR_JOHN_AUTH_API_URL",
        "MR_JOHN_AUTH_AUDIENCE",
        "MR_JOHN_CLIENT_ID",
    ):
        monkeypatch.delenv(env_key, raising=False)

    assert auth_guard._DEFAULT_AUTH_ISSUER == auth_guard._DEFAULT_AUTH_API_URL
    assert auth_guard._DEFAULT_AUTH_ISSUER == "https://auth.api.mr-john-it.com"
    assert auth_guard._resolve_issuer() == "https://auth.api.mr-john-it.com"

    mock_http, _, _ = _make_mock_http_client(rsa_key_pair)

    def _creds(tok: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)

    default_issued_jwt = _make_sdk_token(
        rsa_key_pair,
        sub="user-default-iss",
        email="default@example.com",
        iss="https://auth.api.mr-john-it.com",
    )
    old_ui_issuer_jwt = _make_sdk_token(rsa_key_pair, sub="user-old-iss", iss="https://auth.mr-john-it.com")
    evil_issuer_jwt = _make_sdk_token(rsa_key_pair, sub="user-evil-iss", iss="https://evil.example.com")

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        # 1. Pure default state (no configure() call): default issuer succeeds, old/evil issuers fail with 401.
        ok_user = await get_current_user(_creds(default_issued_jwt))
        assert ok_user.id == "user-default-iss"
        assert ok_user.email == "default@example.com"

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_creds(old_ui_issuer_jwt))
        assert exc_info.value.status_code == 401

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_creds(evil_issuer_jwt))
        assert exc_info.value.status_code == 401

        assert await get_optional_user(_creds(old_ui_issuer_jwt)) is None

        # 2. Calling configure() without issuer= preserves _DEFAULT_AUTH_ISSUER.
        configure(
            audience="mr-john-auth",
            client_id="stock-research",
            api_url="https://auth.api.mr-john-it.com",
        )
        assert auth_guard._resolve_issuer() == "https://auth.api.mr-john-it.com"
        ok_after_cfg = await get_current_user(_creds(default_issued_jwt))
        assert ok_after_cfg.id == "user-default-iss"
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_creds(old_ui_issuer_jwt))
        assert exc_info.value.status_code == 401

        # 3. Explicit configure(issuer=...) overrides default for migrating child services.
        configure(issuer="https://legacy.mr-john-it.com")
        legacy_jwt = _make_sdk_token(rsa_key_pair, sub="user-legacy", iss="https://legacy.mr-john-it.com")
        legacy_user = await get_current_user(_creds(legacy_jwt))
        assert legacy_user.id == "user-legacy"
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_creds(default_issued_jwt))
        assert exc_info.value.status_code == 401


def test_jwks_store_multi_event_loop_concurrency_and_weakref_cleanup(rsa_key_pair):
    """Verify AsyncJWKSStore safely serves multiple sequential and concurrent event loops without RuntimeError."""
    store = AsyncJWKSStore(jwks_url="https://auth.api.mr-john-it.com/.well-known/jwks.json")
    mock_http, _, _ = _make_mock_http_client(rsa_key_pair, delay=0.01)

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        # 1. Sequential event loops (e.g. FastAPI TestClient / repeated asyncio.run) reuse store without error.
        key_loop1 = asyncio.run(store.get_signing_key(rsa_key_pair["kid"]))
        gc.collect()
        assert len(store._locks) == 0

        key_loop2 = asyncio.run(store.get_signing_key(rsa_key_pair["kid"]))
        assert key_loop1 is key_loop2
        assert mock_http.get.call_count == 1

        # 2. Same-loop concurrent tasks deduplicate upstream HTTP fetch via per-loop asyncio.Lock.
        store.clear()

        async def _concurrent_same_loop():
            return await asyncio.gather(
                *[store.get_signing_key(rsa_key_pair["kid"]) for _ in range(5)]
            )

        keys = asyncio.run(_concurrent_same_loop())
        assert len(keys) == 5
        assert all(k is keys[0] for k in keys)
        assert mock_http.get.call_count == 2

        # 3. Concurrent independent event loops across worker threads never raise loop-binding RuntimeError.
        store.clear()
        barrier = threading.Barrier(2)

        def _worker():
            async def _run():
                barrier.wait(timeout=5)
                return await store.get_signing_key(rsa_key_pair["kid"])

            return asyncio.run(_run())

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_worker)
            f2 = pool.submit(_worker)
            w_key1 = f1.result(timeout=5)
            w_key2 = f2.result(timeout=5)

        assert w_key1 is not None and w_key2 is not None

        # 4. Fallback lock dictionary handles non-weakref custom loops, reuses open-loop lock, and prunes closed loops.
        class _NonWeakrefLockMap:
            def get(self, _key):
                raise TypeError("cannot create weak reference to loop")

        store.clear()
        store._locks = _NonWeakrefLockMap()  # type: ignore[assignment]

        async def _reuse_fallback_same_loop():
            k_a = await store.get_signing_key(rsa_key_pair["kid"])
            store.clear()
            k_b = await store.get_signing_key(rsa_key_pair["kid"])
            return k_a, k_b

        k_a, k_b = asyncio.run(_reuse_fallback_same_loop())
        assert k_a is not None and k_b is not None
        assert len(store._fallback_locks) == 1

        store.clear()
        assert asyncio.run(store.get_signing_key(rsa_key_pair["kid"])) is not None
        # Closed previous loop was pruned when inserting the new loop.
        assert len(store._fallback_locks) == 1


@pytest.mark.asyncio
async def test_jwks_store_stale_if_error_backoff_startup_and_recovery(
    rsa_key_pair,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify stale-if-error backoff prevents upstream hammering, fails fast on missing kids, and resets on recovery."""
    clock = {"now": 5.0}  # Simulate container uptime < error_cooldown (30.0s) at startup
    monkeypatch.setattr(auth_guard, "time", SimpleNamespace(monotonic=lambda: clock["now"]))

    store = AsyncJWKSStore(
        jwks_url="https://auth.api.mr-john-it.com/.well-known/jwks.json",
        cache_ttl=60,
        min_refetch_cooldown=30,
        error_cooldown=30.0,
    )
    mock_http, _, http_state = _make_mock_http_client(rsa_key_pair)

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        # Startup with time.monotonic() < error_cooldown must NOT trigger false cooldown.
        key1 = await store.get_signing_key(rsa_key_pair["kid"])
        assert mock_http.get.call_count == 1
        assert store._last_error_at is None

        # Expire cache TTL and simulate upstream failure -> serves stale key and starts error_cooldown.
        clock["now"] = 100.0
        http_state["error"] = RuntimeError("upstream unavailable")
        stale_key = await store.get_signing_key(rsa_key_pair["kid"])
        assert stale_key is key1
        assert mock_http.get.call_count == 2
        assert store._last_error_at == 100.0
        assert store._last_fetched_at == 5.0

        # During error_cooldown (100.0 <= t < 130.0): cached kid returns immediately, missing kid fails fast.
        clock["now"] = 115.0
        assert await store.get_signing_key(rsa_key_pair["kid"]) is key1
        with pytest.raises(jwt.InvalidKeyError, match="backoff"):
            await store.get_signing_key("unknown-kid")
        assert mock_http.get.call_count == 2

        # At exact error_cooldown boundary (t == 130.0): retries upstream and clears error state on success.
        clock["now"] = 130.0
        http_state["error"] = None
        refreshed_key = await store.get_signing_key(rsa_key_pair["kid"])
        assert refreshed_key is not None
        assert mock_http.get.call_count == 3
        assert store._last_error_at is None
        assert store._last_error_url is None

        # Valid JWKS response that lacks requested kid raises InvalidKeyError without setting _last_error_at.
        clock["now"] = 200.0
        with pytest.raises(jwt.InvalidKeyError, match="not found in JWKS"):
            await store.get_signing_key("absent-kid")
        assert store._last_error_at is None

    # Concurrent failure on empty store: second waiter sees error_cooldown and fails fast without 2nd HTTP call.
    empty_store = AsyncJWKSStore(
        jwks_url="https://auth.api.mr-john-it.com/.well-known/jwks.json",
        error_cooldown=30.0,
    )
    failing_http, _, _ = _make_mock_http_client(rsa_key_pair, delay=0.02, error=RuntimeError("timeout"))
    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=failing_http):
        results = await asyncio.gather(
            empty_store.get_signing_key(rsa_key_pair["kid"]),
            empty_store.get_signing_key(rsa_key_pair["kid"]),
            return_exceptions=True,
        )
    assert all(isinstance(r, jwt.InvalidKeyError) for r in results)
    assert failing_http.get.call_count == 1

    # Switching JWKS URL clears previous URL error state instead of leaking backoff across URLs.
    empty_store.jwks_url = "https://other.example.com/.well-known/jwks.json"
    assert empty_store.has_url_mismatch("https://other.example.com/.well-known/jwks.json") is True
    recovery_http, _, _ = _make_mock_http_client(rsa_key_pair)
    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=recovery_http):
        assert await empty_store.get_signing_key(rsa_key_pair["kid"]) is not None
    assert empty_store._last_error_at is None
    assert empty_store._last_error_url is None


@pytest.mark.asyncio
async def test_jwks_store_non_destructive_parsing_and_malformed_jwks(
    rsa_key_pair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Verify empty/corrupted JWKS payloads preserve cached keys and skip invalid JWK items safely."""
    clock = {"now": 100.0}
    monkeypatch.setattr(auth_guard, "time", SimpleNamespace(monotonic=lambda: clock["now"]))

    store = AsyncJWKSStore(
        jwks_url="https://auth.api.mr-john-it.com/.well-known/jwks.json",
        cache_ttl=60,
        min_refetch_cooldown=30,
        error_cooldown=30.0,
    )
    valid_payload = rsa_key_pair["jwks"]
    valid_jwk = rsa_key_pair["jwk"]

    payload_holder = {"data": valid_payload}
    mock_http = AsyncMock()
    mock_http.__aenter__.return_value = mock_http
    mock_http.__aexit__.return_value = False
    mock_http.get.return_value = MagicMock(
        raise_for_status=lambda: None,
        json=lambda: payload_holder["data"],
    )

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        initial_key = await store.get_signing_key(rsa_key_pair["kid"])

        # 1. Empty {"keys": []} after TTL expiry must NOT overwrite existing cached keys.
        clock["now"] = 200.0
        payload_holder["data"] = {"keys": []}
        assert await store.get_signing_key(rsa_key_pair["kid"]) is initial_key
        assert rsa_key_pair["kid"] in store._keys
        assert store._last_error_at == 200.0

        # 2. All-unusable entries (non-dict, EC, use="enc", non-string kid, bad RSA key) keep stale cache intact.
        clock["now"] = 240.0
        payload_holder["data"] = {
            "keys": [
                "not-a-dict",
                {"kty": "EC", "kid": "ec-1"},
                {**valid_jwk, "use": "enc", "kid": "enc-only"},
                {**valid_jwk, "kid": 12345},
                {**valid_jwk, "kid": ""},
                {"kty": "RSA", "use": "sig", "kid": "broken-rsa", "n": "!!!", "e": "AQAB"},
            ]
        }
        with caplog.at_level("WARNING", logger="mr_john_auth"):
            assert await store.get_signing_key(rsa_key_pair["kid"]) is initial_key
        assert rsa_key_pair["kid"] in store._keys
        assert store._last_error_at == 240.0
        assert "Skipping" in caplog.text

        # 3. Mixed valid + invalid JWK items: invalid items skipped, valid RSA signing key (even use=None) kept.
        clock["now"] = 280.0
        valid_no_use_jwk = {k: v for k, v in valid_jwk.items() if k != "use"}
        payload_holder["data"] = {
            "keys": [
                "bad-entry",
                {**valid_jwk, "use": "enc", "kid": "enc-key"},
                {**valid_jwk, "kid": 999},
                valid_no_use_jwk,
            ]
        }
        refreshed = await store.get_signing_key(rsa_key_pair["kid"])
        assert refreshed is not None
        assert store._last_error_at is None
        assert list(store._keys.keys()) == [rsa_key_pair["kid"]]


@pytest.mark.asyncio
async def test_configure_initial_cache_clear_dynamic_env_and_generation_guard(
    rsa_key_pair,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify configure() cache clearing, env tracking precedence, _IMPORT_DEFAULTS, and generation guard."""
    mock_http, requested_urls, _ = _make_mock_http_client(rsa_key_pair)

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http):
        # 1. First configure(api_url=...) clears keys previously fetched from the default URL.
        await jwks_store.get_signing_key(rsa_key_pair["kid"])
        assert requested_urls == ["https://auth.api.mr-john-it.com/.well-known/jwks.json"]
        assert rsa_key_pair["kid"] in jwks_store._keys

        configure(api_url="https://tenant2.example.com")
        assert jwks_store._keys == {}
        assert jwks_store._cached_url is None

        await jwks_store.get_signing_key(rsa_key_pair["kid"])
        assert requested_urls[-1] == "https://tenant2.example.com/.well-known/jwks.json"

        # Explicit jwks_url + client_secret override works and clears previous cache.
        configure(
            jwks_url="https://explicit-jwks.example.com/keys.json",
            client_secret="configured-secret",
        )
        assert auth_guard._resolve_jwks_url() == "https://explicit-jwks.example.com/keys.json"
        assert auth_guard._resolve_client_secret() == "configured-secret"
        assert jwks_store._keys == {}

    # 2. configure(audience=...) leaves jwks_store.jwks_url=None so later env var changes still apply.
    auth_guard._configured_overrides.clear()
    auth_guard.AUTH_API_URL = auth_guard._DEFAULT_AUTH_API_URL
    auth_guard.AUTH_JWKS_URL = auth_guard._DEFAULT_AUTH_JWKS_URL
    auth_guard.SERVICE_CLIENT_SECRET = ""
    jwks_store.jwks_url = None
    jwks_store.clear()

    mock_http2, requested_urls2, _ = _make_mock_http_client(rsa_key_pair)
    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=mock_http2):
        configure(audience="my-child-service")
        assert jwks_store.jwks_url is None

        await jwks_store.get_signing_key(rsa_key_pair["kid"])
        assert requested_urls2 == ["https://auth.api.mr-john-it.com/.well-known/jwks.json"]

        monkeypatch.setenv("MR_JOHN_AUTH_JWKS_URL", "https://dynamic-env.example.com/.well-known/jwks.json")
        assert auth_guard._resolve_jwks_url() == "https://dynamic-env.example.com/.well-known/jwks.json"

        await jwks_store.get_signing_key(rsa_key_pair["kid"])
        assert requested_urls2[-1] == "https://dynamic-env.example.com/.well-known/jwks.json"

        # Switching env again before configure(client_id=...) triggers clear via has_url_mismatch().
        monkeypatch.setenv("MR_JOHN_AUTH_JWKS_URL", "https://third-env.example.com/.well-known/jwks.json")
        configure(client_id="child-client-id")
        assert jwks_store._keys == {}
        assert jwks_store._cached_url is None

    # 3. Non-default env at import time (_IMPORT_DEFAULTS) still allows later setenv/delenv and configure() overrides.
    monkeypatch.setenv("MR_JOHN_AUTH_API_URL", "https://boot-env.example.com/")
    monkeypatch.setenv("MR_JOHN_AUTH_ISSUER", "https://boot-iss.example.com")
    monkeypatch.setenv("MR_JOHN_AUTH_AUDIENCE", "boot-aud")
    monkeypatch.setenv("MR_JOHN_CLIENT_ID", "boot-cid")
    monkeypatch.setenv("MR_JOHN_CLIENT_SECRET", "boot-secret")
    monkeypatch.delenv("MR_JOHN_AUTH_JWKS_URL", raising=False)

    spec = importlib.util.spec_from_file_location("_test_isolated_auth_guard", Path(auth_guard.__file__))
    assert spec is not None and spec.loader is not None
    isolated_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated_mod)

    assert isolated_mod._resolve_api_url() == "https://boot-env.example.com"
    assert isolated_mod._resolve_jwks_url() == "https://boot-env.example.com/.well-known/jwks.json"
    assert isolated_mod._resolve_issuer() == "https://boot-iss.example.com"
    assert isolated_mod._resolve_audience() == "boot-aud"
    assert isolated_mod._resolve_client_id() == "boot-cid"
    assert isolated_mod._resolve_client_secret() == "boot-secret"

    monkeypatch.setenv("MR_JOHN_AUTH_API_URL", "https://reloaded-env.example.com")
    assert isolated_mod._resolve_api_url() == "https://reloaded-env.example.com"
    assert isolated_mod._resolve_jwks_url() == "https://reloaded-env.example.com/.well-known/jwks.json"

    monkeypatch.delenv("MR_JOHN_AUTH_API_URL")
    assert isolated_mod._resolve_api_url() == isolated_mod._DEFAULT_AUTH_API_URL
    assert isolated_mod._resolve_jwks_url() == isolated_mod._DEFAULT_AUTH_JWKS_URL

    # Direct module global assignment overrides env (Priority 2 > Priority 3).
    isolated_mod.AUTH_ISSUER = "https://manual-global.example.com"
    assert isolated_mod._resolve_issuer() == "https://manual-global.example.com"

    # Explicit configure() resetting to default overrides env (Priority 1 > Priority 3).
    monkeypatch.setenv("MR_JOHN_AUTH_API_URL", "https://env-should-be-overridden.example.com")
    isolated_mod.configure(api_url=isolated_mod._DEFAULT_AUTH_API_URL)
    assert isolated_mod._resolve_api_url() == isolated_mod._DEFAULT_AUTH_API_URL

    # 4. In-flight generation guard discards stale results/errors if clear() or configure() happens mid-fetch.
    gen_store = AsyncJWKSStore(jwks_url="https://url-a.example.com/.well-known/jwks.json")
    started_evt = asyncio.Event()
    release_evt = asyncio.Event()
    should_fail = {"value": False}

    async def _gated_get(_url: str):
        started_evt.set()
        await release_evt.wait()
        if should_fail["value"]:
            raise RuntimeError("stale generation failure")
        return MagicMock(raise_for_status=lambda: None, json=lambda: rsa_key_pair["jwks"])

    gated_http = AsyncMock()
    gated_http.__aenter__.return_value = gated_http
    gated_http.__aexit__.return_value = False
    gated_http.get.side_effect = _gated_get

    with patch("mr_john_auth.auth_guard.httpx.AsyncClient", return_value=gated_http):
        # 4a. In-flight fetch succeeds after clear() -> rejected and does not pollute store.
        task = asyncio.create_task(gen_store.get_signing_key(rsa_key_pair["kid"]))
        await started_evt.wait()
        gen_store.clear()
        release_evt.set()
        with pytest.raises(jwt.InvalidKeyError, match="changed"):
            await task
        assert gen_store._keys == {}
        assert gen_store._cached_url is None

        # 4b. In-flight fetch fails after clear() -> rejected and does not poison _last_error_at.
        started_evt.clear()
        release_evt.clear()
        should_fail["value"] = True
        task_err = asyncio.create_task(gen_store.get_signing_key(rsa_key_pair["kid"]))
        await started_evt.wait()
        gen_store.clear()
        release_evt.set()
        with pytest.raises(jwt.InvalidKeyError, match="Failed to fetch JWKS"):
            await task_err
        assert gen_store._last_error_at is None
        assert gen_store._last_error_url is None


@pytest.mark.asyncio
async def test_mr_john_auth_client_direct_and_admin_methods():
    """Verify MrJohnAuthClient v2.0 Direct REST API, Admin API, and context manager lifecycle."""
    mock_client = AsyncMock()
    mock_client.post.return_value = MagicMock(
        status_code=200,
        content=b'{"ok":true}',
        raise_for_status=lambda: None,
        json=lambda: {"ok": True},
    )
    mock_client.get.return_value = MagicMock(
        status_code=200,
        content=b'{"users":[]}',
        raise_for_status=lambda: None,
        json=lambda: {"users": []},
    )
    mock_client.patch.return_value = MagicMock(
        status_code=200,
        content=b'{"id":"u1"}',
        raise_for_status=lambda: None,
        json=lambda: {"id": "u1"},
    )
    mock_client.delete.return_value = MagicMock(
        status_code=200,
        content=b'{"message":"deleted"}',
        raise_for_status=lambda: None,
        json=lambda: {"message": "deleted"},
    )

    async with MrJohnAuthClient(
        api_base_url="https://auth.api.mr-john-it.com",
        admin_access_token="admin-jwt",
        http_client=mock_client,
    ) as sdk_client:
        assert await sdk_client.login("u@example.com", "pw") == {"ok": True}
        assert await sdk_client.verify_mfa("mfa-t", "123456") == {"ok": True}
        assert await sdk_client.refresh_tokens("rt") == {"ok": True}
        assert await sdk_client.logout("rt") == {"ok": True}
        assert await sdk_client.get_user_profile("user-jwt") == {"users": []}
        assert await sdk_client.list_users(q="a", role="user", is_active=True) == {"users": []}
        assert await sdk_client.get_user("u1") == {"users": []}
        assert await sdk_client.update_user(
            "u1",
            display_name="Updated",
            global_role="admin",
            is_active=True,
            custom_claims={"pro": True},
        ) == {"id": "u1"}
        assert await sdk_client.revoke_user_sessions("u1") == {"ok": True}
        assert await sdk_client.delete_user("u1") == {"message": "deleted"}

    # Test internally managed AsyncClient lifecycle (__aenter__ / __aexit__ / aclose)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200,
            content=b'{"access_token":"at_1"}',
            raise_for_status=lambda: None,
            json=lambda: {"access_token": "at_1"},
        )
        async with MrJohnAuthClient(api_base_url="https://auth.api.mr-john-it.com") as pooled_client:
            res = await pooled_client.login("u@example.com", "pw")
            assert res["access_token"] == "at_1"
            # Re-entering when _http_client is already set
            async with pooled_client as same_client:
                assert same_client is pooled_client

        # Closing when already None is a safe no-op
        await pooled_client.aclose()


@pytest.mark.asyncio
async def test_sdk_client_prevents_confused_deputy_and_header_injection():
    """Verify get_user_profile and _build_headers never fall back to admin/service credentials on invalid tokens."""
    mock_client = AsyncMock()
    mock_client.get.return_value = MagicMock(
        status_code=200,
        content=b'{"id":"user-1"}',
        raise_for_status=lambda: None,
        json=lambda: {"id": "user-1"},
    )

    async with MrJohnAuthClient(
        api_base_url="https://auth.api.mr-john-it.com",
        client_id="c",
        client_secret="s",
        admin_access_token="admin-jwt",
        http_client=mock_client,
    ) as sdk_client:
        invalid_tokens = [
            "",
            "   ",
            None,
            "tok\r\nX: 1",
            "tok bar",
            "tok\x00null",
            "tok\x85c1",
            123,
        ]
        for bad_token in invalid_tokens:
            with pytest.raises(ValueError):
                await sdk_client.get_user_profile(bad_token)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                sdk_client._build_headers(bad_token)
        assert mock_client.get.call_count == 0

        # Valid user token binds strictly to that user token without leaking service headers.
        profile = await sdk_client.get_user_profile("user-jwt")
        assert profile == {"id": "user-1"}
        assert mock_client.get.call_count == 1
        call_headers = mock_client.get.call_args.kwargs["headers"]
        assert call_headers == {
            "Content-Type": "application/json",
            "Authorization": "Bearer user-jwt",
        }
        assert "X-Client-Id" not in call_headers
        assert "X-Client-Secret" not in call_headers

        # Omitting access_token still uses admin/service credentials for admin endpoints.
        assert sdk_client._build_headers() == {
            "Content-Type": "application/json",
            "Authorization": "Bearer admin-jwt",
        }

    # Service client credentials still apply when admin_access_token is unset and access_token is omitted,
    # while get_user_profile() still rejects invalid user tokens without falling back to X-Client-Id/Secret.
    async with MrJohnAuthClient(
        api_base_url="https://auth.api.mr-john-it.com",
        client_id="c",
        client_secret="s",
        admin_access_token=None,
        http_client=mock_client,
    ) as svc_client:
        assert svc_client._build_headers() == {
            "Content-Type": "application/json",
            "X-Client-Id": "c",
            "X-Client-Secret": "s",
        }
        with pytest.raises(ValueError):
            await svc_client.get_user_profile("")
        assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_sdk_client_validates_admin_user_id_before_http_requests():
    """Verify admin user methods reject path traversal/injection user_ids before HTTP calls while allowing non-UUID IDs."""
    mock_client = AsyncMock()
    ok_resp = MagicMock(
        status_code=200,
        content=b'{"ok":true}',
        raise_for_status=lambda: None,
        json=lambda: {"ok": True},
    )
    mock_client.get.return_value = ok_resp
    mock_client.patch.return_value = ok_resp
    mock_client.post.return_value = ok_resp
    mock_client.delete.return_value = ok_resp

    async with MrJohnAuthClient(
        api_base_url="https://auth.api.mr-john-it.com",
        admin_access_token="admin-jwt",
        http_client=mock_client,
    ) as sdk_client:
        invalid_user_ids = [
            "",
            ".",
            "..",
            "../users/me",
            "a/b",
            "a\\b",
            "u1?a=1",
            "u1#f",
            "u1%2e",
            " u1",
            "u1\n",
            "u1\x00",
            "u1\x7f",
            "u1\x85",
            "a" * 65,
            123,
        ]
        for bad_id in invalid_user_ids:
            with pytest.raises(ValueError):
                await sdk_client.get_user(bad_id)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                await sdk_client.update_user(bad_id, display_name="X")  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                await sdk_client.revoke_user_sessions(bad_id)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                await sdk_client.delete_user(bad_id)  # type: ignore[arg-type]

        assert mock_client.get.call_count == 0
        assert mock_client.patch.call_count == 0
        assert mock_client.post.call_count == 0
        assert mock_client.delete.call_count == 0

        # Non-UUID test IDs, single-dot IDs, max-length 64 IDs, and UUIDs are all permitted.
        valid_ids = [
            "u1",
            "user.1",
            "a" * 64,
            "550e8400-e29b-41d4-a716-446655440000",
        ]
        for valid_id in valid_ids:
            assert await sdk_client.get_user(valid_id) == {"ok": True}
            assert await sdk_client.update_user(valid_id, display_name="Valid") == {"ok": True}
            assert await sdk_client.revoke_user_sessions(valid_id) == {"ok": True}
            assert await sdk_client.delete_user(valid_id) == {"ok": True}

        assert mock_client.get.call_count == len(valid_ids)
        assert mock_client.patch.call_count == len(valid_ids)
        assert mock_client.post.call_count == len(valid_ids)
        assert mock_client.delete.call_count == len(valid_ids)


@pytest.mark.asyncio
async def test_auth_user_claim_fallbacks_and_oneshot_client():
    """Verify AuthUser custom_claims fallbacks (plan_tier, bool tier, singular role) and one-shot HTTP client."""
    # Scoped custom_claims dict with plan_tier and singular role
    scoped_user = AuthUser(
        id="u-scoped",
        email="s@example.com",
        custom_claims={"svc-a": {"plan_tier": "starter", "role": "reviewer"}},
    )
    assert scoped_user.get_service_plan("svc-a") == "starter"
    assert scoped_user.get_service_roles("svc-a") == ["reviewer"]

    # Boolean tier flag in custom_claims (e.g. {"pro": True}) and fallback to "free"
    bool_tier_user = AuthUser(id="u-bool", email="b@example.com", custom_claims={"pro": True})
    assert bool_tier_user.get_service_plan("svc-b") == "pro"
    assert bool_tier_user.get_service_roles("svc-b") == []

    no_tier_user = AuthUser(id="u-none", email="n@example.com", custom_claims={"other": 1})
    assert no_tier_user.get_service_plan("svc-c") == "free"

    empty_user = AuthUser(id="u-empty", email="e@example.com")
    assert empty_user.get_service_plan("svc-d") == "free"
    assert empty_user.get_service_roles("svc-d") == []

    admin_user = AuthUser(id="u-admin", email="a@example.com", global_role="admin")
    assert admin_user.has_minimum_plan("enterprise") is True

    # One-shot MrJohnAuthClient request (without async with) + 204 No Content decoding
    oneshot_client = MrJohnAuthClient(api_base_url="https://auth.api.mr-john-it.com")
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = MagicMock(
            status_code=204,
            content=b"",
            raise_for_status=lambda: None,
        )
        res = await oneshot_client.logout("rt-1")
        assert res == {}

