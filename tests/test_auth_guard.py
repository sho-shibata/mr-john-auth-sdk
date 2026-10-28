"""Unit tests for mr_john_auth SDK (AsyncJWKSStore, AuthUser, auth_guard).

All external HTTP calls are strictly mocked.
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import pytest

from mr_john_auth import (
    AsyncJWKSStore,
    AuthUser,
    auth_guard,
    get_current_user,
    require_mfa,
    require_plan,
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
        "kid": "test-key-01",
    }


@pytest.mark.asyncio
async def test_jwks_store_fetch_and_cache(rsa_key_pair):
    """Verify AsyncJWKSStore fetches keys and caches them until TTL."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json", cache_ttl=3600)
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"keys": [rsa_key_pair["jwk"]]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        # First call: network fetch
        key = await store.get_signing_key(rsa_key_pair["kid"])
        assert key is not None
        assert mock_get.call_count == 1

        # Second call: cached, no network fetch
        key_cached = await store.get_signing_key(rsa_key_pair["kid"])
        assert key_cached == key
        assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_jwks_store_unknown_kid_cooldown(rsa_key_pair):
    """Verify unknown kid activates cooldown protection against cache-busting DoS."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json", min_refetch_cooldown=300)
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"keys": [rsa_key_pair["jwk"]]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        # Prime the cache with known key
        await store.get_signing_key(rsa_key_pair["kid"])

        # Immediate request with unknown key should trigger cooldown exception without fetching
        with pytest.raises(jwt.InvalidKeyError, match="refetch cooldown active"):
            await store.get_signing_key("attacker-random-kid")
        assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_jwks_store_network_failure():
    """Verify network failures during JWKS fetch raise InvalidKeyError with message."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Connection timeout")

        with pytest.raises(jwt.InvalidKeyError, match="Failed to fetch JWKS"):
            await store.get_signing_key("any-kid")


@pytest.mark.asyncio
async def test_get_current_user_valid_token(rsa_key_pair):
    """Verify valid RS256 token is decoded and parsed into AuthUser."""
    client_id = "stock-research"
    auth_guard.SERVICE_CLIENT_ID = client_id

    # Create signed RS256 token
    now = int(time.time())
    payload = {
        "sub": "user-uuid-123",
        "email": "user@example.com",
        "name": "Jane Trader",
        "global_role": "user",
        "mfa_verified": True,
        "amr": ["pwd", "totp"],
        "ver": 1,
        "services": {client_id: {"plan": "pro", "roles": ["analyst"]}},
        "iss": auth_guard.AUTH_ISSUER,
        "aud": client_id,
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, rsa_key_pair["private_pem"], algorithm="RS256", headers={"kid": rsa_key_pair["kid"]})

    # Mock jwks_store in auth_guard
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
        assert user.get_service_plan(client_id) == "pro"
        assert user.has_service_role("analyst", client_id) is True
        assert user.has_service_role("admin", client_id) is False


@pytest.mark.asyncio
async def test_get_current_user_missing_credentials():
    """Verify missing credentials raise 401 Unauthorized."""
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(None)
    assert exc_info.value.status_code == 401
    assert "Authorization header missing" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_user_missing_kid(rsa_key_pair):
    """Verify token missing kid in header raises 401 Unauthorized."""
    now = int(time.time())
    token = jwt.encode(
        {"sub": "u1", "iss": auth_guard.AUTH_ISSUER, "aud": auth_guard.SERVICE_CLIENT_ID, "exp": now + 3600},
        rsa_key_pair["private_pem"],
        algorithm="RS256",
        # No kid in headers
    )
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(creds)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_expired_token(rsa_key_pair):
    """Verify expired token raises 401 Unauthorized with expired message."""
    client_id = auth_guard.SERVICE_CLIENT_ID
    past = int(time.time()) - 3600
    payload = {
        "sub": "user-uuid-123",
        "email": "user@example.com",
        "iss": auth_guard.AUTH_ISSUER,
        "aud": client_id,
        "iat": past - 100,
        "exp": past,
    }
    token = jwt.encode(payload, rsa_key_pair["private_pem"], algorithm="RS256", headers={"kid": rsa_key_pair["kid"]})

    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])
    with patch.object(auth_guard.jwks_store, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
        mock_get_key.return_value = mock_key

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(creds)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_user_audience_mismatch(rsa_key_pair):
    """Verify token for another service is rejected (Confused Deputy Attack prevention)."""
    auth_guard.SERVICE_CLIENT_ID = "target-service"
    now = int(time.time())
    payload = {
        "sub": "user-uuid-123",
        "email": "user@example.com",
        "iss": auth_guard.AUTH_ISSUER,
        "aud": "attacker-wrong-service",
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, rsa_key_pair["private_pem"], algorithm="RS256", headers={"kid": rsa_key_pair["kid"]})

    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])
    with patch.object(auth_guard.jwks_store, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
        mock_get_key.return_value = mock_key

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(creds)
        assert exc_info.value.status_code == 401
        assert "Token verification failed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_require_mfa_dependency():
    """Verify require_mfa dependency enforces TOTP completion."""
    verified_user = AuthUser(id="u1", email="a@b.com", mfa_verified=True)
    unverified_user = AuthUser(id="u2", email="b@b.com", mfa_verified=False)

    # MFA verified -> passes
    res = await require_mfa(verified_user)
    assert res == verified_user

    # MFA unverified -> 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        await require_mfa(unverified_user)
    assert exc_info.value.status_code == 403
    assert "Two-factor authentication" in exc_info.value.detail


@pytest.mark.asyncio
async def test_jwks_store_double_checked_lock_hit(rsa_key_pair):
    """Verify double-checked locking returns key if primed by concurrent task while awaiting lock."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json")
    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])

    orig_acquire = store._lock.acquire

    async def side_effect_acquire():
        # Populate keys right before lock is granted to simulate race condition
        store._keys[rsa_key_pair["kid"]] = mock_key
        store._last_fetched_at = time.monotonic()
        return await orig_acquire()

    with patch.object(store._lock, "acquire", side_effect=side_effect_acquire):
        key = await store.get_signing_key(rsa_key_pair["kid"])
        assert key == mock_key


@pytest.mark.asyncio
async def test_jwks_store_key_not_in_fresh_jwks(rsa_key_pair):
    """Verify InvalidKeyError is raised if fresh JWKS response does not contain the requested kid."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json")

    mock_resp = MagicMock()
    # Response contains other key, not 'unlisted-key'
    mock_resp.json.return_value = {"keys": [rsa_key_pair["jwk"]]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with pytest.raises(jwt.InvalidKeyError, match="Key ID unlisted-key not found in JWKS"):
            await store.get_signing_key("unlisted-key")


@pytest.mark.asyncio
async def test_require_plan_hierarchy():
    """Verify require_plan checks plan tiers hierarchically (free < starter < pro < enterprise)."""
    client_id = "stock-research"
    pro_user = AuthUser(
        id="u1",
        email="trader@b.com",
        services={client_id: {"plan": "pro"}},
    )

    free_checker = require_plan("free", client_id)
    starter_checker = require_plan("starter", client_id)
    pro_checker = require_plan("pro", client_id)
    enterprise_checker = require_plan("enterprise", client_id)

    # Pro user can access free, starter, pro
    assert await free_checker(pro_user) == pro_user
    assert await starter_checker(pro_user) == pro_user
    assert await pro_checker(pro_user) == pro_user

    # Pro user cannot access enterprise
    with pytest.raises(HTTPException) as exc_info:
        await enterprise_checker(pro_user)
    assert exc_info.value.status_code == 403
    assert "requires at least 'enterprise' plan" in exc_info.value.detail
