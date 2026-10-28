"""Unit tests for mr_john_auth SDK (AsyncJWKSStore, AuthUser, auth_guard, MrJohnAuthClient).

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
    AuthClientData,
    AuthUser,
    MrJohnAuthClient,
    ServiceEntitlement,
    ServicePermissionData,
    auth_guard,
    get_current_user,
    get_optional_user,
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
async def test_get_current_user_valid_token_and_helpers(rsa_key_pair):
    """Verify valid RS256 token is decoded and all AuthUser helper methods work."""
    client_id = "stock-research"
    auth_guard.SERVICE_CLIENT_ID = client_id

    now = int(time.time())
    payload = {
        "sub": "user-uuid-123",
        "email": "user@example.com",
        "name": "Jane Trader",
        "global_role": "user",
        "mfa_verified": True,
        "amr": ["pwd", "totp"],
        "ver": 1,
        "services": {
            client_id: {
                "plan": "pro",
                "roles": ["analyst", "trader"],
                "daily_quota": 500,
            }
        },
        "iss": auth_guard.AUTH_ISSUER,
        "aud": client_id,
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, rsa_key_pair["private_pem"], algorithm="RS256", headers={"kid": rsa_key_pair["kid"]})

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
async def test_require_mfa_and_global_admin_dependencies():
    """Verify require_mfa and require_global_admin dependencies."""
    verified_user = AuthUser(id="u1", email="a@b.com", mfa_verified=True, global_role="user")
    unverified_user = AuthUser(id="u2", email="b@b.com", mfa_verified=False, global_role="user")
    admin_user = AuthUser(id="admin1", email="admin@b.com", mfa_verified=False, global_role="admin")

    assert await require_mfa(verified_user) == verified_user
    with pytest.raises(HTTPException) as exc_info:
        await require_mfa(unverified_user)
    assert exc_info.value.status_code == 403
    assert "Two-factor authentication" in exc_info.value.detail

    assert await require_global_admin(admin_user) == admin_user
    with pytest.raises(HTTPException) as exc_info:
        await require_global_admin(verified_user)
    assert exc_info.value.status_code == 403
    assert "Global administrator" in exc_info.value.detail


@pytest.mark.asyncio
async def test_jwks_store_double_checked_lock_hit(rsa_key_pair):
    """Verify double-checked locking returns key if primed by concurrent task while awaiting lock."""
    store = AsyncJWKSStore("https://auth.example.com/.well-known/jwks.json")
    mock_key = RSAAlgorithm.from_jwk(rsa_key_pair["jwk"])

    orig_acquire = store._lock.acquire

    async def side_effect_acquire():
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
    mock_resp.json.return_value = {"keys": [rsa_key_pair["jwk"]]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with pytest.raises(jwt.InvalidKeyError, match="Key ID unlisted-key not found in JWKS"):
            await store.get_signing_key("unlisted-key")


@pytest.mark.asyncio
async def test_require_plan_and_require_role():
    """Verify require_plan and require_role check permissions and allow global_admin bypass."""
    client_id = "stock-research"
    pro_user = AuthUser(
        id="u1",
        email="trader@b.com",
        services={client_id: {"plan": "pro", "roles": ["trader", "analyst"]}},
    )
    admin_user = AuthUser(id="admin1", email="admin@b.com", global_role="admin")

    free_checker = require_plan("free", client_id)
    starter_checker = require_plan("starter", client_id)
    pro_checker = require_plan("pro", client_id)
    enterprise_checker = require_plan("enterprise", client_id)

    assert await free_checker(pro_user) == pro_user
    assert await starter_checker(pro_user) == pro_user
    assert await pro_checker(pro_user) == pro_user

    with pytest.raises(HTTPException) as exc_info:
        await enterprise_checker(pro_user)
    assert exc_info.value.status_code == 403
    assert "requires at least 'enterprise' plan" in exc_info.value.detail

    # Global admin bypasses plan check
    assert await enterprise_checker(admin_user) == admin_user

    # require_role checks
    role_single = require_role("trader", client_id)
    role_multi = require_role(["editor", "analyst"], client_id)
    role_missing = require_role("super_editor", client_id)

    assert await role_single(pro_user) == pro_user
    assert await role_multi(pro_user) == pro_user
    with pytest.raises(HTTPException) as exc_info:
        await role_missing(pro_user)
    assert exc_info.value.status_code == 403
    assert await role_missing(admin_user) == admin_user


@pytest.mark.asyncio
async def test_mr_john_auth_client_methods():
    """Test MrJohnAuthClient SDK methods with mocked httpx responses."""
    sdk_client = MrJohnAuthClient(
        api_base_url="https://auth-api.mr-john.dev",
        client_id="stock-research",
        client_secret="mjc_secret_123",
    )

    perm_payload = {
        "id": "perm-1",
        "user_id": "user-001",
        "client_id": "stock-research",
        "plan_tier": "pro",
        "roles": ["trader"],
        "custom_claims": {"beta": True},
        "created_at": "2026-10-29T00:00:00Z",
        "updated_at": "2026-10-29T00:00:00Z",
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
         patch("httpx.AsyncClient.patch", new_callable=AsyncMock) as mock_patch, \
         patch("httpx.AsyncClient.delete", new_callable=AsyncMock) as mock_delete:

        # 1. get_user_permission
        r_single = MagicMock()
        r_single.json.return_value = perm_payload
        r_single.raise_for_status = MagicMock()
        mock_get.return_value = r_single

        perm = await sdk_client.get_user_permission("user-001")
        assert isinstance(perm, ServicePermissionData)
        assert perm.plan_tier == "pro"

        # 2. list_user_permissions & get_my_permissions
        r_list = MagicMock()
        r_list.json.return_value = {"permissions": [perm_payload], "total": 1}
        r_list.raise_for_status = MagicMock()
        mock_get.return_value = r_list

        perms = await sdk_client.list_user_permissions("user-001")
        assert len(perms) == 1 and perms[0].client_id == "stock-research"

        my_perms = await sdk_client.get_my_permissions("user_jwt_token")
        assert len(my_perms) == 1

        # 3. upsert_user_permission
        mock_put.return_value = r_single
        upserted = await sdk_client.upsert_user_permission(
            user_id="user-001",
            plan_tier="pro",
            roles=["trader"],
            custom_claims={"beta": True},
        )
        assert upserted.plan_tier == "pro"

        # 4. delete_user_permission
        r_del = MagicMock()
        r_del.json.return_value = {"message": "deleted"}
        r_del.raise_for_status = MagicMock()
        mock_delete.return_value = r_del
        del_resp = await sdk_client.delete_user_permission("user-001")
        assert del_resp["message"] == "deleted"

        # 5. exchange_code_for_tokens & refresh_tokens & get_user_profile
        r_tok = MagicMock()
        r_tok.json.return_value = {"access_token": "at_123", "refresh_token": "rt_123", "expires_in": 300}
        r_tok.raise_for_status = MagicMock()
        mock_post.return_value = r_tok

        tok_data = await sdk_client.exchange_code_for_tokens("code1", "verifier1", "https://cb")
        assert tok_data["access_token"] == "at_123"

        ref_data = await sdk_client.refresh_tokens("rt_123")
        assert ref_data["refresh_token"] == "rt_123"

        # Also test public client branch (no client_secret)
        pub_client = MrJohnAuthClient(client_id="diagramonitor", client_secret="")
        await pub_client.exchange_code_for_tokens("code1", "verifier1", "https://cb")
        await pub_client.refresh_tokens("rt_123")

        r_prof = MagicMock()
        r_prof.json.return_value = {"id": "user-001", "email": "u@example.com"}
        r_prof.raise_for_status = MagicMock()
        mock_get.return_value = r_prof
        prof = await sdk_client.get_user_profile("user_jwt")
        assert prof["id"] == "user-001"

        # 6. Admin Client operations (list_clients, create_client, update_client, rotate_client_secret)
        admin_sdk = MrJohnAuthClient(admin_access_token="admin_jwt")
        client_item = {
            "client_id": "stock-research",
            "client_name": "Stock Research",
            "client_type": "confidential",
            "redirect_uris": [],
            "allowed_scopes": ["openid"],
            "is_active": True,
            "client_secret": "mjc_new",
        }
        r_clients = MagicMock()
        r_clients.json.return_value = {"clients": [client_item], "total": 1}
        r_clients.raise_for_status = MagicMock()
        mock_get.return_value = r_clients
        c_list = await admin_sdk.list_clients()
        assert len(c_list) == 1 and isinstance(c_list[0], AuthClientData)

        r_client_single = MagicMock()
        r_client_single.json.return_value = client_item
        r_client_single.raise_for_status = MagicMock()
        mock_post.return_value = r_client_single
        mock_patch.return_value = r_client_single

        created_c = await admin_sdk.create_client("stock-research", "Stock Research", "confidential")
        assert created_c.client_secret == "mjc_new"

        updated_c = await admin_sdk.update_client(
            "stock-research",
            client_name="Updated",
            client_type="confidential",
            redirect_uris=["https://cb"],
            allowed_scopes=["openid"],
            is_active=True,
        )
        assert updated_c.client_id == "stock-research"

        rotated_c = await admin_sdk.rotate_client_secret("stock-research")
        assert rotated_c.client_secret == "mjc_new"
