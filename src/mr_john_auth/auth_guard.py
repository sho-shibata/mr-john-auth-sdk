"""Mr. John Auth Guard & Client SDK for FastAPI Child Services

Drop-in authentication, role-based access control, TOTP MFA step-up verification,
and API client for ServicePermission, AuthClient, and OAuth/RTR token operations.

Features:
- Stateless RS256 JWT verification using cached JWKS from mr-john-auth.
- Asynchronous non-blocking JWKS fetching with httpx.AsyncClient.
- Stale-While-Revalidate resilience: serves cached keys if JWKS refresh fails transiently.
- Cache-busting DoS defense with 5-minute cooldown on unknown Key IDs (kid).
- Strict Audience (aud) validation to prevent token replay between services.
- Dynamic environment configuration & programmatic `configure()` support (immune to import order).
- Step-up MFA verification guard (require_mfa), Subscription plan guard (require_plan),
  Service role guard (require_role), Global Admin guard (require_global_admin),
  and optional user resolver (get_optional_user).
- Full async HTTP client (MrJohnAuthClient) with connection pooling for managing SERVICE_PERMISSIONS,
  AUTH_CLIENTS, and OAuth 2.0 PKCE / RTR token exchange.
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Union
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

logger = logging.getLogger("mr_john_auth")

# Default fallback constants; dynamically resolved via helper functions to avoid import-order bugs
_DEFAULT_AUTH_API_URL = "https://auth-api.mr-john.dev"
_DEFAULT_AUTH_ISSUER = "https://auth.mr-john.dev"
_DEFAULT_CLIENT_ID = "default-client"

AUTH_API_URL = os.getenv("MR_JOHN_AUTH_API_URL", _DEFAULT_AUTH_API_URL)
AUTH_JWKS_URL = os.getenv("MR_JOHN_AUTH_JWKS_URL", f"{AUTH_API_URL.rstrip('/')}/.well-known/jwks.json")
AUTH_ISSUER = os.getenv("MR_JOHN_AUTH_ISSUER", _DEFAULT_AUTH_ISSUER)
SERVICE_CLIENT_ID = os.getenv("MR_JOHN_CLIENT_ID", _DEFAULT_CLIENT_ID)
SERVICE_CLIENT_SECRET = os.getenv("MR_JOHN_CLIENT_SECRET", "")

security = HTTPBearer(auto_error=False)


def _resolve_api_url() -> str:
    if AUTH_API_URL != _DEFAULT_AUTH_API_URL:
        return AUTH_API_URL
    return os.getenv("MR_JOHN_AUTH_API_URL", _DEFAULT_AUTH_API_URL)


def _resolve_jwks_url() -> str:
    default_jwks = f"{_DEFAULT_AUTH_API_URL}/.well-known/jwks.json"
    if AUTH_JWKS_URL != default_jwks:
        return AUTH_JWKS_URL
    env_jwks = os.getenv("MR_JOHN_AUTH_JWKS_URL")
    if env_jwks:
        return env_jwks
    return f"{_resolve_api_url().rstrip('/')}/.well-known/jwks.json"


def _resolve_issuer() -> str:
    if AUTH_ISSUER != _DEFAULT_AUTH_ISSUER:
        return AUTH_ISSUER
    return os.getenv("MR_JOHN_AUTH_ISSUER", _DEFAULT_AUTH_ISSUER)


def _resolve_client_id() -> str:
    if SERVICE_CLIENT_ID != _DEFAULT_CLIENT_ID:
        return SERVICE_CLIENT_ID
    return os.getenv("MR_JOHN_CLIENT_ID", _DEFAULT_CLIENT_ID)


def _resolve_client_secret() -> str:
    if SERVICE_CLIENT_SECRET != "":
        return SERVICE_CLIENT_SECRET
    return os.getenv("MR_JOHN_CLIENT_SECRET", "")


def configure(
    *,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    api_url: Optional[str] = None,
    jwks_url: Optional[str] = None,
    issuer: Optional[str] = None,
) -> None:
    """Programmatically configure mr_john_auth SDK settings at application startup."""
    global AUTH_API_URL, AUTH_JWKS_URL, AUTH_ISSUER, SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET
    if api_url is not None:
        AUTH_API_URL = api_url.rstrip("/")
    if jwks_url is not None:
        AUTH_JWKS_URL = jwks_url
    elif api_url is not None:
        AUTH_JWKS_URL = f"{AUTH_API_URL}/.well-known/jwks.json"
    if issuer is not None:
        AUTH_ISSUER = issuer
    if client_id is not None:
        SERVICE_CLIENT_ID = client_id
    if client_secret is not None:
        SERVICE_CLIENT_SECRET = client_secret
    jwks_store.jwks_url = _resolve_jwks_url()


class AsyncJWKSStore:
    """Async-safe, thread-safe JWKS cache with unknown-kid DoS rate limiting and Stale-While-Revalidate."""

    def __init__(self, jwks_url: Optional[str] = None, cache_ttl: int = 3600, min_refetch_cooldown: int = 300):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.min_refetch_cooldown = min_refetch_cooldown
        self._keys: Dict[str, Any] = {}
        self._last_fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    def clear(self) -> None:
        """Clear cached JWKS keys and reset fetch timestamp."""
        self._keys.clear()
        self._last_fetched_at = 0.0

    async def get_signing_key(self, kid: str) -> Any:
        now = time.monotonic()
        if kid in self._keys and (now - self._last_fetched_at) < self.cache_ttl:
            return self._keys[kid]

        async with self._lock:
            now = time.monotonic()
            if kid in self._keys and (now - self._last_fetched_at) < self.cache_ttl:
                return self._keys[kid]

            # Cooldown protection against Cache Busting DoS
            if self._keys and (now - self._last_fetched_at) < self.min_refetch_cooldown:
                if kid not in self._keys:
                    raise jwt.InvalidKeyError(f"Key ID {kid} not found (refetch cooldown active).")

            target_url = self.jwks_url or _resolve_jwks_url()
            async with httpx.AsyncClient(timeout=5.0) as client:
                try:
                    res = await client.get(target_url)
                    res.raise_for_status()
                    jwks_data = res.json()
                except Exception as exc:
                    # Stale-While-Revalidate fallback: if key is already in cache, serve it despite transient error
                    if kid in self._keys:
                        logger.warning(
                            "Failed to refresh JWKS from %s (%s); serving cached signing key for kid=%s",
                            target_url,
                            exc,
                            kid,
                        )
                        return self._keys[kid]
                    raise jwt.InvalidKeyError(f"Failed to fetch JWKS from {target_url}: {exc}") from exc

            new_keys: Dict[str, Any] = {}
            for jwk_item in jwks_data.get("keys", []):
                k_id = jwk_item.get("kid")
                if k_id and jwk_item.get("kty") == "RSA":
                    new_keys[k_id] = RSAAlgorithm.from_jwk(jwk_item)

            self._keys = new_keys
            self._last_fetched_at = time.monotonic()

            if kid not in self._keys:
                raise jwt.InvalidKeyError(f"Key ID {kid} not found in JWKS.")
            return self._keys[kid]


jwks_store = AsyncJWKSStore()

PLAN_HIERARCHY: Dict[str, int] = {
    "free": 0,
    "starter": 1,
    "pro": 2,
    "enterprise": 3,
}


class ServiceEntitlement(BaseModel):
    """Structured representation of a user's entitlement for a specific service."""
    client_id: str
    plan: str = "free"
    roles: List[str] = Field(default_factory=lambda: ["member"])
    custom_claims: Dict[str, Any] = Field(default_factory=dict)


class ServicePermissionData(BaseModel):
    """Data model representing a SERVICE_PERMISSIONS record from mr-john-auth API."""
    id: str
    user_id: str
    client_id: str
    plan_tier: str
    roles: List[str]
    custom_claims: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AuthClientData(BaseModel):
    """Data model representing an AUTH_CLIENTS record from mr-john-auth API."""
    client_id: str
    client_name: str
    client_type: str
    redirect_uris: List[str] = Field(default_factory=list)
    allowed_scopes: List[str] = Field(default_factory=list)
    is_active: bool = True
    created_at: Optional[datetime] = None
    client_secret: Optional[str] = None


class AuthUser(BaseModel):
    """Authenticated user entity extracted from cryptographically verified RS256 JWT."""
    id: str  # sub (Universal UUID across all ecosystem services)
    email: str
    display_name: Optional[str] = None
    global_role: str = "user"
    mfa_verified: bool = False
    amr: List[str] = []
    token_version: int = 1
    services: Dict[str, Any] = {}

    @property
    def is_global_admin(self) -> bool:
        """Check if user holds the global 'admin' role across the Mr. John ecosystem."""
        return self.global_role == "admin"

    def get_service_entitlement(self, service_id: Optional[str] = None) -> ServiceEntitlement:
        """Return structured ServiceEntitlement (plan, roles, custom_claims) for a service."""
        target_id = service_id or _resolve_client_id()
        raw = self.services.get(target_id, {})
        if not isinstance(raw, dict):
            return ServiceEntitlement(client_id=target_id)
        plan = str(raw.get("plan", "free"))
        roles = list(raw.get("roles", ["member"]))
        custom = {k: v for k, v in raw.items() if k not in ("plan", "roles")}
        return ServiceEntitlement(
            client_id=target_id,
            plan=plan,
            roles=roles,
            custom_claims=custom,
        )

    def get_service_plan(self, service_id: Optional[str] = None) -> str:
        """Get plan tier for a specific service (e.g. 'free', 'starter', 'pro', 'enterprise')."""
        target_id = service_id or _resolve_client_id()
        raw = self.services.get(target_id, {})
        if not isinstance(raw, dict):
            return "free"
        return str(raw.get("plan", "free"))

    def get_service_roles(self, service_id: Optional[str] = None) -> List[str]:
        """Get list of roles assigned to the user in a specific service."""
        target_id = service_id or _resolve_client_id()
        raw = self.services.get(target_id, {})
        if not isinstance(raw, dict):
            return []
        roles = raw.get("roles", [])
        return list(roles) if isinstance(roles, list) else []

    def has_service_role(self, role: str, service_id: Optional[str] = None) -> bool:
        """Check if user has a specific role in this service."""
        return role in self.get_service_roles(service_id)

    def has_any_service_role(self, roles: Sequence[str], service_id: Optional[str] = None) -> bool:
        """Check if user has at least one of the specified roles in this service."""
        user_roles = set(self.get_service_roles(service_id))
        return any(r in user_roles for r in roles)

    def has_minimum_plan(self, minimum_plan: str, service_id: Optional[str] = None) -> bool:
        """Check if user's plan on the service meets or exceeds minimum_plan."""
        min_rank = PLAN_HIERARCHY.get(minimum_plan.lower(), 0)
        user_rank = PLAN_HIERARCHY.get(self.get_service_plan(service_id).lower(), 0)
        return user_rank >= min_rank

    def get_custom_claim(self, key: str, default: Any = None, service_id: Optional[str] = None) -> Any:
        """Retrieve a custom claim from the user's service permissions."""
        entitlement = self.get_service_entitlement(service_id)
        return entitlement.custom_claims.get(key, default)


async def _verify_token_to_user(token: str) -> AuthUser:
    """Internal helper to verify RS256 JWT and construct AuthUser."""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise jwt.InvalidTokenError("Missing or invalid 'kid' in token header.")

    signing_key = await jwks_store.get_signing_key(kid)

    payload = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        issuer=_resolve_issuer(),
        audience=_resolve_client_id(),
        options={
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
            "require": ["exp", "iss", "sub", "aud"],
        },
    )

    return AuthUser(
        id=str(payload["sub"]),
        email=payload.get("email", ""),
        display_name=payload.get("name"),
        global_role=payload.get("global_role", "user"),
        mfa_verified=bool(payload.get("mfa_verified", False)),
        amr=payload.get("amr", []),
        token_version=int(payload.get("ver", 1)),
        services=payload.get("services", {}),
    )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthUser:
    """FastAPI dependency to verify RS256 JWT locally in <1 millisecond."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return await _verify_token_to_user(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[AuthUser]:
    """FastAPI dependency for endpoints that support both guest and authenticated users."""
    if not credentials or not credentials.credentials:
        return None
    try:
        return await _verify_token_to_user(credentials.credentials)
    except jwt.PyJWTError:
        return None


async def require_mfa(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """Enforce TOTP Two-Factor Authentication for sensitive operations."""
    if not user.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Two-factor authentication (TOTP) is required for this action.",
        )
    return user


async def require_global_admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """Enforce global administrator privileges (global_role == 'admin')."""
    if not user.is_global_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Global administrator privileges are required for this action.",
        )
    return user


def require_plan(minimum_plan: str, service_id: Optional[str] = None):
    """Dependency factory to enforce plan tiers hierarchically (free < starter < pro < enterprise)."""
    min_rank = PLAN_HIERARCHY.get(minimum_plan.lower(), 0)

    async def plan_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        target_id = service_id or _resolve_client_id()
        if user.is_global_admin:
            return user
        plan = user.get_service_plan(target_id).lower()
        user_rank = PLAN_HIERARCHY.get(plan, 0)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This feature requires at least '{minimum_plan}' plan on {target_id}",
            )
        return user
    return plan_checker


def require_role(required_roles: Union[str, Sequence[str]], service_id: Optional[str] = None):
    """Dependency factory to enforce service-specific role(s). Global admins pass automatically."""
    roles_list = [required_roles] if isinstance(required_roles, str) else list(required_roles)

    async def role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        target_id = service_id or _resolve_client_id()
        if user.is_global_admin or user.has_any_service_role(roles_list, target_id):
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Required role(s) {roles_list} on '{target_id}' not satisfied.",
        )
    return role_checker


class MrJohnAuthClient:
    """Async HTTP Client for interacting with mr-john-auth API (ServicePermissions, AuthClients, OAuth/RTR tokens).

    Supports authentication via:
    1. Confidential Client credentials (`client_id` + `client_secret`) for backend-to-backend management of its own service permissions.
    2. Global Admin Bearer `access_token` for cross-service administration and client management.

    Supports both standalone calls and persistent connection pooling via `async with MrJohnAuthClient(...) as client:`.
    """

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        admin_access_token: Optional[str] = None,
        timeout: float = 10.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.api_base_url = (api_base_url or _resolve_api_url()).rstrip("/")
        self.client_id = client_id or _resolve_client_id()
        self.client_secret = client_secret if client_secret is not None else _resolve_client_secret()
        self.admin_access_token = admin_access_token
        self.timeout = timeout
        self._http_client = http_client

    async def __aenter__(self) -> "MrJohnAuthClient":
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying persistent httpx.AsyncClient if open."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _build_headers(self, access_token: Optional[str] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        token = access_token or self.admin_access_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif self.client_id and self.client_secret:
            headers["X-Client-Id"] = self.client_id
            headers["X-Client-Secret"] = self.client_secret
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        if self._http_client is not None:
            fn = getattr(self._http_client, method)
            kwargs: Dict[str, Any] = {}
            if headers is not None:
                kwargs["headers"] = headers
            if json is not None:
                kwargs["json"] = json
            res = await fn(url, **kwargs)
            res.raise_for_status()
            return res

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            fn = getattr(client, method)
            kwargs = {}
            if headers is not None:
                kwargs["headers"] = headers
            if json is not None:
                kwargs["json"] = json
            res = await fn(url, **kwargs)
            res.raise_for_status()
            return res

    # --- 1. SERVICE_PERMISSIONS Operations ---
    async def get_my_permissions(self, user_access_token: str) -> List[ServicePermissionData]:
        """Fetch all service permissions for the owner of `user_access_token`."""
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/users/me/permissions",
            headers=self._build_headers(user_access_token),
        )
        data = res.json()
        return [ServicePermissionData.model_validate(item) for item in data.get("permissions", [])]

    async def get_user_permission(
        self,
        user_id: str,
        client_id: Optional[str] = None,
    ) -> ServicePermissionData:
        """Fetch a user's SERVICE_PERMISSIONS record for a specific client_id."""
        target_client = client_id or self.client_id
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/permissions/users/{user_id}/{target_client}",
            headers=self._build_headers(),
        )
        return ServicePermissionData.model_validate(res.json())

    async def list_user_permissions(self, user_id: str) -> List[ServicePermissionData]:
        """List all SERVICE_PERMISSIONS records for a user (Admin sees all; Confidential Client sees own)."""
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/permissions/users/{user_id}",
            headers=self._build_headers(),
        )
        data = res.json()
        return [ServicePermissionData.model_validate(item) for item in data.get("permissions", [])]

    async def upsert_user_permission(
        self,
        user_id: str,
        plan_tier: str = "free",
        roles: Optional[List[str]] = None,
        custom_claims: Optional[Dict[str, Any]] = None,
        client_id: Optional[str] = None,
    ) -> ServicePermissionData:
        """Register or update (Upsert) a user's SERVICE_PERMISSIONS record."""
        target_client = client_id or self.client_id
        payload = {
            "plan_tier": plan_tier,
            "roles": roles if roles is not None else ["member"],
            "custom_claims": custom_claims if custom_claims is not None else {},
        }
        res = await self._request(
            "put",
            f"{self.api_base_url}/api/v1/permissions/users/{user_id}/{target_client}",
            headers=self._build_headers(),
            json=payload,
        )
        return ServicePermissionData.model_validate(res.json())

    async def delete_user_permission(
        self,
        user_id: str,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Delete a user's SERVICE_PERMISSIONS record for a client_id."""
        target_client = client_id or self.client_id
        res = await self._request(
            "delete",
            f"{self.api_base_url}/api/v1/permissions/users/{user_id}/{target_client}",
            headers=self._build_headers(),
        )
        return res.json()

    # --- 2. OAuth 2.0 PKCE & RTR Token Operations (For Child Service BFFs) ---
    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange OAuth 2.0 PKCE authorization_code for access_token and refresh_token."""
        payload: Dict[str, Any] = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/token",
            json=payload,
        )
        return res.json()

    async def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """Rotate refresh_token and obtain a new access_token + refresh_token pair."""
        payload: Dict[str, Any] = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": refresh_token,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/token",
            json=payload,
        )
        return res.json()

    async def get_user_profile(self, user_access_token: str) -> Dict[str, Any]:
        """Fetch live user profile and permissions from `/api/v1/users/me`."""
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/users/me",
            headers=self._build_headers(user_access_token),
        )
        return res.json()

    # --- 3. AUTH_CLIENTS Administration (Global Admin Only) ---
    async def list_clients(self) -> List[AuthClientData]:
        """List all registered AuthClient applications."""
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/clients",
            headers=self._build_headers(),
        )
        data = res.json()
        return [AuthClientData.model_validate(item) for item in data.get("clients", [])]

    async def create_client(
        self,
        client_id: str,
        client_name: str,
        client_type: str = "public",
        redirect_uris: Optional[List[str]] = None,
        allowed_scopes: Optional[List[str]] = None,
        is_active: bool = True,
    ) -> AuthClientData:
        """Register a new AuthClient application."""
        payload = {
            "client_id": client_id,
            "client_name": client_name,
            "client_type": client_type,
            "redirect_uris": redirect_uris or [],
            "allowed_scopes": allowed_scopes or ["openid", "profile", "email"],
            "is_active": is_active,
        }
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/clients",
            headers=self._build_headers(),
            json=payload,
        )
        return AuthClientData.model_validate(res.json())

    async def update_client(
        self,
        client_id: str,
        client_name: Optional[str] = None,
        client_type: Optional[str] = None,
        redirect_uris: Optional[List[str]] = None,
        allowed_scopes: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
    ) -> AuthClientData:
        """Update an existing AuthClient application."""
        payload: Dict[str, Any] = {}
        if client_name is not None:
            payload["client_name"] = client_name
        if client_type is not None:
            payload["client_type"] = client_type
        if redirect_uris is not None:
            payload["redirect_uris"] = redirect_uris
        if allowed_scopes is not None:
            payload["allowed_scopes"] = allowed_scopes
        if is_active is not None:
            payload["is_active"] = is_active

        res = await self._request(
            "patch",
            f"{self.api_base_url}/api/v1/clients/{client_id}",
            headers=self._build_headers(),
            json=payload,
        )
        return AuthClientData.model_validate(res.json())

    async def rotate_client_secret(self, client_id: str) -> AuthClientData:
        """Rotate and issue a new client_secret for a confidential AuthClient."""
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/clients/{client_id}/rotate-secret",
            headers=self._build_headers(),
        )
        return AuthClientData.model_validate(res.json())
