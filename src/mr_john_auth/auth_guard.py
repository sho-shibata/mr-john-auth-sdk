"""Mr. John Auth Guard & Client SDK v2.0 for FastAPI Child Services.

Drop-in stateless RS256 ID Token (JWT) verification, Firebase Auth style
``custom_claims`` authorization guards, TOTP MFA step-up enforcement,
Direct REST API / Admin HTTP client, and 100% backward-compatible helpers
for existing child services.

Features:
- Stateless RS256 JWT verification using cached JWKS from mr-john-auth.
- Asynchronous non-blocking JWKS fetching with ``httpx.AsyncClient``.
- Stale-While-Revalidate resilience: serves cached keys if JWKS refresh fails transiently.
- Cache-busting DoS defense with 5-minute cooldown on unknown Key IDs (``kid``).
- Multi-audience tolerance: verifies ``aud`` against ``MR_JOHN_AUTH_AUDIENCE`` and
  legacy ``MR_JOHN_CLIENT_ID`` (when configured and distinct) to prevent token replay
  without breaking existing child services.
- Dynamic environment configuration & programmatic ``configure()`` support.
- FastAPI Depends guards: ``get_current_user``, ``get_optional_user``,
  ``require_mfa``, ``require_global_admin``, ``require_claim``, and
  backward-compatible ``require_plan`` / ``require_role``.
- Async HTTP client (``MrJohnAuthClient``) with ``async with`` connection pooling
  for v2.0 Direct REST API auth flows and Admin user management.
"""

import asyncio
import logging
import os
import threading
import time
import unicodedata
import weakref
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import quote

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel, Field

logger = logging.getLogger("mr_john_auth")

# Default fallback constants; dynamically resolved via helper functions to avoid import-order bugs.
_DEFAULT_AUTH_API_URL = "https://auth.api.mr-john-it.com"
_DEFAULT_AUTH_JWKS_URL = f"{_DEFAULT_AUTH_API_URL}/.well-known/jwks.json"
_DEFAULT_AUTH_ISSUER = "https://auth.api.mr-john-it.com"
_DEFAULT_AUTH_AUDIENCE = "mr-john-auth"
_DEFAULT_CLIENT_ID = ""
_DEFAULT_CLIENT_SECRET = ""


def _read_nonempty_env(name: str, fallback: str) -> str:
    """Return environment variable value when non-empty/non-blank, else fallback."""
    val = os.getenv(name)
    return val if val is not None and val.strip() != "" else fallback


AUTH_API_URL: str = _read_nonempty_env("MR_JOHN_AUTH_API_URL", _DEFAULT_AUTH_API_URL).rstrip("/")
AUTH_JWKS_URL: str = _read_nonempty_env(
    "MR_JOHN_AUTH_JWKS_URL",
    f"{AUTH_API_URL}/.well-known/jwks.json",
)
AUTH_ISSUER: str = _read_nonempty_env("MR_JOHN_AUTH_ISSUER", _DEFAULT_AUTH_ISSUER)
AUTH_AUDIENCE: str = _read_nonempty_env("MR_JOHN_AUTH_AUDIENCE", _DEFAULT_AUTH_AUDIENCE)
SERVICE_CLIENT_ID: str = os.getenv("MR_JOHN_CLIENT_ID", _DEFAULT_CLIENT_ID)
SERVICE_CLIENT_SECRET: str = os.getenv("MR_JOHN_CLIENT_SECRET", _DEFAULT_CLIENT_SECRET)

# Snapshot of module globals at import time so subsequent env updates still take effect.
_IMPORT_DEFAULTS: Dict[str, str] = {
    "api_url": AUTH_API_URL,
    "jwks_url": AUTH_JWKS_URL,
    "issuer": AUTH_ISSUER,
    "audience": AUTH_AUDIENCE,
    "client_id": SERVICE_CLIENT_ID,
    "client_secret": SERVICE_CLIENT_SECRET,
}

# Tracks explicit values set via configure() so resetting to a default overrides env vars cleanly.
_configured_overrides: Dict[str, str] = {}

security = HTTPBearer(auto_error=False)


def _resolve_setting(
    key: str,
    current_value: str,
    default_value: str,
    env_var: str,
    *,
    fallback_factory: Optional[Callable[[], str]] = None,
    allow_empty: bool = False,
    strip_trailing_slash: bool = False,
) -> str:
    """Resolve SDK configuration by precedence: configure() > direct module global > os.getenv()."""
    if key in _configured_overrides:
        val = _configured_overrides[key]
        return val.rstrip("/") if strip_trailing_slash else val

    normalized_current = current_value.rstrip("/") if strip_trailing_slash else current_value
    if normalized_current not in (default_value, _IMPORT_DEFAULTS[key]):
        return normalized_current

    env_val = os.getenv(env_var)
    if env_val is not None and (allow_empty or env_val.strip() != ""):
        resolved = env_val
    else:
        resolved = fallback_factory() if fallback_factory is not None else default_value
    return resolved.rstrip("/") if strip_trailing_slash else resolved


def _resolve_api_url() -> str:
    return _resolve_setting(
        "api_url",
        AUTH_API_URL,
        _DEFAULT_AUTH_API_URL,
        "MR_JOHN_AUTH_API_URL",
        strip_trailing_slash=True,
    )


def _resolve_jwks_url() -> str:
    return _resolve_setting(
        "jwks_url",
        AUTH_JWKS_URL,
        _DEFAULT_AUTH_JWKS_URL,
        "MR_JOHN_AUTH_JWKS_URL",
        fallback_factory=lambda: f"{_resolve_api_url()}/.well-known/jwks.json",
    )


def _resolve_issuer() -> str:
    return _resolve_setting(
        "issuer",
        AUTH_ISSUER,
        _DEFAULT_AUTH_ISSUER,
        "MR_JOHN_AUTH_ISSUER",
    )


def _resolve_audience() -> str:
    return _resolve_setting(
        "audience",
        AUTH_AUDIENCE,
        _DEFAULT_AUTH_AUDIENCE,
        "MR_JOHN_AUTH_AUDIENCE",
    )


def _resolve_client_id() -> str:
    return _resolve_setting(
        "client_id",
        SERVICE_CLIENT_ID,
        _DEFAULT_CLIENT_ID,
        "MR_JOHN_CLIENT_ID",
        allow_empty=True,
    )


def _resolve_client_secret() -> str:
    return _resolve_setting(
        "client_secret",
        SERVICE_CLIENT_SECRET,
        _DEFAULT_CLIENT_SECRET,
        "MR_JOHN_CLIENT_SECRET",
        allow_empty=True,
    )


def configure(
    *,
    audience: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    api_url: Optional[str] = None,
    jwks_url: Optional[str] = None,
    issuer: Optional[str] = None,
) -> None:
    """Programmatically configure mr_john_auth SDK settings at application startup."""
    global AUTH_API_URL, AUTH_JWKS_URL, AUTH_ISSUER, AUTH_AUDIENCE, SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET

    previous_effective_jwks = jwks_store.jwks_url or _resolve_jwks_url()

    if api_url is not None:
        AUTH_API_URL = api_url.rstrip("/")
        _configured_overrides["api_url"] = AUTH_API_URL
    if jwks_url is not None:
        AUTH_JWKS_URL = jwks_url
        _configured_overrides["jwks_url"] = AUTH_JWKS_URL
    elif api_url is not None:
        AUTH_JWKS_URL = f"{AUTH_API_URL}/.well-known/jwks.json"
        _configured_overrides["jwks_url"] = AUTH_JWKS_URL
    if issuer is not None:
        AUTH_ISSUER = issuer
        _configured_overrides["issuer"] = AUTH_ISSUER
    if audience is not None:
        AUTH_AUDIENCE = audience
        _configured_overrides["audience"] = AUTH_AUDIENCE
    if client_id is not None:
        SERVICE_CLIENT_ID = client_id
        _configured_overrides["client_id"] = SERVICE_CLIENT_ID
    if client_secret is not None:
        SERVICE_CLIENT_SECRET = client_secret
        _configured_overrides["client_secret"] = SERVICE_CLIENT_SECRET

    resolved_jwks = _resolve_jwks_url()
    # Pin jwks_store.jwks_url only when JWKS/API URL was explicitly configured so env changes still apply otherwise.
    if jwks_url is not None or api_url is not None or "jwks_url" in _configured_overrides:
        jwks_store.jwks_url = resolved_jwks

    effective_jwks = jwks_store.jwks_url or resolved_jwks
    if previous_effective_jwks != effective_jwks or jwks_store.has_url_mismatch(effective_jwks):
        jwks_store.clear()


class AsyncJWKSStore:
    """Multi-loop-safe JWKS cache with error backoff, unknown-kid DoS rate limiting, and Stale-While-Revalidate."""

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        cache_ttl: int = 3600,
        min_refetch_cooldown: int = 300,
        error_cooldown: float = 30.0,
    ) -> None:
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.min_refetch_cooldown = min_refetch_cooldown
        self.error_cooldown = error_cooldown
        self._state_lock = threading.Lock()
        self._locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
            weakref.WeakKeyDictionary()
        )
        self._fallback_locks: Dict[int, Tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}
        self._keys: Dict[str, Any] = {}
        self._last_fetched_at: float = 0.0
        self._last_error_at: Optional[float] = None
        self._cached_url: Optional[str] = None
        self._last_error_url: Optional[str] = None
        self._generation: int = 0

    def _get_loop_lock(self) -> asyncio.Lock:
        """Lazily bind one asyncio.Lock per running event loop without holding locks across awaits."""
        loop = asyncio.get_running_loop()
        with self._state_lock:
            try:
                loop_lock = self._locks.get(loop)
                if loop_lock is None:
                    loop_lock = asyncio.Lock()
                    self._locks[loop] = loop_lock
                return loop_lock
            except TypeError:
                # Fallback when a custom event loop does not support weak references.
                stale_ids = [
                    loop_id
                    for loop_id, (stored_loop, _) in self._fallback_locks.items()
                    if stored_loop.is_closed()
                ]
                for loop_id in stale_ids:
                    self._fallback_locks.pop(loop_id, None)

                loop_id = id(loop)
                entry = self._fallback_locks.get(loop_id)
                if entry is None or entry[0] is not loop:
                    loop_lock = asyncio.Lock()
                    self._fallback_locks[loop_id] = (loop, loop_lock)
                    return loop_lock
                return entry[1]

    def _resolve_target_url(self) -> str:
        return self.jwks_url or _resolve_jwks_url()

    def _is_error_cooldown_active(self, target_url: str, now: float) -> bool:
        return (
            self._last_error_at is not None
            and self._last_error_url == target_url
            and self.error_cooldown > 0
            and (now - self._last_error_at) < self.error_cooldown
        )

    def _is_cache_fresh(self, now: float) -> bool:
        return (
            (self._cached_url is not None or self._last_fetched_at > 0.0)
            and (now - self._last_fetched_at) < self.cache_ttl
        )

    def _url_matches(self, target_url: str) -> bool:
        return self._cached_url == target_url or (self._cached_url is None and bool(self._keys))

    def _fast_resolve_locked(self, kid: str, target_url: str, now: float) -> Tuple[bool, Any]:
        """Resolve cached key or fail-fast under ``_state_lock``. Returns (handled, key)."""
        error_active = self._is_error_cooldown_active(target_url, now)
        if self._url_matches(target_url) and kid in self._keys:
            if self._is_cache_fresh(now) or error_active:
                return True, self._keys[kid]
        if error_active:
            raise jwt.InvalidKeyError(
                f"JWKS fetch backoff active after recent failure for {target_url}."
            )
        return False, None

    def has_url_mismatch(self, target_url: str) -> bool:
        """Return True if cached keys or recorded failure state belong to a different JWKS URL."""
        with self._state_lock:
            if self._cached_url is not None and self._cached_url != target_url:
                return True
            if self._last_error_url is not None and self._last_error_url != target_url:
                return True
            return False

    def clear(self) -> None:
        """Clear cached JWKS keys and reset fetch/error timestamps while preserving per-loop locks."""
        with self._state_lock:
            self._generation += 1
            self._keys = {}
            self._last_fetched_at = 0.0
            self._last_error_at = None
            self._cached_url = None
            self._last_error_url = None

    @staticmethod
    def _parse_jwks_payload(jwks_data: Any) -> Dict[str, Any]:
        """Validate and parse RSA signing keys from a JWKS JSON payload without mutating store state."""
        if not isinstance(jwks_data, dict) or not isinstance(jwks_data.get("keys"), list):
            raise ValueError("Invalid JWKS payload structure.")

        new_keys: Dict[str, Any] = {}
        for jwk_item in jwks_data["keys"]:
            if not isinstance(jwk_item, dict):
                logger.warning("Skipping non-dict JWK item in JWKS payload.")
                continue
            if jwk_item.get("kty") != "RSA":
                continue
            use = jwk_item.get("use")
            if use not in (None, "sig"):
                logger.warning("Skipping RSA JWK item with non-signing use=%r.", use)
                continue
            k_id = jwk_item.get("kid")
            if not isinstance(k_id, str) or not k_id:
                logger.warning("Skipping RSA JWK item with missing or non-string kid.")
                continue
            try:
                new_keys[k_id] = RSAAlgorithm.from_jwk(jwk_item)
            except Exception as exc:
                logger.warning("Skipping invalid RSA JWK item for kid=%s: %s", k_id, exc)

        if not new_keys:
            raise ValueError("JWKS payload contained no usable RSA signing keys.")
        return new_keys

    async def get_signing_key(self, kid: str) -> Any:
        """Return RSA signing key for ``kid``, fetching and caching JWKS as needed."""
        with self._state_lock:
            handled, cached_key = self._fast_resolve_locked(
                kid, self._resolve_target_url(), time.monotonic()
            )
            if handled:
                return cached_key

        loop_lock = self._get_loop_lock()
        async with loop_lock:
            with self._state_lock:
                target_url = self._resolve_target_url()
                now = time.monotonic()

                if self._cached_url is not None and self._cached_url != target_url:
                    self._keys = {}
                    self._last_fetched_at = 0.0
                    self._cached_url = None
                if self._last_error_url is not None and self._last_error_url != target_url:
                    self._last_error_at = None
                    self._last_error_url = None

                start_generation = self._generation
                handled, cached_key = self._fast_resolve_locked(kid, target_url, now)
                if handled:
                    return cached_key

                # Cooldown protection against Cache-Busting DoS on unknown kid requests.
                if (
                    self._keys
                    and (self._cached_url is not None or self._last_fetched_at > 0.0)
                    and (now - self._last_fetched_at) < self.min_refetch_cooldown
                    and kid not in self._keys
                ):
                    raise jwt.InvalidKeyError(
                        f"Key ID {kid} not found (refetch cooldown active)."
                    )

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.get(target_url)
                    res.raise_for_status()
                    jwks_data = res.json()
                new_keys = self._parse_jwks_payload(jwks_data)
            except Exception as exc:
                stale_key: Any = None
                with self._state_lock:
                    current_url = self._resolve_target_url()
                    if self._generation == start_generation and current_url == target_url:
                        self._last_error_at = time.monotonic()
                        self._last_error_url = target_url
                        if kid in self._keys and (
                            self._cached_url == target_url or self._cached_url is None
                        ):
                            stale_key = self._keys[kid]
                if stale_key is not None:
                    logger.warning(
                        "Failed to refresh JWKS from %s (%s); serving cached signing key for kid=%s",
                        target_url,
                        exc,
                        kid,
                    )
                    return stale_key
                raise jwt.InvalidKeyError(
                    f"Failed to fetch JWKS from {target_url}: {exc}"
                ) from exc

            with self._state_lock:
                current_url = self._resolve_target_url()
                if self._generation != start_generation or current_url != target_url:
                    raise jwt.InvalidKeyError(
                        f"JWKS store configuration changed while fetching from {target_url}."
                    )
                self._keys = new_keys
                self._last_fetched_at = time.monotonic()
                self._cached_url = target_url
                self._last_error_at = None
                self._last_error_url = None
                resolved_key = self._keys.get(kid)

            if resolved_key is None:
                raise jwt.InvalidKeyError(f"Key ID {kid} not found in JWKS.")
            return resolved_key


jwks_store = AsyncJWKSStore()

PLAN_HIERARCHY: Dict[str, int] = {
    "free": 0,
    "starter": 1,
    "pro": 2,
    "max": 3,
    "enterprise": 4,
}
_ORDERED_PLAN_TIERS: List[str] = [
    tier for tier, _ in sorted(PLAN_HIERARCHY.items(), key=lambda item: item[1], reverse=True)
]


class ServiceEntitlement(BaseModel):
    """Structured representation of a user's entitlement for a specific service."""

    client_id: str
    plan: str = "free"
    roles: List[str] = Field(default_factory=lambda: ["member"])
    custom_claims: Dict[str, Any] = Field(default_factory=dict)


class ServicePermissionData(BaseModel):
    """Legacy data model representing a SERVICE_PERMISSIONS record (backward compatibility)."""

    id: str
    user_id: str
    client_id: str
    plan_tier: str
    roles: List[str]
    custom_claims: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AuthClientData(BaseModel):
    """Legacy data model representing an AUTH_CLIENTS record (backward compatibility)."""

    client_id: str
    client_name: str
    client_type: str
    redirect_uris: List[str] = Field(default_factory=list)
    allowed_scopes: List[str] = Field(default_factory=list)
    is_active: bool = True
    created_at: Optional[datetime] = None
    client_secret: Optional[str] = None


class AuthUser(BaseModel):
    """Authenticated user entity extracted from a cryptographically verified RS256 JWT."""

    id: str  # sub (Universal User UUID across all ecosystem services)
    email: str
    email_verified: bool = False
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    global_role: str = "user"
    mfa_verified: bool = False
    amr: List[str] = Field(default_factory=list)
    token_version: int = 1
    custom_claims: Dict[str, Any] = Field(default_factory=dict)
    services: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_global_admin(self) -> bool:
        """Check if the user holds the global 'admin' role across the Mr. John ecosystem."""
        return self.global_role == "admin"

    def get_claim(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from ``custom_claims`` (Firebase Auth style)."""
        return self.custom_claims.get(key, default)

    def has_claim(self, key: str, expected_value: Any = True) -> bool:
        """Check if ``custom_claims[key]`` matches ``expected_value`` (Global Admins pass automatically)."""
        if self.is_global_admin:
            return True
        if key not in self.custom_claims:
            return False
        actual = self.custom_claims[key]
        # Avoid Python's bool/int equality quirk (e.g. 1 == True, 0 == False).
        if isinstance(expected_value, bool) or isinstance(actual, bool):
            return type(actual) is type(expected_value) and actual == expected_value
        return actual == expected_value

    def _resolve_target_id(self, service_id: Optional[str] = None) -> str:
        return service_id or _resolve_client_id() or _resolve_audience()

    def _resolve_service_source(self, service_id: Optional[str] = None) -> Tuple[str, Optional[Dict[str, Any]]]:
        target_id = self._resolve_target_id(service_id)
        if target_id in self.services:
            raw = self.services[target_id]
            return target_id, raw if isinstance(raw, dict) else None

        scoped = self.custom_claims.get(target_id)
        if isinstance(scoped, dict):
            return target_id, scoped
        if self.custom_claims:
            return target_id, self.custom_claims
        return target_id, None

    @staticmethod
    def _extract_plan(source: Optional[Dict[str, Any]]) -> str:
        if source is None:
            return "free"
        explicit_plan = source.get("plan")
        if isinstance(explicit_plan, str) and explicit_plan:
            return explicit_plan
        plan_tier = source.get("plan_tier")
        if isinstance(plan_tier, str) and plan_tier:
            return plan_tier
        for tier in _ORDERED_PLAN_TIERS:
            if source.get(tier) is True:
                return tier
        return "free"

    @staticmethod
    def _extract_roles(source: Optional[Dict[str, Any]], default_roles: List[str]) -> List[str]:
        if source is None:
            return list(default_roles)
        raw_roles = source.get("roles")
        if isinstance(raw_roles, list):
            return [str(r) for r in raw_roles]
        raw_role = source.get("role")
        if isinstance(raw_role, str) and raw_role:
            return [raw_role]
        return list(default_roles)

    def get_service_entitlement(self, service_id: Optional[str] = None) -> ServiceEntitlement:
        """Return structured ServiceEntitlement resolving from ``services`` or ``custom_claims``."""
        target_id, source = self._resolve_service_source(service_id)
        if source is None:
            return ServiceEntitlement(client_id=target_id)
        plan = self._extract_plan(source)
        roles = self._extract_roles(source, ["member"])
        custom = {k: v for k, v in source.items() if k not in ("plan", "roles")}
        return ServiceEntitlement(
            client_id=target_id,
            plan=plan,
            roles=roles,
            custom_claims=custom,
        )

    def get_service_plan(self, service_id: Optional[str] = None) -> str:
        """Get plan tier for a service (e.g. 'free', 'starter', 'pro', 'enterprise')."""
        _, source = self._resolve_service_source(service_id)
        return self._extract_plan(source)

    def get_service_roles(self, service_id: Optional[str] = None) -> List[str]:
        """Get list of roles assigned to the user in a service."""
        _, source = self._resolve_service_source(service_id)
        return self._extract_roles(source, [])

    def has_service_role(self, role: str, service_id: Optional[str] = None) -> bool:
        """Check if the user has a specific role in the target service."""
        return role in self.get_service_roles(service_id)

    def has_any_service_role(self, roles: Sequence[str], service_id: Optional[str] = None) -> bool:
        """Check if the user has at least one of the specified roles in the target service."""
        user_roles = set(self.get_service_roles(service_id))
        return any(r in user_roles for r in roles)

    def has_minimum_plan(self, minimum_plan: str, service_id: Optional[str] = None) -> bool:
        """Check if the user's plan on the service meets or exceeds ``minimum_plan``."""
        clean_min = minimum_plan.lower().strip() if isinstance(minimum_plan, str) else ""
        if clean_min not in PLAN_HIERARCHY:
            raise ValueError(
                f"Unknown plan tier '{minimum_plan}'. Valid tiers: {sorted(PLAN_HIERARCHY.keys())}"
            )
        if self.is_global_admin:
            return True
        min_rank = PLAN_HIERARCHY[clean_min]
        user_rank = PLAN_HIERARCHY.get(self.get_service_plan(service_id).lower(), 0)
        return user_rank >= min_rank

    def get_custom_claim(self, key: str, default: Any = None, service_id: Optional[str] = None) -> Any:
        """Retrieve a custom claim from service permissions or top-level ``custom_claims``."""
        entitlement = self.get_service_entitlement(service_id)
        if key in entitlement.custom_claims:
            return entitlement.custom_claims[key]
        return self.custom_claims.get(key, default)


def _parse_bool_claim(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    if isinstance(value, (int, float)):
        return bool(value)
    return False


async def _verify_token_to_user(token: str) -> AuthUser:
    """Verify an RS256 JWT against JWKS and construct an ``AuthUser``."""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise jwt.InvalidTokenError("Missing or invalid 'kid' in token header.")

    signing_key = await jwks_store.get_signing_key(kid)

    allowed_audiences: List[str] = []
    primary_audience = _resolve_audience()
    if primary_audience:
        allowed_audiences.append(primary_audience)
    legacy_client_id = _resolve_client_id()
    if legacy_client_id and legacy_client_id not in allowed_audiences:
        allowed_audiences.append(legacy_client_id)

    if not allowed_audiences:
        raise jwt.InvalidAudienceError("No allowed JWT audience configured.")

    payload = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        issuer=_resolve_issuer(),
        audience=allowed_audiences,
        options={
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
            "require": ["exp", "iss", "sub", "aud"],
        },
    )

    sub = payload.get("sub")
    if sub is None or str(sub) == "":
        raise jwt.InvalidTokenError("Missing or empty 'sub' claim in token payload.")

    raw_amr = payload.get("amr")
    amr = [str(item) for item in raw_amr] if isinstance(raw_amr, list) else []

    raw_custom_claims = payload.get("custom_claims")
    custom_claims = raw_custom_claims if isinstance(raw_custom_claims, dict) else {}

    raw_services = payload.get("services")
    services = raw_services if isinstance(raw_services, dict) else {}

    display_name = payload.get("name")
    if display_name is None:
        display_name = payload.get("display_name")

    avatar_url = payload.get("picture")
    if avatar_url is None:
        avatar_url = payload.get("avatar_url")

    raw_ver = payload.get("ver", 1)
    try:
        token_version = int(raw_ver)
    except (TypeError, ValueError):
        token_version = 1

    return AuthUser(
        id=str(sub),
        email=str(payload.get("email") or ""),
        email_verified=_parse_bool_claim(payload.get("email_verified", False)),
        display_name=str(display_name) if display_name is not None else None,
        avatar_url=str(avatar_url) if avatar_url is not None else None,
        global_role=str(payload.get("global_role") or "user"),
        mfa_verified=_parse_bool_claim(payload.get("mfa_verified", False)),
        amr=amr,
        token_version=token_version,
        custom_claims=custom_claims,
        services=services,
    )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthUser:
    """FastAPI dependency to verify an RS256 Bearer JWT locally in <1 millisecond."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return await _verify_token_to_user(credentials.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[AuthUser]:
    """FastAPI dependency for endpoints supporting both anonymous and authenticated users."""
    if not credentials or not credentials.credentials:
        return None
    try:
        return await _verify_token_to_user(credentials.credentials)
    except jwt.PyJWTError:
        return None


async def require_mfa(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """FastAPI dependency enforcing TOTP Two-Factor Authentication verification."""
    if not user.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Two-factor authentication (TOTP) is required for this action.",
        )
    return user


async def require_global_admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """FastAPI dependency enforcing global administrator privileges (``global_role == 'admin'``)."""
    if not user.is_global_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Global administrator privileges are required for this action.",
        )
    return user


def require_claim(
    key: str,
    expected_value: Any = True,
) -> Callable[..., Coroutine[Any, Any, AuthUser]]:
    """Dependency factory enforcing ``custom_claims[key] == expected_value`` (Global Admins pass)."""

    async def claim_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not user.has_claim(key, expected_value):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required claim '{key}' is not satisfied.",
            )
        return user

    return claim_checker


def require_plan(
    minimum_plan: str,
    service_id: Optional[str] = None,
) -> Callable[..., Coroutine[Any, Any, AuthUser]]:
    """Dependency factory enforcing hierarchical plan tiers (backward-compatibility wrapper)."""
    clean_min = minimum_plan.lower().strip() if isinstance(minimum_plan, str) else ""
    if clean_min not in PLAN_HIERARCHY:
        raise ValueError(
            f"Unknown plan tier '{minimum_plan}'. Valid tiers: {sorted(PLAN_HIERARCHY.keys())}"
        )

    async def plan_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if user.is_global_admin:
            return user
        target_id = service_id or _resolve_client_id() or _resolve_audience()
        if not user.has_minimum_plan(clean_min, target_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This feature requires at least '{clean_min}' plan on {target_id}",
            )
        return user

    return plan_checker


def require_role(
    required_roles: Union[str, Sequence[str]],
    service_id: Optional[str] = None,
) -> Callable[..., Coroutine[Any, Any, AuthUser]]:
    """Dependency factory enforcing service-specific role(s) (backward-compatibility wrapper)."""
    roles_list = [required_roles] if isinstance(required_roles, str) else list(required_roles)

    async def role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        target_id = service_id or _resolve_client_id() or _resolve_audience()
        if user.is_global_admin or user.has_any_service_role(roles_list, target_id):
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Required role(s) {roles_list} on '{target_id}' not satisfied.",
        )

    return role_checker


_UNSET = object()
_MAX_USER_ID_LENGTH = 64
_FORBIDDEN_USER_ID_CHARS = frozenset(("/", "\\", "?", "#", "%"))


def _has_control_or_whitespace(text: str) -> bool:
    """Return True when ``text`` contains NUL, Unicode Cc control characters, or whitespace."""
    return any(
        ch == "\x00" or unicodedata.category(ch) == "Cc" or ch.isspace()
        for ch in text
    )


def _validate_user_access_token(user_access_token: Any) -> str:
    """Validate an explicit user access token before sending Authorization headers."""
    if not isinstance(user_access_token, str) or not user_access_token:
        raise ValueError("user_access_token must be a non-empty string.")
    if _has_control_or_whitespace(user_access_token):
        raise ValueError("user_access_token cannot contain whitespace or control characters.")
    return user_access_token


def _validate_user_id(user_id: Any) -> str:
    """Validate an admin target ``user_id`` without rejecting non-UUID test identifiers."""
    if not isinstance(user_id, str) or not (1 <= len(user_id) <= _MAX_USER_ID_LENGTH):
        raise ValueError(
            f"user_id must be a string between 1 and {_MAX_USER_ID_LENGTH} characters."
        )
    if _has_control_or_whitespace(user_id):
        raise ValueError("user_id cannot contain whitespace or control characters.")
    if user_id in (".", "..") or ".." in user_id:
        raise ValueError("user_id cannot contain path traversal segments.")
    if any(ch in _FORBIDDEN_USER_ID_CHARS for ch in user_id):
        raise ValueError("user_id contains forbidden URL characters.")
    return user_id


class MrJohnAuthClient:
    """Async HTTP Client for mr-john-auth v2.0 Direct REST API and Admin user management.

    Supports both standalone requests and persistent connection pooling via
    ``async with MrJohnAuthClient(...) as client:``.
    """

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        admin_access_token: Optional[str] = None,
        timeout: float = 10.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.api_base_url = (api_base_url or _resolve_api_url()).rstrip("/")
        self.client_id = client_id if client_id is not None else _resolve_client_id()
        self.client_secret = client_secret if client_secret is not None else _resolve_client_secret()
        self.admin_access_token = admin_access_token
        self.timeout = timeout
        self._http_client = http_client
        self._owns_http_client = http_client is None

    async def __aenter__(self) -> "MrJohnAuthClient":
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
            self._owns_http_client = True
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying managed ``httpx.AsyncClient`` if open."""
        if self._http_client is not None and self._owns_http_client:
            await self._http_client.aclose()
            self._http_client = None

    def _build_user_headers(self, user_access_token: Any) -> Dict[str, str]:
        """Build headers bound strictly to an explicit user token without admin/service fallback."""
        validated_token = _validate_user_access_token(user_access_token)
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {validated_token}",
        }

    def _build_headers(
        self,
        access_token: Any = _UNSET,
        *,
        include_auth: bool = True,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if not include_auth:
            return headers
        if access_token is not _UNSET:
            return self._build_user_headers(access_token)
        if self.admin_access_token:
            headers["Authorization"] = f"Bearer {self.admin_access_token}"
        elif self.client_id and self.client_secret:
            headers["X-Client-Id"] = self.client_id
            headers["X-Client-Secret"] = self.client_secret
        return headers

    def _admin_user_url(self, user_id: Any, suffix: str = "") -> str:
        validated_id = _validate_user_id(user_id)
        safe_user_id = quote(validated_id, safe="")
        return f"{self.api_base_url}/api/v1/admin/users/{safe_user_id}{suffix}"

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        kwargs: Dict[str, Any] = {}
        if headers is not None:
            kwargs["headers"] = headers
        if params is not None:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json

        if self._http_client is not None:
            fn = getattr(self._http_client, method)
            res = await fn(url, **kwargs)
            res.raise_for_status()
            return res

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            fn = getattr(client, method)
            res = await fn(url, **kwargs)
            res.raise_for_status()
            return res

    @staticmethod
    def _decode_json(res: httpx.Response) -> Dict[str, Any]:
        if getattr(res, "status_code", None) == 204 or getattr(res, "content", None) == b"":
            return {}
        return res.json()

    # --- 1. Direct REST API Authentication Operations (v2.0 Firebase Auth Style) ---
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate with email and password via ``POST /api/v1/auth/login``."""
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/login",
            headers=self._build_headers(include_auth=False),
            json={"email": email, "password": password},
        )
        return self._decode_json(res)

    async def verify_mfa(self, mfa_token: str, code: str) -> Dict[str, Any]:
        """Complete TOTP/backup-code MFA challenge via ``POST /api/v1/auth/mfa/verify``."""
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/mfa/verify",
            headers=self._build_headers(include_auth=False),
            json={"mfa_token": mfa_token, "code": code},
        )
        return self._decode_json(res)

    async def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """Rotate ``refresh_token`` and obtain a new token pair via ``POST /api/v1/auth/token``."""
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/token",
            headers=self._build_headers(include_auth=False),
            json={"refresh_token": refresh_token},
        )
        return self._decode_json(res)

    async def logout(self, refresh_token: str) -> Dict[str, Any]:
        """Revoke ``refresh_token`` via ``POST /api/v1/auth/logout``."""
        res = await self._request(
            "post",
            f"{self.api_base_url}/api/v1/auth/logout",
            headers=self._build_headers(include_auth=False),
            json={"refresh_token": refresh_token},
        )
        return self._decode_json(res)

    async def get_user_profile(self, user_access_token: str) -> Dict[str, Any]:
        """Fetch live user profile and custom claims from ``GET /api/v1/users/me``."""
        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/users/me",
            headers=self._build_user_headers(user_access_token),
        )
        return self._decode_json(res)

    # --- 2. Global Admin User Management Operations ---
    async def list_users(
        self,
        q: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        """List or search users via ``GET /api/v1/admin/users``."""
        params: Dict[str, Any] = {"page": page, "per_page": per_page}
        if q is not None:
            params["q"] = q
        if role is not None:
            params["role"] = role
        if is_active is not None:
            params["is_active"] = is_active

        res = await self._request(
            "get",
            f"{self.api_base_url}/api/v1/admin/users",
            headers=self._build_headers(),
            params=params,
        )
        return self._decode_json(res)

    async def get_user(self, user_id: str) -> Dict[str, Any]:
        """Fetch detailed user info via ``GET /api/v1/admin/users/{user_id}``."""
        res = await self._request(
            "get",
            self._admin_user_url(user_id),
            headers=self._build_headers(),
        )
        return self._decode_json(res)

    async def update_user(self, user_id: str, **fields: Any) -> Dict[str, Any]:
        """Update user attributes or custom claims via ``PATCH /api/v1/admin/users/{user_id}``."""
        res = await self._request(
            "patch",
            self._admin_user_url(user_id),
            headers=self._build_headers(),
            json=fields,
        )
        return self._decode_json(res)

    async def revoke_user_sessions(self, user_id: str) -> Dict[str, Any]:
        """Force-revoke all user sessions via ``POST /api/v1/admin/users/{user_id}/revoke-sessions``."""
        res = await self._request(
            "post",
            self._admin_user_url(user_id, "/revoke-sessions"),
            headers=self._build_headers(),
        )
        return self._decode_json(res)

    async def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Permanently delete a user via ``DELETE /api/v1/admin/users/{user_id}``."""
        res = await self._request(
            "delete",
            self._admin_user_url(user_id),
            headers=self._build_headers(),
        )
        return self._decode_json(res)
