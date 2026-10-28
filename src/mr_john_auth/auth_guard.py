"""Mr. John Auth Guard SDK for FastAPI Child Services

Drop-in authentication, role-based access control, and TOTP MFA step-up verification.
Features:
- Stateless RS256 JWT verification using cached JWKS from mr-john-auth.
- Asynchronous non-blocking JWKS fetching with httpx.AsyncClient.
- Cache-busting DoS defense with 5-minute cooldown on unknown Key IDs (kid).
- Strict Audience (aud) validation to prevent token replay between services.
- Step-up MFA verification guard (require_mfa) and Subscription plan guard (require_plan).
"""

import asyncio
import os
import time
from typing import Any, Dict, List, Optional
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# Configuration from environment variables
AUTH_JWKS_URL = os.getenv("MR_JOHN_AUTH_JWKS_URL", "https://auth-api.mr-john.dev/.well-known/jwks.json")
AUTH_ISSUER = os.getenv("MR_JOHN_AUTH_ISSUER", "https://auth.mr-john.dev")
SERVICE_CLIENT_ID = os.getenv("MR_JOHN_CLIENT_ID", "default-client")

security = HTTPBearer(auto_error=False)


class AsyncJWKSStore:
    """Async-safe, thread-safe JWKS cache with unknown-kid DoS rate limiting."""

    def __init__(self, jwks_url: str, cache_ttl: int = 3600, min_refetch_cooldown: int = 300):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.min_refetch_cooldown = min_refetch_cooldown
        self._keys: Dict[str, Any] = {}
        self._last_fetched_at: float = 0.0
        self._lock = asyncio.Lock()

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

            async with httpx.AsyncClient(timeout=5.0) as client:
                try:
                    res = await client.get(self.jwks_url)
                    res.raise_for_status()
                    jwks_data = res.json()
                except Exception as exc:
                    raise jwt.InvalidKeyError(f"Failed to fetch JWKS from {self.jwks_url}: {exc}") from exc

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


jwks_store = AsyncJWKSStore(AUTH_JWKS_URL)


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

    def get_service_plan(self, service_id: str = SERVICE_CLIENT_ID) -> str:
        """Get plan tier for a specific service (e.g. 'free', 'pro', 'enterprise')."""
        return self.services.get(service_id, {}).get("plan", "free")

    def has_service_role(self, role: str, service_id: str = SERVICE_CLIENT_ID) -> bool:
        """Check if user has a specific role in this service."""
        roles = self.services.get(service_id, {}).get("roles", [])
        return role in roles


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

    token = credentials.credentials
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise jwt.InvalidTokenError("Missing or invalid 'kid' in token header.")

        signing_key = await jwks_store.get_signing_key(kid)

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=AUTH_ISSUER,
            audience=SERVICE_CLIENT_ID,
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


async def require_mfa(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """Enforce TOTP Two-Factor Authentication for sensitive operations."""
    if not user.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Two-factor authentication (TOTP) is required for this action.",
        )
    return user


PLAN_HIERARCHY: Dict[str, int] = {
    "free": 0,
    "starter": 1,
    "pro": 2,
    "enterprise": 3,
}


def require_plan(minimum_plan: str, service_id: str = SERVICE_CLIENT_ID):
    """Dependency factory to enforce plan tiers hierarchically (free < starter < pro < enterprise)."""
    min_rank = PLAN_HIERARCHY.get(minimum_plan.lower(), 0)

    async def plan_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        plan = user.get_service_plan(service_id).lower()
        user_rank = PLAN_HIERARCHY.get(plan, 0)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This feature requires at least '{minimum_plan}' plan on {service_id}",
            )
        return user
    return plan_checker
