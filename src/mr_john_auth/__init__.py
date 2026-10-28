"""Mr. John Authentication & Authorization SDK for Python / FastAPI."""

from mr_john_auth import auth_guard
from mr_john_auth.auth_guard import (
    AUTH_ISSUER,
    AUTH_JWKS_URL,
    PLAN_HIERARCHY,
    SERVICE_CLIENT_ID,
    AsyncJWKSStore,
    AuthUser,
    get_current_user,
    jwks_store,
    require_mfa,
    require_plan,
)

__version__ = "1.0.0"

__all__ = [
    "AUTH_ISSUER",
    "AUTH_JWKS_URL",
    "PLAN_HIERARCHY",
    "SERVICE_CLIENT_ID",
    "AsyncJWKSStore",
    "AuthUser",
    "auth_guard",
    "get_current_user",
    "jwks_store",
    "require_mfa",
    "require_plan",
    "__version__",
]
