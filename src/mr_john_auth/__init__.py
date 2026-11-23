"""Mr. John Auth Client SDK (v2.0)."""

from mr_john_auth.auth_guard import (
    PLAN_HIERARCHY,
    AsyncJWKSStore,
    AuthClientData,
    AuthUser,
    MrJohnAuthClient,
    ServiceEntitlement,
    ServicePermissionData,
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

__version__ = "2.0.0"

__all__ = [
    "AsyncJWKSStore",
    "AuthClientData",
    "AuthUser",
    "MrJohnAuthClient",
    "PLAN_HIERARCHY",
    "ServiceEntitlement",
    "ServicePermissionData",
    "__version__",
    "configure",
    "get_current_user",
    "get_optional_user",
    "jwks_store",
    "require_claim",
    "require_global_admin",
    "require_mfa",
    "require_plan",
    "require_role",
]
