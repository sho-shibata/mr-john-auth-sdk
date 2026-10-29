"""Mr. John Auth Client SDK"""

from mr_john_auth.auth_guard import (
    AsyncJWKSStore,
    AuthClientData,
    AuthUser,
    MrJohnAuthClient,
    PLAN_HIERARCHY,
    ServiceEntitlement,
    ServicePermissionData,
    configure,
    get_current_user,
    get_optional_user,
    jwks_store,
    require_global_admin,
    require_mfa,
    require_plan,
    require_role,
)

__version__ = "1.2.0"

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
    "require_global_admin",
    "require_mfa",
    "require_plan",
    "require_role",
]
