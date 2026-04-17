from rest_framework.permissions import BasePermission


def has_role(user, role: str) -> bool:
    """Check if user has role. Admin inherits operator, operator inherits viewer (R3)."""
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True

    user_groups = set(user.groups.values_list("name", flat=True))

    if role == "viewer":
        return bool(user_groups & {"viewer", "operator", "admin"})
    if role == "operator":
        return bool(user_groups & {"operator", "admin"})
    if role == "admin":
        return "admin" in user_groups

    return False


class IsServiceAccount(BasePermission):
    """Allow access for service token users (ingest API)."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.username.startswith("svc-")
        )


class IsOperator(BasePermission):
    def has_permission(self, request, view):
        return has_role(request.user, "operator")


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return has_role(request.user, "admin")
