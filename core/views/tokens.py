"""
Service token management — admin-only CRUD for DRF auth tokens used by
scanner ingest (`kubeposture-import` CronJobs etc.).

Service accounts are plain Django users with usernames prefixed `svc-`;
the ingest API's IsServiceAccount permission only accepts that prefix.
"""
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required
from rest_framework.authtoken.models import Token

from core.api.permissions import has_role


def admin_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Admin role required")
        return view_func(request, *args, **kwargs)
    wrapper.__name__ = view_func.__name__
    wrapper.__doc__ = view_func.__doc__
    return wrapper


@admin_required
def token_list(request):
    svc_users = (
        User.objects
        .filter(username__startswith="svc-")
        .prefetch_related("auth_token")
        .order_by("username")
    )
    tokens = []
    for u in svc_users:
        tok = Token.objects.filter(user=u).first()
        tokens.append({
            "username": u.username,
            "name": u.username.removeprefix("svc-"),
            "is_active": u.is_active,
            "key": tok.key if tok else None,
            "created": tok.created if tok else None,
            "new_key": request.session.pop(f"new_token:{u.username}", None),
        })

    context = {
        "tokens": tokens,
        "nav": "settings",
        "settings_tab": "tokens",
    }
    return render(request, "settings/tokens.html", context)


@admin_required
def token_create(request):
    if request.method != "POST":
        return redirect("token-list")

    name = request.POST.get("name", "").strip().lower()
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        messages.error(request, "Name must be alphanumeric (dashes/underscores allowed).")
        return redirect("token-list")

    username = f"svc-{name}"
    if User.objects.filter(username=username).exists():
        messages.error(request, f"Service account '{username}' already exists.")
        return redirect("token-list")

    user = User.objects.create_user(username=username, is_active=True)
    token = Token.objects.create(user=user)
    request.session[f"new_token:{username}"] = token.key
    messages.success(request, f"Created service account '{username}'. Copy the token — it won't be shown again after the page reloads.")
    return redirect("token-list")


@admin_required
def token_regenerate(request, username):
    if request.method != "POST":
        return redirect("token-list")

    if not username.startswith("svc-"):
        return HttpResponseForbidden("Not a service account")

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, f"Service account '{username}' not found.")
        return redirect("token-list")

    Token.objects.filter(user=user).delete()
    token = Token.objects.create(user=user)
    request.session[f"new_token:{username}"] = token.key
    messages.success(request, f"Regenerated token for '{username}'. Old token is now invalid.")
    return redirect("token-list")


@admin_required
def token_delete(request, username):
    if request.method != "POST":
        return redirect("token-list")

    if not username.startswith("svc-"):
        return HttpResponseForbidden("Not a service account")

    User.objects.filter(username=username).delete()
    messages.success(request, f"Deleted service account '{username}'.")
    return redirect("token-list")
