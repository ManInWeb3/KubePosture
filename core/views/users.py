"""
User management views — admin-only CRUD for users and role assignment.
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from core.api.permissions import has_role


def admin_required(view_func):
    """Decorator: login + admin role required."""
    @login_required
    def wrapper(request, *args, **kwargs):
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Admin role required")
        return view_func(request, *args, **kwargs)
    wrapper.__name__ = view_func.__name__
    wrapper.__doc__ = view_func.__doc__
    return wrapper


@admin_required
def user_list(request):
    search = request.GET.get("search", "").strip()
    role_filter = request.GET.get("role", "")

    qs = User.objects.prefetch_related("groups").order_by("username")
    # Exclude service accounts from the list
    qs = qs.exclude(username__startswith="svc-")

    if search:
        qs = qs.filter(
            Q(username__icontains=search)
            | Q(email__icontains=search)
            | Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
        )
    if role_filter:
        qs = qs.filter(groups__name=role_filter)

    paginator = Paginator(qs, 25)
    page_obj = paginator.get_page(request.GET.get("page", 1))

    groups = Group.objects.order_by("name")

    context = {
        "users": page_obj,
        "page_obj": page_obj,
        "groups": groups,
        "nav": "settings",
        "settings_tab": "users",
    }
    return render(request, "users/list.html", context)


@admin_required
def user_create(request):
    groups = Group.objects.order_by("name")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        selected_groups = request.POST.getlist("groups")
        is_active = request.POST.get("is_active") == "on"

        if not username:
            messages.error(request, "Username is required.")
            return render(request, "users/form.html", {"groups": groups, "nav": "settings", "settings_tab": "users"})

        if User.objects.filter(username=username).exists():
            messages.error(request, f"Username '{username}' already exists.")
            return render(request, "users/form.html", {"groups": groups, "nav": "settings", "settings_tab": "users"})

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password or None,
            first_name=first_name,
            last_name=last_name,
        )
        user.is_active = is_active
        user.save(update_fields=["is_active"])
        user.groups.set(Group.objects.filter(name__in=selected_groups))

        messages.success(request, f"User '{username}' created.")
        return redirect("user-list")

    return render(request, "users/form.html", {"groups": groups, "nav": "settings", "settings_tab": "users"})


@admin_required
def user_edit(request, pk):
    user_obj = get_object_or_404(User, pk=pk)
    groups = Group.objects.order_by("name")
    user_groups = set(user_obj.groups.values_list("name", flat=True))

    if request.method == "POST":
        user_obj.first_name = request.POST.get("first_name", "").strip()
        user_obj.last_name = request.POST.get("last_name", "").strip()
        user_obj.email = request.POST.get("email", "").strip()
        user_obj.is_active = request.POST.get("is_active") == "on"
        user_obj.save(update_fields=["first_name", "last_name", "email", "is_active"])

        selected_groups = request.POST.getlist("groups")
        user_obj.groups.set(Group.objects.filter(name__in=selected_groups))

        # Password change (optional)
        new_password = request.POST.get("new_password", "")
        if new_password:
            user_obj.set_password(new_password)
            user_obj.save(update_fields=["password"])

        messages.success(request, f"User '{user_obj.username}' updated.")
        return redirect("user-list")

    context = {
        "edit_user": user_obj,
        "groups": groups,
        "user_groups": user_groups,
        "nav": "settings",
        "settings_tab": "users",
    }
    return render(request, "users/form.html", context)


@admin_required
def user_toggle_active(request, pk):
    """POST: toggle user active/inactive."""
    if request.method != "POST":
        return redirect("user-list")

    user_obj = get_object_or_404(User, pk=pk)
    # Prevent deactivating yourself
    if user_obj == request.user:
        messages.error(request, "Cannot deactivate your own account.")
        return redirect("user-list")

    user_obj.is_active = not user_obj.is_active
    user_obj.save(update_fields=["is_active"])
    status = "activated" if user_obj.is_active else "deactivated"
    messages.success(request, f"User '{user_obj.username}' {status}.")
    return redirect("user-list")
