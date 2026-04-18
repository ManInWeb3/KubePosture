"""Profile and password change views."""
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import redirect, render

from core.models import UserPreference


@login_required
def profile_view(request):
    pref, _ = UserPreference.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = request.POST.get("form", "info")
        if form == "preferences":
            pref.show_help = request.POST.get("show_help") == "on"
            pref.save(update_fields=["show_help"])
            messages.success(request, "Preferences saved.")
        else:
            user = request.user
            user.first_name = request.POST.get("first_name", "").strip()
            user.last_name = request.POST.get("last_name", "").strip()
            user.email = request.POST.get("email", "").strip()
            user.save(update_fields=["first_name", "last_name", "email"])
            messages.success(request, "Profile updated.")
        return redirect("profile")

    groups = list(request.user.groups.values_list("name", flat=True))
    return render(request, "auth/profile.html", {
        "groups": groups,
        "preference": pref,
        "nav": "profile",
    })


@login_required
def password_change_view(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Password changed.")
            return redirect("profile")
    else:
        form = PasswordChangeForm(request.user)

    return render(request, "auth/password_change.html", {"form": form, "nav": "profile"})
