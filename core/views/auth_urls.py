from django.contrib.auth import views as auth_views
from django.urls import path

from core.views.profile import profile_view, password_change_view

urlpatterns = [
    path("login/", auth_views.LoginView.as_view(template_name="auth/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("profile/", profile_view, name="profile"),
    path("password/", password_change_view, name="password-change"),
]
