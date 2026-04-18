from django.conf import settings
from django.db import models


class UserPreference(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="preference",
    )
    show_help = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} preferences"
