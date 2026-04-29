"""Per-user UI preferences.

Currently a single flag — `hide_help` — driving the visibility of the
`{% help %}…{% endhelp %}` blocks. Lives on its own model rather than
on auth.User to keep us off custom-user-model territory and to leave
room for future prefs without churn.
"""
from django.conf import settings
from django.db import models


class UserPreference(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="kv_preferences",
    )
    hide_help = models.BooleanField(
        default=False,
        help_text=(
            "When True, `{% help %}…{% endhelp %}` blocks render as empty. "
            "Toggled from /profile/. See Architecture/dev_docs/08-ui.md "
            "§Help blocks."
        ),
    )

    def __str__(self) -> str:
        return f"prefs({self.user_id}: hide_help={self.hide_help})"
