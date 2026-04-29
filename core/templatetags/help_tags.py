"""`{% help "Title" %}…{% endhelp %}` block tag.

Renders the inner body inside templates/widgets/help_block.html so help
copy can live next to the screen it explains. Visibility is per-user,
toggled from `/profile/` and stored on `core.UserPreference.hide_help`.
See Architecture/dev_docs/08-ui.md §Help blocks for the convention.
"""
from __future__ import annotations

from django import template
from django.template.loader import render_to_string

register = template.Library()


def _user_hides_help(user) -> bool:
    """Per-request cached lookup of the user's hide_help preference.

    Cached on the user instance (one query per request, regardless of how
    many `{% help %}` blocks the page contains).
    """
    if not getattr(user, "is_authenticated", False):
        return False
    if hasattr(user, "_kv_hide_help"):
        return bool(user._kv_hide_help)
    # Imported lazily to keep templatetags loadable before app-ready.
    from core.models import UserPreference
    pref = UserPreference.objects.filter(user=user).only("hide_help").first()
    user._kv_hide_help = bool(pref and pref.hide_help)
    return user._kv_hide_help


class HelpNode(template.Node):
    def __init__(self, title, nodelist):
        self.title = title
        self.nodelist = nodelist

    def render(self, context):
        request = context.get("request")
        user = getattr(request, "user", None) if request else None
        if user is not None and _user_hides_help(user):
            return ""
        body = self.nodelist.render(context)
        return render_to_string(
            "widgets/help_block.html",
            {"title": self.title.resolve(context), "body": body},
            request=request,
        )


@register.tag(name="help")
def do_help(parser, token):
    bits = token.split_contents()
    if len(bits) != 2:
        raise template.TemplateSyntaxError(
            "{% help \"Title\" %}…{% endhelp %} requires exactly one title argument"
        )
    title = parser.compile_filter(bits[1])
    nodelist = parser.parse(("endhelp",))
    parser.delete_first_token()
    return HelpNode(title, nodelist)
