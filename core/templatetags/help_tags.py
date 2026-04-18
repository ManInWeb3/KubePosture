"""
{% help "Optional title" %}
  <p>Help body — plain HTML.</p>
{% endhelp %}

Renders a Tabler alert-info block only when the current user has
preference.show_help == True (default for new users). Anonymous users
never see help blocks.
"""
from django import template
from django.template.loader import render_to_string

register = template.Library()


class HelpNode(template.Node):
    def __init__(self, nodelist, title):
        self.nodelist = nodelist
        self.title = title

    def render(self, context):
        user = context.get("user")
        if not user or not user.is_authenticated:
            return ""
        if not _show_help(user):
            return ""
        title = self.title.resolve(context) if self.title else ""
        body = self.nodelist.render(context)
        return render_to_string("widgets/help_block.html", {
            "title": title,
            "body": body,
        })


def _show_help(user) -> bool:
    pref = getattr(user, "preference", None)
    if pref is None:
        return True
    return pref.show_help


@register.tag(name="help")
def do_help(parser, token):
    bits = token.split_contents()
    title = parser.compile_filter(bits[1]) if len(bits) > 1 else None
    nodelist = parser.parse(("endhelp",))
    parser.delete_first_token()
    return HelpNode(nodelist, title)
