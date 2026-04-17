"""Template tags for parsing Package URLs (purl) and linking to registries."""
from django import template
from django.utils.html import format_html

register = template.Library()

# Registry URL patterns by purl type
REGISTRY_URLS = {
    "deb": ("Debian Packages", "https://packages.debian.org/search?keywords={name}"),
    "rpm": ("RPM Packages", "https://rpmfind.net/linux/rpm2html/search.php?query={name}"),
    "npm": ("npm", "https://www.npmjs.com/package/{name}"),
    "pypi": ("PyPI", "https://pypi.org/project/{name}/"),
    "golang": ("pkg.go.dev", "https://pkg.go.dev/{namespace}/{name}"),
    "gem": ("RubyGems", "https://rubygems.org/gems/{name}"),
    "maven": ("Maven Central", "https://mvnrepository.com/artifact/{namespace}/{name}"),
    "nuget": ("NuGet", "https://www.nuget.org/packages/{name}"),
    "cargo": ("crates.io", "https://crates.io/crates/{name}"),
    "github": ("GitHub", "https://github.com/{namespace}/{name}"),
    "oci": ("Container", "https://hub.docker.com/r/{namespace}/{name}"),
    "apk": ("Alpine Packages", "https://pkgs.alpinelinux.org/packages?name={name}"),
    "cocoapods": ("CocoaPods", "https://cocoapods.org/pods/{name}"),
    "composer": ("Packagist", "https://packagist.org/packages/{namespace}/{name}"),
    "hex": ("Hex.pm", "https://hex.pm/packages/{name}"),
    "swift": ("Swift Packages", "https://swiftpackageindex.com/search?query={name}"),
}


def parse_purl(purl: str) -> dict | None:
    """Parse a Package URL into its components.

    Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    Examples:
      pkg:deb/debian/openssl@1.1.1k
      pkg:npm/express@4.18.2
      pkg:golang/golang.org/x/sys@v0.15.0
      pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1
    """
    from urllib.parse import unquote

    if not purl or not purl.startswith("pkg:"):
        return None

    # Parse on raw (encoded) string first, then decode individual parts.
    # This is necessary because %40 (@) in namespace (e.g. npm scoped
    # packages like %40someorg-scs/aa-sdk) would break the @version split
    # if decoded before parsing.
    rest = purl[4:]

    # Split off subpath (#)
    subpath = ""
    if "#" in rest:
        rest, subpath = rest.rsplit("#", 1)

    # Split off qualifiers (?)
    qualifiers = ""
    if "?" in rest:
        rest, qualifiers = rest.rsplit("?", 1)

    # Split off version — use last @ that isn't percent-encoded
    # rsplit on @ works because the version is always the last @segment
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)

    # Split type/namespace/name
    parts = rest.split("/", 1)
    pkg_type = parts[0]
    remainder = parts[1] if len(parts) > 1 else ""

    # For types like golang, the namespace can contain slashes
    # Split the last segment as name
    if "/" in remainder:
        namespace, name = remainder.rsplit("/", 1)
    else:
        namespace = ""
        name = remainder

    # Decode percent-encoding on each part for display
    return {
        "type": pkg_type,
        "namespace": unquote(namespace),
        "name": unquote(name),
        "version": unquote(version),
        "qualifiers": unquote(qualifiers),
        "subpath": unquote(subpath),
        "full": purl,
    }


@register.inclusion_tag("components/_purl_info.html")
def purl_info(purl: str):
    """Render parsed purl with registry link."""
    parsed = parse_purl(purl)
    if not parsed:
        return {"parsed": None, "purl": purl}

    registry_name = ""
    registry_url = ""
    entry = REGISTRY_URLS.get(parsed["type"])
    if entry:
        registry_name, url_template = entry
        try:
            registry_url = url_template.format(
                name=parsed["name"],
                namespace=parsed["namespace"],
            )
            # golang: namespace includes the full module path
            if parsed["type"] == "golang" and parsed["namespace"]:
                registry_url = f"https://pkg.go.dev/{parsed['namespace']}/{parsed['name']}"
            elif parsed["type"] == "golang":
                registry_url = f"https://pkg.go.dev/{parsed['name']}"
        except (KeyError, IndexError):
            registry_url = ""

    return {
        "parsed": parsed,
        "purl": purl,
        "registry_name": registry_name,
        "registry_url": registry_url,
    }
