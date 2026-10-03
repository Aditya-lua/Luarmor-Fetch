# Tool by @adi.codz (Discord)
"""Shared primitives for the JNKIE pipeline: the Roblox-flavoured HTTP client
(with optional redirect following so we can inspect ``Location`` exactly like
the loader stub does), user-reference resolution (slug / script id / url / file),
delivery-answer classification, and delivered-payload classification.

Nothing here does protocol parsing -- these are pure, reusable helpers kept
small so the loader/fetcher/probe modules stay testable. Standard library only.
"""
import hashlib
import os
import re
import urllib.error
import urllib.request

# --- constants ---------------------------------------------------------------
# The JNKIE edges fingerprint the client; the real loader runs under a Roblox
# executor's HTTP function, so we present the executor UA, not a browser one.
ROBLOX_UA = "Roblox/WinInet"

API_HOST = "https://api.jnkie.com"
# delivery edge: POST the script key here, body = key, Content-Type text/plain.
DELIVERY_TMPL = API_HOST + "/api/v1/luascripts/delivery/%s?v=2&errors=text"
# the two public loader-download edges (both 302 -> cdn.jnkie.com/<hash>.lua):
SCRIPT_LOADER_TMPL = API_HOST + "/api/v1/luascripts/public/%s/download"   # by script id
GAME_LOADER_TMPL = API_HOST + "/api/v1/loaders/public/%s/download"        # by loader slug
SITE_LOADER_TMPL = "https://jnkie.com/loaders/%s"                         # 302 -> the above

# A denial body is "LDR-DENIED:<CODE>\n<human message>" (the loader matches
# exactly this). errors=text asks the edge for this plaintext shape.
DENIAL_PREFIX = "LDR-DENIED"
SCRIPT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# The delivery edge requires a hardware fingerprint that real executors inject
# into their HTTP request fn automatically (the loader never sets it itself).
# Omitting it yields LDR-DENIED:HWID_REQUIRED. The edge reads it from any of
# these header names (executor-dependent); we send the generic one.
HWID_HEADER = "Fingerprint"
HWID_HEADER_ALIASES = ("Fingerprint", "X-Fingerprint", "Syn-Fingerprint")


class JnkieError(RuntimeError):
    """Any recoverable protocol/transport error surfaced to the CLI."""


# --- HTTP --------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect following so a 3xx surfaces with its
    ``Location`` intact -- the loader inspects it by hand, and so do we."""

    def redirect_request(self, *args, **kwargs):
        return None


def http(url, method="GET", headers=None, body=None, timeout=25, follow=False):
    """One HTTP call with the executor UA.

    Returns ``(status, headers_dict, body_str)``. The body is decoded latin-1 so
    binary payloads survive round-trips untouched. 3xx/4xx do not raise: their
    status, headers and body come back like any other response (so a non-followed
    redirect or an ``LDR-DENIED`` 403 is inspectable). ``follow=True`` lets
    urllib chase redirects (used to walk the public-loader -> CDN chain)."""
    h = {"User-Agent": ROBLOX_UA}
    if headers:
        h.update(headers)
    data = body.encode("latin-1") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = (urllib.request.build_opener() if follow
              else urllib.request.build_opener(_NoRedirect))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers.items()), r.read().decode("latin-1")
    except urllib.error.HTTPError as e:              # 3xx (unfollowed) + 4xx/5xx
        return e.code, dict(e.headers.items()), e.read().decode("latin-1")
    except urllib.error.URLError as e:
        raise JnkieError("request to %s failed: %s" % (url, e.reason))


def header_get(headers, name):
    """Case-insensitive header lookup over the dict ``http`` returns."""
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


# --- user-reference resolution ----------------------------------------------
def resolve_reference(ref):
    """Classify a user-supplied source string into ``(kind, value)``:

      ('file',      path)  an existing local file
      ('url',       url)   a full http(s) url (site loader, public edge, or cdn)
      ('script-id', id)    a bare 64-hex script id (go straight to delivery)
      ('slug',      slug)  a game-loader slug (jnkie.com/loaders/<slug>)
    """
    if ref and os.path.isfile(ref):
        return "file", ref
    low = ref.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return "url", ref
    if SCRIPT_ID_RE.match(low):
        return "script-id", low
    m = re.search(r"loaders/([A-Za-z0-9_-]+)", ref)
    if m:
        return "slug", m.group(1)
    return "slug", ref


def delivery_url(script_id):
    return DELIVERY_TMPL % script_id


def normalize_hwid(hwid):
    """Return a plausible executor HWID/fingerprint string.

    An HWID-locked key must receive the *exact* fingerprint it was registered to
    (pass your real one). When none is given we derive a stable 32-hex value so a
    non-locked key still passes the HWID_REQUIRED gate and the same machine
    reproduces the same fingerprint across runs."""
    if hwid:
        return hwid
    seed = (os.environ.get("JNKIE_HWID")
            or "%s|%s" % (os.environ.get("HOSTNAME", ""), os.getuid()
                          if hasattr(os, "getuid") else os.environ.get("USERNAME", "")))
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:32]


# --- classification ----------------------------------------------------------
def classify_delivery(status, headers, body):
    """Bucket a delivery-edge answer.

      denied        the key was rejected (4xx + LDR-DENIED)
      url-body      200 whose body is the CDN url to GET next
      redirect      3xx with a Location to the CDN url
      payload       200 whose body is the script itself (no indirection)
      error         anything else
    """
    b = body.strip()
    if status in (400, 401, 403) and b.startswith(DENIAL_PREFIX):
        return "denied"
    if status == 200 and (b.startswith("https://") or b.startswith("http://")):
        return "url-body"
    if status in (301, 302, 303, 307, 308) and header_get(headers, "Location"):
        return "redirect"
    if status == 200 and b:
        return "payload"
    return "error"


def parse_denial(body):
    """Split ``LDR-DENIED:<CODE>\\n<message>`` into ``(code, message)``.

    Mirrors the loader's own match: the first line is the code (``LDR-DENIED`` or
    ``LDR-DENIED:SOMETHING``), the rest is a human-readable reason."""
    text = body.strip()
    first, _, rest = text.partition("\n")
    first = first.strip()
    code = first if (first == DENIAL_PREFIX or
                     re.match(r"^LDR-DENIED:[A-Z_]+$", first)) else DENIAL_PREFIX
    message = rest.strip() or first
    return code, message


def classify_payload(body):
    """Best-effort bucket for a delivered body (what loadstring would run).

      denied     an LDR-DENIED error leaked through
      url        a bare CDN url (indirection not yet followed)
      luau-bc    compiled Luau bytecode (starts with the \\x1b/\\x00 header)
      lua        readable Lua/Luau source
      html       an HTML/error page (a gate or CDN miss)
      empty      nothing
    """
    if not body:
        return "empty"
    b = body.lstrip()
    if b.startswith(DENIAL_PREFIX):
        return "denied"
    if b.startswith("https://") or b.startswith("http://"):
        return "url"
    if body[:1] in ("\x1b", "\x00") or body[:4] == "\x1bLua":
        return "luau-bc"
    if b[:1] == "<" and ("<html" in b[:200].lower() or "<!doctype" in b[:200].lower()):
        return "html"
    return "lua"
