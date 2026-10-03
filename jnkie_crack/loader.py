# Tool by @adi.codz (Discord)
"""Pure parsing of JNKIE loader stubs -- no I/O, no network, fully unit-testable.

Two loader variants are produced by JNKIE and both are plain, readable Lua:

* **script-key loader** (``/api/v1/luascripts/public/<id>/download``): a ~2.5 KB
  stub bound to a single script id. It POSTs the key to the delivery edge, then
  follows either a ``https://`` body or a ``Location`` 302 to the CDN, and
  ``loadstring``s the result.

* **game-loader** (``jnkie.com/loaders/<slug>``): a bundle that maps the current
  Roblox place/game to one of many protected scripts. Its head declares
  ``local S,P,G = {<64-hex ids>}, {[placeId]=i}, {[gameId]=i}`` and picks
  ``i = P[game.PlaceId] or G[game.GameId]`` before running the same handshake on
  ``S[i]``.

Protocol reference: docs/JNKIE_NOTES.md.
"""
import re

# --- signatures / extractors -------------------------------------------------
DELIVERY_ID_RE = re.compile(r"luascripts/delivery/([0-9a-f]{64})")
HEX64_RE = re.compile(r'"([0-9a-f]{64})"')
INTMAP_RE = re.compile(r"\[(\d+)\]\s*=\s*(\d+)")
SPG_HEAD_RE = re.compile(r"local\s+S\s*,\s*P\s*,\s*G\s*=\s*")
DELIVERY_EP_RE = re.compile(r'(https?://[^/"\']+)/api/v1/luascripts/delivery/')
KICK_RE = re.compile(r':Kick\(\s*h\s*\)|ErrorMessage')
GETGENV_KEY_RE = re.compile(r"getgenv\(\)\s*\.\s*SCRIPT_KEY")
REQUEST_FNS = ("syn.request", "request", "http_request", "http.request")


def _brace_group(s, i):
    """Given ``s[i] == '{'`` return ``(inner_text, index_after_closing_brace)``,
    honouring Lua string literals so braces inside strings don't miscount."""
    if s[i] != "{":
        raise ValueError("expected '{' at offset %d" % i)
    depth, j = 0, i
    instr, esc, quote = False, False, ""
    while j < len(s):
        c = s[j]
        if instr:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                instr = False
        elif c in ('"', "'"):
            instr, quote = True, c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i + 1:j], j + 1
        j += 1
    raise ValueError("unbalanced braces from offset %d" % i)


def _int_map(text):
    return {int(a): int(b) for a, b in INTMAP_RE.findall(text)}


def parse_loader(text):
    """Classify and decompose a loader stub.

    Returns a dict with: ``variant`` (``game-loader`` | ``script-key`` |
    ``unknown``), ``script_ids`` (ordered), ``place_map`` / ``game_map`` (int ->
    1-based index into ``script_ids``), ``delivery_host``, ``uses_getgenv_key``,
    ``request_fns`` (executor HTTP fns referenced), and ``is_jnkie``.
    """
    is_jnkie = ("JNKIE" in text) or bool(DELIVERY_ID_RE.search(text))
    info = {
        "is_jnkie": is_jnkie,
        "variant": "unknown",
        "script_ids": [],
        "place_map": {},
        "game_map": {},
        "delivery_host": None,
        "uses_getgenv_key": bool(GETGENV_KEY_RE.search(text)),
        "request_fns": [fn for fn in REQUEST_FNS if fn in text],
    }
    hm = DELIVERY_EP_RE.search(text)
    if hm:
        info["delivery_host"] = hm.group(1)

    head = SPG_HEAD_RE.search(text)
    if head:
        # game-loader: three consecutive brace groups S, P, G.
        i = text.index("{", head.end())
        s_body, k = _brace_group(text, i)
        i2 = text.index("{", k)
        p_body, k2 = _brace_group(text, i2)
        i3 = text.index("{", k2)
        g_body, _ = _brace_group(text, i3)
        info["variant"] = "game-loader"
        info["script_ids"] = HEX64_RE.findall(s_body)
        info["place_map"] = _int_map(p_body)
        info["game_map"] = _int_map(g_body)
        return info

    ids = []
    for m in DELIVERY_ID_RE.finditer(text):
        if m.group(1) not in ids:
            ids.append(m.group(1))
    if ids:
        info["variant"] = "script-key"
        info["script_ids"] = ids
    return info


def select_script_id(info, index=None, place_id=None, game_id=None):
    """Pick a script id from a parsed loader.

    * ``place_id`` / ``game_id`` resolve through the game-loader's maps.
    * ``index`` is 1-based into ``script_ids``.
    * otherwise the first id (the only one, for a script-key loader).

    Returns ``(script_id, how)`` or raises ``ValueError`` when nothing matches.
    """
    ids = info.get("script_ids") or []
    if not ids:
        raise ValueError("no script ids in this loader")
    if place_id is not None:
        idx = info.get("place_map", {}).get(int(place_id))
        if not idx:
            raise ValueError("place id %s not covered by this loader" % place_id)
        return ids[idx - 1], "place:%s" % place_id
    if game_id is not None:
        idx = info.get("game_map", {}).get(int(game_id))
        if not idx:
            raise ValueError("game id %s not covered by this loader" % game_id)
        return ids[idx - 1], "game:%s" % game_id
    if index is not None:
        if not (1 <= index <= len(ids)):
            raise ValueError("index %d out of range (1..%d)" % (index, len(ids)))
        return ids[index - 1], "index:%d" % index
    return ids[0], "default"
