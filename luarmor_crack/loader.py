# Tool by @adi.codz (Discord)
"""Stage 1-2 parsing and input assembly for the Luarmor v4 bootstrap.

Everything in this module is pure: it transforms the loader stub text and the
sephal init text into the primed source the sandbox runs, plus small helpers
(time-pin derivation, handshake extraction) used by the fetcher. No I/O, no
sandbox, no network -- which keeps it fully unit-testable.

Protocol reference: docs/LUARMOR_NOTES.md sections 11-15.
"""
import re
import time

from .common import decode_lua_escapes


# ---------------------------------------------------------------------------
# stage 1: the loader stub (api.luarmor.net/files/v4/loaders/<md5>.lua)
# ---------------------------------------------------------------------------
def parse_stub(text):
    """The 5-line unobfuscated v4 stub -> {bsdata0_line, module_id, init_url}."""
    m = re.search(r'(_bsdata0=\{.*?\};)', text, re.S)
    if not m:
        raise ValueError("no _bsdata0 line in the loader stub "
                         "(is this a Luarmor v4 loader?)")
    bs_line = m.group(1).strip()

    m = re.search(r'"([0-9a-f]+-sephal)"', text)
    module_id = m.group(1) if m else None
    if not module_id:
        m = re.search(r'local f,b,a="[^"]+","([^"]+)"', text)
        module_id = m.group(1) if m else None
    if not module_id:
        raise ValueError("no module id in the loader stub")

    m = re.search(r'game:HttpGet\("([^"]+)"', text)
    init_url = m.group(1) if m else None

    return {"bsdata0_line": bs_line, "module_id": module_id,
            "init_url": init_url, "stub": text}


def parse_bsdata0(line):
    """The _bsdata0 table literal -> Lua-style 1-indexed dict of ints / bytes."""
    m = re.search(r"_bsdata0=\{(.*?)\};", line, re.S)
    if not m:
        raise ValueError("no _bsdata0 table literal to parse")
    body = m.group(1)
    parts, cur, inq, esc = [], "", False, False
    for ch in body:
        if inq:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                inq = False
        elif ch == '"':
            inq = True
            cur += ch
        elif ch == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)

    def conv(p):
        p = p.strip()
        if p.startswith('"'):
            return decode_lua_escapes(p[1:-1])
        return int(p)

    return {i + 1: conv(p) for i, p in enumerate(parts)}


# ---------------------------------------------------------------------------
# stage 2: the sephal init (v4_init_sephal.lua, a Luraph v15 chunk itself)
# ---------------------------------------------------------------------------
def parse_init(text):
    """The sephal init -> {blob, chunk}.

    Layout: a short header comment, then ``superflow_bytecode={...}`` (the
    ~9.6 KB encrypted program as a global table), then the Luraph v15 VM chunk
    starting at ``return setmetatable({``. Everything may sit on one line.
    The chunk's final ``:TK()`` call is normalized to receive the module id as
    its vararg, mirroring the stub's ``loadstring(a)(module_id)`` fresh path.
    """
    m = re.search(r"(superflow_bytecode=\{.*?\})", text)
    if not m:
        raise ValueError("no superflow_bytecode table in the init (wrong file?)")
    blob = m.group(1)
    rest = text[m.end():]
    cm = re.search(r"return setmetatable\(\{", rest)
    if not cm:
        raise ValueError("no VM chunk (`return setmetatable`) after the blob")
    chunk = rest[cm.start():]
    chunk = re.sub(r":TK\(\)\s*\([^;]*\)\s*;?\s*$", ':TK()(__MODULE_ID__);', chunk)
    chunk = re.sub(r":TK\(\)\s*;?\s*$", ':TK()(__MODULE_ID__);', chunk)
    if not chunk.rstrip().endswith(';'):
        chunk = chunk.rstrip() + ';'
    return {"blob": blob, "chunk": chunk.rstrip()}


def build_input(stub, init, module_id, script_key, init_text):
    """Stub-faithful primed source assembled in the exact order the loader's
    fresh-download path uses: script_key, _bsdata0, superflow blob, ldrupd8m
    (the raw init text the stub sets only on fresh downloads), then the VM chunk
    with the module id passed as its vararg.

    The _bsdata0-before-blob order matters: the blob's last element embeds a
    runtime concat with _bsdata0[10] (LUARMOR_NOTES.md section 12)."""
    key = script_key or "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"
    chunk = init["chunk"].replace('__MODULE_ID__', '"%s"' % module_id)
    return (
        'script_key="%s";\n' % key
        + stub["bsdata0_line"] + "\n"
        + init["blob"] + "\n"
        + "ldrupd8m=[========[" + init_text + "]========];\n"
        + chunk + "\n"
    )


# ---------------------------------------------------------------------------
# sandbox-clock pinning (the loader's build stamp)
# ---------------------------------------------------------------------------
def loader_time_pin(stub_text):
    """Derive the sandbox clock from the loader's build timestamp.

    _bsdata0 carries a ~now epoch entry that rotates with the loader file. A
    stale time_pin skews the bootstrap's clock vs the server (hours after a
    container reset) and the session validation rejects -> State848. Falls back
    to wall-clock now when no plausible epoch entry is present."""
    now = int(time.time())
    m = re.search(r"_bsdata0=\{([^}]*)\}", stub_text)
    if m:
        for n in re.findall(r"\d{9,10}", m.group(1)):
            v = int(n)
            if abs(v - now) < 4 * 86400:
                return v
    return now


# ---------------------------------------------------------------------------
# trace parsing (handshake + behaviour markers)
# ---------------------------------------------------------------------------
def extract_handshake(raw):
    """Pull the captured auth request and behaviour markers from a raw trace."""
    out = {"url": None, "a": None, "d": None, "b": None, "urls": [],
           "states": [], "loadstrings": []}
    m = re.search(r'Url = "(https://x\.luarmor\.net[^"]+)"', raw)
    if m:
        out["url"] = m.group(1)
        q = m.group(1)
        for k in ("a", "d", "b"):
            km = re.search(r"[?&]%s=([^&]*)" % k, q)
            if km:
                out[k] = km.group(1)
    out["urls"] = re.findall(r"--   (https?://\S+)", raw)
    out["states"] = sorted(set(re.findall(r"Error: (State\d+)", raw)))
    out["loadstrings"] = re.findall(r"loadstring\(\) of (\d+) bytes", raw)
    out["gui"] = "ScreenGui" in raw
    out["canary"] = "P2D GetLength" in raw
    out["kicked"] = "LocalPlayer:Kick" in raw
    return out
