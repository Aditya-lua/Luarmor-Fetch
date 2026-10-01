# Tool by @adi.codz (Discord)
"""Shared primitives: the Roblox-flavoured HTTP client, server-response
classification, Lua string-escape decoding, and portable discovery of the
Deobfuscator-Luraph-V15 sandbox repo (luau + envlog harness).

Nothing here touches the sandbox; these are pure helpers reused by every
pipeline so the loader/fetcher/probe modules stay small and testable.
"""
import importlib
import os
import sys
import urllib.request

# --- constants ---------------------------------------------------------------
# Luarmor's auth/CDN edges fingerprint the client; the real loader runs under a
# Roblox executor, so we present the executor's UA rather than a browser one.
ROBLOX_UA = "Roblox/Win32"

# Server-side tripwires (plain-text bodies, not the encrypted session blob).
OUTDATED_MARK = "loader code is outdated"
EXEC_TRAP_MARK = "executor is not supported"

# The sandbox repo is identified by these artifacts, not by its directory name.
_REPO_BASENAMES = ("Deobfuscator-Luraph-V15", "deobfuscator-luraph-v15")
_REPO_MARKERS = (
    ("core", "harness.py"),
    ("runtime", "envlog.luau"),
)


class SandboxNotFound(RuntimeError):
    """Raised when the Deobfuscator-Luraph-V15 sandbox repo cannot be located."""


class SandboxError(RuntimeError):
    """Raised when the sandbox is found but cannot execute (e.g. the bundled
    luau binary is incompatible with this CPU)."""


# --- HTTP --------------------------------------------------------------------
def http_get(url, timeout=25, ua=ROBLOX_UA):
    """Single GET with the executor UA. Returns (status, body) with the body
    decoded latin-1 so binary signing blobs survive round-trips untouched."""
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("latin-1")


# --- response classification -------------------------------------------------
def classify_response(body):
    """Bucket an auth-host answer.

    stale-loader   -> the loader's _bsdata0 blobs are from an old rotation
    executor-trap  -> the host flagged the client fingerprint
    session-response -> the real next stage: a JSON array of one hex blob
    json / text    -> anything else
    """
    import re
    if OUTDATED_MARK in body:
        return "stale-loader"
    if EXEC_TRAP_MARK in body:
        return "executor-trap"
    body = body.strip()
    if body.startswith('["') and body.endswith('"]') \
            and re.fullmatch(r'["\[\]0-9a-fA-F\s]+', body):
        return "session-response"
    if body.startswith("{") or body.startswith("["):
        return "json"
    return "text"


# --- Lua string escapes ------------------------------------------------------
def decode_lua_escapes(s):
    """Decode a Lua double-quoted string body (WITHOUT the surrounding quotes)
    to bytes. Handles \\ddd (1-3 decimal), \\xHH (hex) and the named escapes;
    this matches how _bsdata0's binary entries are written by the loader."""
    out = bytearray()
    j = 0
    named = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34,
             "a": 7, "b": 8, "f": 12, "v": 11, "'": 39, "0": 0}
    while j < len(s):
        if s[j] == "\\" and j + 1 < len(s):
            c = s[j + 1]
            if c == "x" and j + 3 < len(s):
                out.append(int(s[j + 2:j + 4], 16))
                j += 4
            elif c.isdigit():
                k = j + 1
                num = ""
                while k < len(s) and s[k].isdigit() and len(num) < 3:
                    num += s[k]
                    k += 1
                out.append(int(num) & 0xFF)
                j = k
            else:
                out.append(named.get(c, 0))
                j += 2
        else:
            out.append(ord(s[j]) & 0xFF)
            j += 1
    return bytes(out)


# --- sandbox-repo discovery --------------------------------------------------
def _looks_like_repo(path):
    if not path or not os.path.isdir(path):
        return False
    return all(os.path.exists(os.path.join(path, *marker))
               for marker in _REPO_MARKERS)


def find_sandbox_repo(explicit=None):
    """Locate the Deobfuscator-Luraph-V15 repo (luau runtime + envlog harness).

    Search order: explicit arg, ``LUARMOR_REPO`` env var, then common sibling
    locations relative to this repo and the home directory (including one level
    of nesting, e.g. ``<base>/<owner>/deobfuscator-luraph-v15``). Raises
    ``SandboxNotFound`` with the full list of places tried when none matches.
    """
    here = os.path.dirname(os.path.abspath(__file__))     # luarmor_crack/
    repo_root = os.path.dirname(here)                      # Luarmor-Fetch/
    parent = os.path.dirname(repo_root)
    home = os.path.expanduser("~")

    bases = (parent, home, os.path.join(home, "my-project"),
             os.path.join(home, "aditya-lua"))
    candidates = [explicit, os.environ.get("LUARMOR_REPO")]
    for base in bases:
        for name in _REPO_BASENAMES:
            candidates.append(os.path.join(base, name))
    # shallow scan one level deeper (nested clones)
    for base in bases:
        try:
            subdirs = sorted(os.listdir(base))
        except OSError:
            continue
        for sub in subdirs:
            for name in _REPO_BASENAMES:
                candidates.append(os.path.join(base, sub, name))

    tried = []
    for cand in candidates:
        if not cand:
            continue
        cand = os.path.abspath(os.path.expanduser(cand))
        if cand in tried:
            continue
        tried.append(cand)
        if _looks_like_repo(cand):
            return cand
    raise SandboxNotFound(
        "Deobfuscator-Luraph-V15 sandbox not found (needs core/harness.py + "
        "runtime/envlog.luau).\nSet LUARMOR_REPO or pass --repo. Tried:\n  "
        + "\n  ".join(tried))


def import_harness(repo_path):
    """Import the sandbox ``harness`` module from a discovered repo without
    polluting import state for callers that discover a different repo later."""
    core = os.path.join(repo_path, "core")
    if core not in sys.path:
        sys.path.insert(0, core)
    # tools/ carries sibling helpers harness may import lazily
    tools = os.path.join(repo_path, "tools")
    if os.path.isdir(tools) and tools not in sys.path:
        sys.path.insert(0, tools)
    return importlib.import_module("harness")


def ensure_luau_executable(path):
    """Fresh clones drop the exec bit; restore it if the file exists."""
    if path and os.path.exists(path):
        try:
            mode = os.stat(path).st_mode
            if not (mode & 0o111):
                os.chmod(path, mode | 0o111)
        except OSError:
            pass
        return path
    return None


def resolve_luau(repo_path, explicit=None):
    """Pick the luau binary to run.

    Order: explicit arg, ``LUARMOR_LUAU`` env, the repo's ``bin/luau``, then a
    ``luau`` on PATH. The explicit/env override exists because the repo's
    prebuilt binary may be built for a microarchitecture the host CPU does not
    implement (it then faults with an illegal instruction); a user can point at
    a compatible build without touching the sandbox repo."""
    exe = "luau.exe" if os.name == "nt" else "luau"
    for cand in (explicit, os.environ.get("LUARMOR_LUAU"),
                 os.path.join(repo_path, "bin", exe)):
        if cand and os.path.exists(cand):
            return ensure_luau_executable(cand)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, exe)
        if os.path.exists(p):
            return p
    raise SandboxError(
        "no luau binary found (looked at --luau, LUARMOR_LUAU, %s/bin/%s, PATH). "
        "Build one with `python build_luau.py` in the sandbox repo, or install luau."
        % (repo_path, exe))


def preflight_luau(luau):
    """Run a trivial script to confirm luau actually executes on this machine.

    Returns None on success, or a human-readable reason string on failure. The
    bundled binary can abort with SIGILL (invalid opcode) on CPUs missing the
    instructions it was built for; that surfaces here as a clear message instead
    of a silent empty sandbox trace downstream."""
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".luau", delete=False) as f:
        f.write('print("__LRM_OK__")\n')
        probe = f.name
    try:
        r = subprocess.run([luau, probe], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return "could not run luau (%s)" % e
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass
    if r.returncode < 0:
        import signal
        signame = signal.Signals(-r.returncode).name if -r.returncode in \
            set(s.value for s in signal.Signals) else "signal %d" % (-r.returncode)
        if -r.returncode == getattr(signal, "SIGILL", 4):
            return ("luau aborted with SIGILL (illegal instruction): the binary at %s "
                    "was built for a CPU microarchitecture this machine does not "
                    "implement. Supply a compatible build via --luau or LUARMOR_LUAU."
                    % luau)
        return "luau aborted with %s" % signame
    if b"__LRM_OK__" not in r.stdout:
        return ("luau ran but produced no output (rc=%d); the binary may be incompatible. "
                "Supply a working build via --luau or LUARMOR_LUAU." % r.returncode)
    return None
