# Tool by @adi.codz (Discord)
"""Stage 3-5 of the Luarmor pipeline: run the bootstrap in the Luau/envlog
sandbox, capture the auth handshake, replay it live, and (two-phase) drive the
full same-process protocol with in-run live fetch.

This module replaces the parent repo's Node.js entry points (``scripts/run_raw.js``,
``scripts/patch_primed.js``) with direct use of the Python sandbox:
``core/harness.py`` for building/running the harness, and
``core/obfuscators/luraph_v15/driver.py`` for the VM entry/spin patching. No
``node`` process is spawned. The sandbox repo is discovered at runtime
(``common.find_sandbox_repo``); nothing is vendored here.
"""
import os
import re
import select
import subprocess
import sys
import tempfile
import time
import urllib.request

from . import common
from .loader import (build_input, extract_handshake, loader_time_pin,
                     parse_bsdata0, parse_init, parse_stub)


# ---------------------------------------------------------------------------
# sandbox wiring (discovery + dynamic import, Node-free)
# ---------------------------------------------------------------------------
class Sandbox:
    """Bundles a discovered sandbox repo: the harness module, the luraph_v15
    patcher, and the luau binary path. One instance per run."""

    def __init__(self, repo_path, luau=None, preflight=True):
        self.repo = repo_path
        self.harness = common.import_harness(repo_path)
        self.luau = common.resolve_luau(repo_path, luau)
        if preflight:
            reason = common.preflight_luau(self.luau)
            if reason:
                raise common.SandboxError(reason)
        # the entry/spin patcher lives in the luraph_v15 obfuscator package;
        # core/ is already on sys.path via import_harness.
        from obfuscators.luraph_v15 import driver as _driver  # noqa: E402
        self._driver = _driver

    def patch(self, source, tmpdir):
        """Apply the VM entry tags + spin rewrite the driver normally applies
        (so serve-mode and single runs behave like the Node run_raw path).
        Entry patching parses an AST and is best-effort; the spin rewrite is a
        pure regex and always runs."""
        patched = source
        try:
            p = os.path.join(tmpdir, "_primed_for_ast.luau")
            with open(p, "w", encoding="latin-1", newline="") as f:
                f.write(source)
            try:
                patched = self._driver.patch_entries(source, p)
            finally:
                if os.path.exists(p):
                    os.remove(p)
        except Exception as e:
            sys.stderr.write("[i] entry patch skipped (%s); spin rewrite still applied\n" % e)
        return self._driver.patch_spin(patched)


# ---------------------------------------------------------------------------
# stage 1-2 helpers (source acquisition, shared by both pipelines)
# ---------------------------------------------------------------------------
def obtain_stub(loader_url=None, loader_file=None):
    """Fetch (fresh) or read a loader stub. Blobs rotate ~hourly, so a URL is
    preferred; saved stubs go stale within the hour."""
    if loader_url:
        status, text = common.http_get(loader_url)
        if status != 200 or "_bsdata0" not in text:
            raise RuntimeError("loader fetch failed (%s, %d bytes)" % (status, len(text)))
        return text
    if loader_file:
        with open(loader_file, encoding="latin-1") as f:
            return f.read()
    raise RuntimeError("no loader source: give a loader URL or file")


def obtain_init(init_file=None, init_url=None):
    """Read a cached sephal init, or try the CDN (which gates non-executor
    clients). Returns (text, source_label)."""
    if init_file:
        with open(init_file, encoding="latin-1") as f:
            return f.read(), "file"
    if init_url:
        status, text = common.http_get(init_url)
        if common.EXEC_TRAP_MARK in text or text.lstrip().startswith("<") \
                or len(text) < 100000:
            raise RuntimeError(
                "the CDN gate served a trap/placeholder (%d bytes); the real init is "
                "executor-only. Save one from an executor cache "
                "(static_content_170926/init-<module>.lua) and pass it with --init."
                % len(text))
        return text, "cdn"
    raise RuntimeError("no init available: pass --init with a cached sephal init file")


# ---------------------------------------------------------------------------
# the simple pipeline (single sandbox run + live handshake)
# ---------------------------------------------------------------------------
def run_simple_pipeline(args):
    """luarmor_fetch.py's 6-stage pipeline, Node-free. Returns a report dict."""
    outdir = args.output
    os.makedirs(outdir, exist_ok=True)
    report = {"stages": {}}

    # -- stage 1: loader ----------------------------------------------------
    print("[1] obtaining the loader stub ...")
    stub_text = obtain_stub(args.loader_url, args.loader)
    stub = parse_stub(stub_text)
    bs = parse_bsdata0(stub["bsdata0_line"])
    print("    module id : %s" % stub["module_id"])
    print("    init url   : %s" % (stub["init_url"] or "(none)"))
    print("    _bsdata0   : %d entries" % len(bs))
    report["stages"]["loader"] = {"module_id": stub["module_id"],
                                  "init_url": stub["init_url"],
                                  "bsdata0_entries": len(bs)}

    # -- stage 2: init ------------------------------------------------------
    print("[2] obtaining the sephal init ...")
    init_text, init_source = obtain_init(args.init, stub["init_url"])
    init = parse_init(init_text)
    print("    from %s (%d bytes); blob %d, chunk %d"
          % (init_source, len(init_text), len(init["blob"]), len(init["chunk"])))
    report["stages"]["init"] = {"source": init_source, "bytes": len(init_text)}

    # -- stage 3: sandbox bootstrap -----------------------------------------
    print("[3] running the bootstrap in the sandbox (builds the auth request) ...")
    sandbox = Sandbox(common.find_sandbox_repo(args.repo), luau=getattr(args, "luau", None))
    primed = build_input(stub, init, stub["module_id"], args.script_key, init_text)
    with open(os.path.join(outdir, "sephal_primed.lua"), "w", encoding="latin-1") as f:
        f.write(primed)
    tmp = tempfile.mkdtemp(prefix="lrm_simple_", dir=outdir)
    patched = sandbox.patch(primed, tmp)
    cfg = {
        "readfile_map": {"static_content_170926/init-%s.lua" % stub["module_id"]: init_text},
        "time_pin": loader_time_pin(stub_text),
        "time_budget": 300, "devirt": False, "spin": 60,
        "trace_globals": True, "call_log": True,
    }
    hpath = os.path.join(tmp, "harness.luau")
    body, err = sandbox.harness.run_once(sandbox.luau, patched, cfg, hpath,
                                         timeout=300, keep=True)
    raw = sandbox.harness.LAST_RAW[0]
    sandbox.harness.save_raw(os.path.join(outdir, "bootstrap.raw.txt"))
    hs = extract_handshake(raw)
    print("    GUI: %s  canary: %s  states: %s" % (hs["gui"], hs["canary"], hs["states"] or "-"))
    if hs["url"]:
        print("    auth request captured: a=%s.. d=..(%d) b=..(%d)"
              % ((hs["a"] or "")[:6], len(hs["d"] or ""), len(hs["b"] or "")))
    else:
        print("    [!] no auth request captured; see bootstrap.raw.txt"
              + (" (sandbox error: %s)" % err[-200:] if err else ""))
    report["stages"]["bootstrap"] = {k: v for k, v in hs.items()}

    # -- stage 4: live handshake --------------------------------------------
    if not hs["url"] or args.skip_live:
        print("[4] handshake replay skipped")
        return report
    print("[4] replaying the handshake live (the b signature is one-time) ...")
    try:
        status, resp = common.http_get(hs["url"])
    except Exception as e:
        print("    [!] request failed: %s" % e)
        return report
    kind = common.classify_response(resp)
    print("    server: %s (%d bytes) -> %s" % (status, len(resp), kind))
    report["stages"]["handshake"] = {"status": status, "kind": kind, "bytes": len(resp)}
    if kind == "stale-loader":
        print("    [!] the loader's _bsdata0 blobs are STALE: re-fetch with --loader-url")
    elif kind == "session-response":
        print("    [+] SESSION ACCEPTED -- the sandbox-built signature is valid")
        print("    [i] cross-run replay is nonce-bound; use `two-phase` to decrypt in-process")
    elif kind == "executor-trap":
        print("    [!] the auth host flagged the client fingerprint")
    return report


# ---------------------------------------------------------------------------
# the two-phase same-process driver (in-run live fetch, nonce-stable)
# ---------------------------------------------------------------------------
def run_two_phase(args):
    """luarmor_two_phase.py's same-process driver, Node-free and path-portable.

    One luau process: build the handshake -> yield NEEDFETCH -> fetch live ->
    plant the response -> resume. Same process = same per-process nonce, so the
    response decrypts in-sandbox. Returns a report dict."""
    outdir = args.output
    os.makedirs(outdir, exist_ok=True)
    script_key = args.script_key or os.environ.get("LRM_SCRIPT_KEY")

    # -- source --------------------------------------------------------------
    print("[0] obtaining loader + init ...")
    stub_text = obtain_stub(args.loader_url, args.loader)
    stub = parse_stub(stub_text)
    init_text, _ = obtain_init(args.init, stub["init_url"])
    init = parse_init(init_text)
    print("[1] loader: module id %s, %d _bsdata0 entries"
          % (stub["module_id"], stub["bsdata0_line"].count(",")))

    primed = build_input(stub, init, stub["module_id"], script_key, init_text)
    if not script_key:
        print("    [i] no script key (--script-key / LRM_SCRIPT_KEY): the session decrypt will "
              "fail by design (the server keys the response to the real key)")
    with open(os.path.join(outdir, "primed.lua"), "w", encoding="latin-1") as f:
        f.write(primed)

    sandbox = Sandbox(common.find_sandbox_repo(args.repo), luau=getattr(args, "luau", None))
    tmp = tempfile.mkdtemp(prefix="lrm2p_", dir=outdir)
    # the driver always runs the patched source (entry tags + spin rewrite);
    # an unpatched source never reaches the handshake in serve mode.
    patched = sandbox.patch(primed, tmp)

    time_pin = loader_time_pin(stub_text)
    print("    time_pin: %d (loader build time, now=%d)" % (time_pin, int(time.time())))
    cfg = {
        "readfile_map": {"static_content_170926/init-%s.lua" % stub["module_id"]: init_text},
        "time_pin": time_pin,
        "time_budget": 300, "devirt": False, "spin": 60, "trace_globals": True,
        "call_log": True, "call_log_full": True, "serve": True,
    }
    src = sandbox.harness.build_harness(patched, cfg, None)
    hp = os.path.join(tmp, "harness.luau")
    with open(hp, "w", encoding="latin-1", newline="\n") as f:
        f.write(src)
    harness = sandbox.harness
    proc = subprocess.Popen([sandbox.luau], cwd=tmp, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    print("[2] require + start: driving the live protocol in-run ...")
    proc.stdin.write(b'__S = require("./harness")\n')
    proc.stdin.flush()
    time.sleep(8)                      # let the multi-MB harness module compile
    try:                               # drain anything the compile printed
        while select.select([proc.stdout], [], [], 0.5)[0]:
            if not proc.stdout.read1(1 << 20):
                break
    except Exception:
        pass

    def repl(stmt, timeout=120, expect=None):
        """One REPL statement; read until the expected sentinel / ENVLOG-END."""
        proc.stdin.write(stmt.encode() + b"\n")
        proc.stdin.flush()
        end = (expect or harness.mark("ENVLOG-END")).encode()
        buf = b""
        t0 = time.time()
        while end not in buf:
            left = timeout - (time.time() - t0)
            if left <= 0:
                return None, buf.decode("latin-1", "replace")[-2000:]
            r, _, _ = select.select([proc.stdout], [], [], min(left, 5))
            if not r:
                continue
            chunk = proc.stdout.read1(1 << 20)
            if not chunk:
                return None, "process exited: " + buf.decode("latin-1", "replace")[-2000:]
            buf += chunk
        return buf.decode("latin-1", "replace"), None

    def drive(stmt, timeout):
        """Send one serve call; read until NEEDFETCH / ENVLOG-END / timeout."""
        proc.stdin.write(stmt.encode() + b"\n")
        proc.stdin.flush()
        buf = b""
        t0 = time.time()
        while True:
            left = timeout - (time.time() - t0)
            if left <= 0:
                return "timeout", buf.decode("latin-1", "replace")
            r, _, _ = select.select([proc.stdout], [], [], min(left, 2))
            if not r:
                continue
            chunk = proc.stdout.read1(1 << 20)
            if not chunk:
                return "dead", buf.decode("latin-1", "replace")
            buf += chunk
            m = re.search(rb"NEEDFETCH (https?://\S+)", buf)
            if m:
                return "fetch", m.group(1).decode()
            if harness.mark("ENVLOG-END").encode() in buf:
                return "end", buf.decode("latin-1", "replace")

    planted = {}

    def plant(url_u, body_u, headers_u):
        """Native-table plant: no JSON decoder in the path, any body size."""
        def esc(s):
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') \
                .replace("\n", "\\n").replace("\r", "\\r") + '"'
        idx = len(planted) + 1 + 1000
        mod_p = os.path.join(tmp, "resp_%d.luau" % idx)
        hdr = "{" + ", ".join("[%s] = %s" % (esc(str(k)), esc(str(v)))
                              for k, v in headers_u.items()) + "}"
        with open(mod_p, "w", encoding="latin-1") as f:
            f.write("return { url = %s, body = %s, headers = %s }\n"
                    % (esc(url_u), esc(body_u), hdr))
        okp = errp = None
        for attempt in range(3):       # the REPL can swallow a post-compile stmt
            okp, errp = repl('__S(require("./resp_%d"), "", "plant")' % idx,
                             120, expect="PLANT-")
            if okp is not None and "PLANT-OK" in okp:
                break
            print("    (plant retry %d)" % (attempt + 1))
        if okp is None or ("PLANT-OK %d" % len(body_u)) not in okp:
            print("[!] plant failed:", (okp or errp or "")[-300:].strip())
            return False
        planted[url_u] = len(body_u)
        return True

    # -- the NEEDFETCH / resume loop ----------------------------------------
    stmt = '__S("", "", "start")'
    nfetch = 0
    data = ""
    while True:
        mode, data = drive(stmt, 300)
        if mode != "fetch":
            break
        nfetch += 1
        url_u = data
        print("    round %d NEEDFETCH ...%s" % (nfetch, url_u[-40:]))
        try:
            req = urllib.request.Request(url_u, headers={"User-Agent": common.ROBLOX_UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                body_u = r.read().decode("latin-1")
                headers_u = {k: v for k, v in r.headers.items()}
        except Exception as exc:
            print("[!] live fetch failed: %s" % exc)
            proc.kill()
            return {"error": "live fetch failed", "fetches": nfetch}
        kind = common.classify_response(body_u)
        print("        -> %s (%d bytes)" % (kind, len(body_u)))
        with open(os.path.join(outdir, "resp_r%02d.txt" % nfetch), "w",
                  encoding="latin-1") as f:
            f.write(body_u)
        if kind in ("stale-loader", "executor-trap"):
            print("[!] server rejected the handshake: %s" % body_u[:140])
            proc.kill()
            return {"error": kind, "fetches": nfetch}
        if not plant(url_u, body_u, headers_u):
            proc.kill()
            return {"error": "plant failed", "fetches": nfetch}
        stmt = '__S("", "", "resume")'

    text = data if isinstance(data, str) else data.decode("latin-1", "replace")
    with open(os.path.join(outdir, "final.raw.txt"), "w", encoding="latin-1") as f:
        f.write(text)
    states = sorted(set(re.findall(r"Error: (State\d+)", text)))
    chunks = re.findall(r"loadstring\(\) of (\d+) bytes", text)
    kicked = "LocalPlayer:Kick" in text

    # recover any loadstring'd client chunks the run emitted. The runtime wraps
    # each as \0<nonce>CHUNK <key>\n<hex>\n; match it nonce-agnostically (the
    # per-run nonce varies and need not be reconstructed here). On a successful
    # chain this hex decodes to the decrypted client payload.
    recovered = []
    for key, hx in re.findall(r"\x00[0-9a-f]*CHUNK (\S+)\n([0-9a-f]+)\n", text):
        try:
            src = bytes.fromhex(hx).decode("latin-1")
        except ValueError:
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:48]
        path = os.path.join(outdir, "recovered_%s.lua" % safe)
        with open(path, "w", encoding="latin-1") as f:
            f.write(src)
        recovered.append((path, len(src)))

    print("[3] run finished: fetches=%d states=%s loadstrings=%s kicked=%s"
          % (nfetch, states or "-", chunks or "-", kicked))
    for path, n in recovered:
        head = ""
        try:
            with open(path, encoding="latin-1") as f:
                head = f.readline().strip()[:70]
        except OSError:
            pass
        print("    [+] recovered client chunk: %s (%d bytes) %s" % (path, n, head))
    print("[+] artifacts in %s" % outdir)
    proc.kill()
    return {"fetches": nfetch, "states": states, "loadstrings": chunks,
            "kicked": kicked, "recovered": [p for p, _ in recovered]}
