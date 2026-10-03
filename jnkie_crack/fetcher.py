# Tool by @adi.codz (Discord)
"""Live side of the JNKIE pipeline: resolve a loader reference to its stub text,
then run the delivery handshake (POST key -> follow CDN url -> recover payload).

Unlike Luarmor-Fetch there is no sandbox and no signature to build: the loader's
only input is the plaintext ``script_key``, so given a key you own, this
reproduces the exact request the executor loader makes and recovers the final
``loadstring``'d body. The chain soft-fails (``LDR-DENIED``) without a valid key,
by design.
"""
import json
import os

from . import common
from .loader import parse_loader, select_script_id


# ---------------------------------------------------------------------------
# loader acquisition
# ---------------------------------------------------------------------------
def resolve_loader(ref, timeout=25):
    """Turn a user reference into ``(text, meta)``.

    ``ref`` may be a local file, a full url (site loader / public edge / CDN), a
    bare 64-hex script id, or a game-loader slug. For the network cases the
    public edges 302 to ``cdn.jnkie.com/<hash>.lua``; we follow that chain and
    return the stub text plus where it came from.
    """
    kind, val = common.resolve_reference(ref)
    meta = {"reference": ref, "kind": kind}
    if kind == "file":
        with open(val, encoding="latin-1") as f:
            meta["source"] = "file:%s" % val
            return f.read(), meta
    if kind == "script-id":
        url = common.SCRIPT_LOADER_TMPL % val
    elif kind == "slug":
        url = common.GAME_LOADER_TMPL % val
    else:                                            # full url
        url = val
    status, _, body = common.http(url, follow=True, timeout=timeout)
    if status != 200 or not body.strip():
        raise common.JnkieError("loader fetch failed (%s, %d bytes) from %s"
                                 % (status, len(body), url))
    meta["source"] = url
    return body, meta


# ---------------------------------------------------------------------------
# the delivery handshake
# ---------------------------------------------------------------------------
def deliver(script_id, key, hwid=None, timeout=25):
    """Run the delivery handshake for one script id with the given key.

    ``hwid`` is the hardware fingerprint the edge requires (see
    ``common.normalize_hwid``); an HWID-locked key needs its exact registered
    value. Returns a result dict: ``{script_id, status, kind, denied(bool),
    code, message, final_url, payload(str|None), payload_kind, bytes, hwid}``.
    Never raises on a protocol-level denial -- that is reported in the dict.
    """
    if not common.SCRIPT_ID_RE.match(script_id):
        raise ValueError("not a 64-hex script id: %r" % script_id)
    fingerprint = common.normalize_hwid(hwid)
    url = common.delivery_url(script_id)
    status, headers, body = common.http(
        url, method="POST",
        headers={"Content-Type": "text/plain", common.HWID_HEADER: fingerprint},
        body=key, timeout=timeout)
    kind = common.classify_delivery(status, headers, body)
    out = {"script_id": script_id, "status": status, "kind": kind,
           "denied": False, "code": None, "message": None, "hwid": fingerprint,
           "final_url": None, "payload": None, "payload_kind": None, "bytes": 0}

    if kind == "denied":
        code, message = common.parse_denial(body)
        out.update(denied=True, code=code, message=message)
        return out

    final_url = None
    if kind == "url-body":
        final_url = body.strip()
    elif kind == "redirect":
        final_url = common.header_get(headers, "Location")
    elif kind == "payload":
        # the edge returned the script inline (no indirection)
        out.update(payload=body, bytes=len(body),
                   payload_kind=common.classify_payload(body))
        return out
    else:
        out["message"] = "unexpected delivery answer (status %s)" % status
        return out

    out["final_url"] = final_url
    fstatus, _, fbody = common.http(final_url, timeout=timeout, follow=True)
    if fstatus != 200 or not fbody:
        out["message"] = "CDN fetch failed (%s, %d bytes)" % (fstatus, len(fbody))
        return out
    out.update(payload=fbody, bytes=len(fbody),
               payload_kind=common.classify_payload(fbody))
    return out


# ---------------------------------------------------------------------------
# orchestration (CLI entry)
# ---------------------------------------------------------------------------
def run_fetch(args):
    """Resolve the source, pick a script id, run delivery, and save artifacts.

    Returns a report dict. Prints a short progress narrative."""
    outdir = args.output
    os.makedirs(outdir, exist_ok=True)
    key = args.key or os.environ.get("JNKIE_SCRIPT_KEY")

    report = {}
    info = None
    # -- resolve the script id ------------------------------------------------
    if args.script_id and not args.loader_url and not args.loader and not args.slug:
        script_id, how = args.script_id, "explicit"
        print("[1] script id (explicit): %s" % script_id)
    else:
        ref = args.loader_url or args.loader or args.slug or args.script_id
        print("[1] resolving loader: %s" % ref)
        text, meta = resolve_loader(ref)
        info = parse_loader(text)
        if not info["is_jnkie"]:
            print("    [!] this does not look like a JNKIE loader")
        print("    variant: %s | scripts: %d | source: %s"
              % (info["variant"], len(info["script_ids"]), meta["source"]))
        if info["variant"] == "game-loader":
            print("    place entries: %d | game entries: %d"
                  % (len(info["place_map"]), len(info["game_map"])))
        report["loader"] = {k: v for k, v in info.items()
                            if k not in ("place_map", "game_map")}
        report["loader"]["place_entries"] = len(info["place_map"])
        report["loader"]["game_entries"] = len(info["game_map"])
        if args.script_id:
            script_id, how = args.script_id, "explicit"
        else:
            script_id, how = select_script_id(
                info, index=args.index, place_id=args.place_id, game_id=args.game_id)
        print("    selected script id (%s): %s" % (how, script_id))

    report["script_id"] = script_id
    report["selected_by"] = how

    # -- deliver --------------------------------------------------------------
    hwid = getattr(args, "hwid", None) or os.environ.get("JNKIE_HWID")
    if not key:
        print("[2] no script key (--key / JNKIE_SCRIPT_KEY): the delivery edge "
              "will return LDR-DENIED by design")
    else:
        print("[2] running the delivery handshake ...")
    res = deliver(script_id, key or "", hwid=hwid)
    report["delivery"] = {k: v for k, v in res.items() if k != "payload"}

    if res["denied"]:
        print("    [!] DENIED %s -- %s" % (res["code"], res["message"]))
        if res["code"].endswith("HWID_REQUIRED") or res["code"].endswith("HWID_MISMATCH"):
            print("        the key is HWID-locked: pass the machine's registered "
                  "fingerprint with --hwid (or JNKIE_HWID)")
        return report
    if not res["payload"]:
        print("    [!] no payload recovered: %s" % (res.get("message") or res["kind"]))
        return report

    # -- save -----------------------------------------------------------------
    tag = script_id[:16]
    ext = "luauc" if res["payload_kind"] == "luau-bc" else "lua"
    path = os.path.join(outdir, "payload_%s.%s" % (tag, ext))
    with open(path, "w", encoding="latin-1") as f:
        f.write(res["payload"])
    report["payload_path"] = path
    print("    [+] delivered %d bytes (%s) via %s"
          % (res["bytes"], res["payload_kind"], res["kind"]))
    if res["final_url"]:
        print("        CDN: %s" % res["final_url"])
    print("    [+] saved -> %s" % path)

    with open(os.path.join(outdir, "fetch_%s.json" % tag), "w") as f:
        json.dump(report, f, indent=2)
    print("[+] artifacts in %s" % outdir)
    return report


def run_resolve(args):
    """Resolve + parse a loader and return its metadata (no key, no delivery).

    Prints a human narrative unless ``--json`` is set (then the caller emits the
    machine-readable report and this stays quiet, so stdout parses cleanly)."""
    quiet = getattr(args, "json", False)
    ref = args.loader_url or args.loader or args.slug or args.script_id
    if not quiet:
        print("[1] resolving loader: %s" % ref)
    text, meta = resolve_loader(ref)
    info = parse_loader(text)
    if not quiet:
        print("    source : %s" % meta["source"])
        print("    jnkie  : %s" % info["is_jnkie"])
        print("    variant: %s" % info["variant"])
        print("    host   : %s" % (info["delivery_host"] or "-"))
        print("    reqfns : %s" % (", ".join(info["request_fns"]) or "-"))
        print("    getgenv key: %s" % info["uses_getgenv_key"])
        print("    scripts: %d" % len(info["script_ids"]))
        for n, sid in enumerate(info["script_ids"][:20], 1):
            print("      [%2d] %s" % (n, sid))
        if len(info["script_ids"]) > 20:
            print("      ... (%d more)" % (len(info["script_ids"]) - 20))
        if info["variant"] == "game-loader":
            print("    place map: %d entries | game map: %d entries"
                  % (len(info["place_map"]), len(info["game_map"])))
    report = {k: v for k, v in info.items()}
    report["source"] = meta["source"]
    return report
