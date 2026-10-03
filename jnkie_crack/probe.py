# Tool by @adi.codz (Discord)
"""Static analyzer for captured JNKIE loaders and delivered payloads.

Classifies a file against the JNKIE loader signatures, reports the variant
(script-key vs game-loader), extracts script ids, the delivery host, place/game
coverage, and IOCs (kick/error strings, denial codes, executor request fns). No
network -- runs purely on the file text. Delivered (post-``loadstring``) bodies
are bucketed too, so you can tell a stub from the thing it loads.
"""
import json
import re
from pathlib import Path

from . import common
from .loader import parse_loader

# --- detection signatures ----------------------------------------------------
SIG_BRAND = re.compile(r"\bJNKIE\b")
SIG_DELIVERY = re.compile(r"luascripts/delivery/[0-9a-f]{64}")
SIG_DENIED = re.compile(r"LDR-DENIED")
SIG_SPG = re.compile(r"local\s+S\s*,\s*P\s*,\s*G\s*=")
SIG_GETGENV = re.compile(r"getgenv\(\)\s*\.\s*SCRIPT_KEY")
SIG_REQFN = re.compile(r"\b(syn\.request|http_request|http\.request)\b")
SIG_LOADSTRING = re.compile(r"\bloadstring\s*\(")

ALL_SIGS = [
    ("brand_jnkie", SIG_BRAND),
    ("delivery_endpoint", SIG_DELIVERY),
    ("denial_protocol", SIG_DENIED),
    ("spg_bundle_head", SIG_SPG),
    ("getgenv_script_key", SIG_GETGENV),
    ("executor_request_fn", SIG_REQFN),
]

# --- IOCs --------------------------------------------------------------------
IOC_KICK = re.compile(r'warn\(\s*"([^"]{8,200})"')
IOC_ERRTITLE = re.compile(r'ErrorTitle\.Text\s*=\s*"([^"]+)"')
IOC_WEBHOOK = re.compile(
    r"https?://[^\s\"']+(?:workers\.dev|discord(?:app)?\.com/api/webhooks|webhook\.site)[^\s\"']*")


def line_of(source, offset):
    return source.count("\n", 0, offset) + 1


def detect(source):
    """Return ``(hits, confidence)``. Any 2 signatures => JNKIE loader."""
    hits = [name for name, rx in ALL_SIGS if rx.search(source)]
    n = len(hits)
    if n >= 4:
        conf = 1.0
    elif n >= 2:
        conf = 0.9
    elif n == 1:
        conf = 0.5
    else:
        conf = 0.0
    return hits, conf


def analyze(path):
    path = Path(path)
    source = path.read_text(encoding="latin-1", errors="replace")
    hits, conf = detect(source)
    report = {
        "file": str(path),
        "bytes": len(source.encode("latin-1", errors="replace")),
        "lines": source.count("\n") + 1,
        "jnkie_loader": conf >= 0.9,
        "confidence": conf,
        "signature_hits": hits,
        "payload_kind": common.classify_payload(source),
    }
    if conf < 0.9:
        return report

    info = parse_loader(source)
    report["variant"] = info["variant"]
    report["delivery_host"] = info["delivery_host"]
    report["uses_getgenv_key"] = info["uses_getgenv_key"]
    report["request_fns"] = info["request_fns"]
    report["script_ids"] = {
        "count": len(info["script_ids"]),
        "ids": info["script_ids"][:40],
    }
    report["coverage"] = {
        "place_entries": len(info["place_map"]),
        "game_entries": len(info["game_map"]),
    }

    iocs = []
    for m in IOC_KICK.finditer(source):
        iocs.append({"kind": "message", "value": m.group(1)[:160]})
    for m in IOC_ERRTITLE.finditer(source):
        iocs.append({"kind": "error_title", "value": m.group(1)[:80]})
    for m in IOC_WEBHOOK.finditer(source):
        host = re.match(r"https?://[^/]+", m.group(0))
        iocs.append({"kind": "webhook_url", "host": host.group(0) if host else m.group(0)})
    # de-dup while preserving order
    seen, uniq = set(), []
    for ioc in iocs:
        key = (ioc["kind"], ioc["value"] if "value" in ioc else ioc["host"])
        if key not in seen:
            seen.add(key)
            uniq.append(ioc)
    report["iocs"] = uniq[:20]
    return report


def split_loader(path, outdir, report):
    """Write a machine-readable breakdown (``loader.json``) alongside the raw
    stub for a detected loader."""
    path, outdir = Path(path), Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    info = parse_loader(path.read_text(encoding="latin-1", errors="replace"))
    (outdir / "loader.json").write_text(json.dumps({
        "variant": info["variant"],
        "delivery_host": info["delivery_host"],
        "script_ids": info["script_ids"],
        "place_map": info["place_map"],
        "game_map": info["game_map"],
        "request_fns": info["request_fns"],
    }, indent=2), encoding="utf-8")
    return outdir


def format_report(report):
    """Human-readable one-screen summary of an analyze() report."""
    lines = []
    verdict = "JNKIE LOADER" if report["jnkie_loader"] else "not a jnkie loader"
    lines.append("verdict: %s (confidence %.2f)" % (verdict, report["confidence"]))
    lines.append("file:    %s  (%d bytes, %d lines)"
                 % (report["file"], report["bytes"], report["lines"]))
    lines.append("payload: %s" % report["payload_kind"])
    lines.append("signs:   %s" % (", ".join(report["signature_hits"]) or "-"))
    if report["jnkie_loader"]:
        lines.append("variant: %s" % report.get("variant"))
        lines.append("host:    %s" % (report.get("delivery_host") or "-"))
        lines.append("reqfns:  %s" % (", ".join(report.get("request_fns", [])) or "-"))
        sids = report.get("script_ids", {})
        lines.append("scripts: %d  (first: %s)"
                     % (sids.get("count", 0),
                        ", ".join(i[:12] + ".." for i in sids.get("ids", [])[:4]) or "-"))
        cov = report.get("coverage", {})
        if cov.get("place_entries") or cov.get("game_entries"):
            lines.append("cover:   %d places, %d games"
                         % (cov["place_entries"], cov["game_entries"]))
        for ioc in report.get("iocs", []):
            if ioc["kind"] == "webhook_url":
                lines.append("ioc:     webhook -> %s/..." % ioc["host"])
            else:
                lines.append("ioc:     %s: %s" % (ioc["kind"], ioc["value"]))
    return "\n".join(lines)
