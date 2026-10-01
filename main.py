#!/usr/bin/env python3
# Tool by @adi.codz (Discord)
"""Luarmor-Fetch -- command-line entry point.

Subcommands:
  fetch       single sandbox run + live auth handshake (classify the answer)
  two-phase   same-process driver: live NEEDFETCH/resume loop, in-process decrypt
  probe       static analysis of a captured Luarmor client (no sandbox needed)

The fetch/two-phase pipelines need the Deobfuscator-Luraph-V15 sandbox (luau +
envlog harness); it is discovered via --repo / LUARMOR_REPO / sibling scan.
`probe` is fully standalone.
"""
import argparse
import sys

from luarmor_crack import ATTRIBUTION, __version__
from luarmor_crack import probe as probe_mod


def _add_source_args(p):
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--loader-url", metavar="URL",
                     help="public v4 loader URL "
                          "(api.luarmor.net/files/v4/loaders/<md5>.lua); preferred, "
                          "since blobs rotate ~hourly")
    src.add_argument("--loader", metavar="FILE", help="a saved loader stub file")
    p.add_argument("--init", metavar="FILE",
                   help="a cached sephal init file (recommended; the CDN gate serves "
                        "the real init only to executor clients)")
    p.add_argument("--script-key", metavar="KEY",
                   help="script_key value (or set LRM_SCRIPT_KEY in the env)")
    p.add_argument("--repo", metavar="DIR",
                   help="path to the Deobfuscator-Luraph-V15 sandbox repo "
                        "(else LUARMOR_REPO / auto-discovery)")
    p.add_argument("--luau", metavar="BIN",
                   help="path to a luau binary to run (else LUARMOR_LUAU / the repo's "
                        "bin/luau / PATH); use this if the bundled binary is built for "
                        "an incompatible CPU")
    p.add_argument("--output", metavar="DIR", default="work/out",
                   help="output directory for artifacts (default: work/out)")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="luarmor-fetch", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="luarmor-fetch " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="single sandbox run + live handshake",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_source_args(f)
    f.add_argument("--skip-live", action="store_true",
                   help="build the handshake but do not replay it live")

    t = sub.add_parser("two-phase", help="same-process driver with in-run live fetch",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_source_args(t)

    pr = sub.add_parser("probe", help="static Luarmor client analysis (no sandbox)")
    pr.add_argument("file", help="a captured Lua/Luau client file")
    pr.add_argument("--json", action="store_true", help="machine-readable output")
    pr.add_argument("--split", metavar="OUTDIR", default=None,
                    help="write loader.lua / payload.lua / opaque.json")
    return ap


def cmd_probe(args):
    import json
    import os
    if not os.path.isfile(args.file):
        print("error: no such file: %s" % args.file, file=sys.stderr)
        return 1
    report = probe_mod.analyze(args.file)
    if args.split and report.get("luarmor_client"):
        probe_mod.split_payload(args.file, args.split, report)
        report["split_dir"] = args.split
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(probe_mod.format_report(report))
        if args.split and report.get("luarmor_client"):
            print("split:   -> %s (loader.lua / payload.lua / opaque.json)" % args.split)
    return 0 if report.get("luarmor_client") else 2


def main(argv=None):
    print(ATTRIBUTION)
    args = build_parser().parse_args(argv)
    if args.cmd == "probe":
        return cmd_probe(args)

    # fetch / two-phase: import the sandbox-backed pipelines lazily so `probe`
    # and `--help` never require the sandbox repo to be present.
    from luarmor_crack import fetcher
    try:
        if args.cmd == "fetch":
            fetcher.run_simple_pipeline(args)
        elif args.cmd == "two-phase":
            fetcher.run_two_phase(args)
    except fetcher.common.SandboxNotFound as e:
        print("\n[!] %s" % e, file=sys.stderr)
        return 3
    except fetcher.common.SandboxError as e:
        print("\n[!] %s" % e, file=sys.stderr)
        return 4
    except (RuntimeError, ValueError) as e:
        print("\n[!] %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
