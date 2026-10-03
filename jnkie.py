#!/usr/bin/env python3
# Tool by @adi.codz (Discord)
"""jnkie-fetch -- command-line entry point.

Subcommands:
  fetch     resolve a loader (or take a script id) + run the delivery handshake
            with your key, and recover the final loadstring'd payload
  resolve   resolve + parse a loader to its metadata (no key, no delivery)
  probe     static analysis of a captured loader or delivered payload (no network)

JNKIE's loader is unobfuscated and its only secret is the delivery handshake, so
no sandbox is needed: this tool is fully standalone (standard library only).
Without a valid key the chain returns LDR-DENIED by design.
"""
import argparse
import sys

from jnkie_crack import ATTRIBUTION, __version__
from jnkie_crack import probe as probe_mod


def _add_source_args(p, require=True):
    src = p.add_mutually_exclusive_group(required=require)
    src.add_argument("--slug", metavar="NAME",
                     help="a game-loader slug (jnkie.com/loaders/<slug>)")
    src.add_argument("--loader-url", metavar="URL",
                     help="a full loader url (site/public edge or cdn .lua)")
    src.add_argument("--loader", metavar="FILE", help="a saved loader stub file")
    src.add_argument("--script-id", metavar="ID",
                     help="a 64-hex script id (skip loader resolution; go straight "
                          "to delivery)")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="jnkie-fetch", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="jnkie-fetch " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="delivery handshake + recover payload",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    # for fetch, a bare --script-id is a valid standalone source, so not required
    # as a group only if a script id is given; keep the group optional and check.
    _add_source_args(f, require=False)
    f.add_argument("--key", metavar="KEY",
                   help="script key (or set JNKIE_SCRIPT_KEY in the env)")
    f.add_argument("--index", type=int, metavar="N",
                   help="1-based script index into a game-loader bundle")
    f.add_argument("--place-id", type=int, metavar="ID",
                   help="pick the game-loader script mapped to this Roblox PlaceId")
    f.add_argument("--game-id", type=int, metavar="ID",
                   help="pick the game-loader script mapped to this Roblox GameId")
    f.add_argument("--output", metavar="DIR", default="work/out",
                   help="artifact directory (default: work/out)")

    r = sub.add_parser("resolve", help="resolve + parse a loader (no key)",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_source_args(r, require=True)
    r.add_argument("--json", action="store_true", help="machine-readable output")

    pr = sub.add_parser("probe", help="static loader/payload analysis (no network)")
    pr.add_argument("file", help="a captured loader or delivered Lua file")
    pr.add_argument("--json", action="store_true", help="machine-readable output")
    pr.add_argument("--split", metavar="OUTDIR", default=None,
                    help="write loader.json (variant / ids / maps) for a loader")
    return ap


def cmd_probe(args):
    import json
    import os
    if not os.path.isfile(args.file):
        print("error: no such file: %s" % args.file, file=sys.stderr)
        return 1
    report = probe_mod.analyze(args.file)
    if args.split and report.get("jnkie_loader"):
        probe_mod.split_loader(args.file, args.split, report)
        report["split_dir"] = args.split
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(probe_mod.format_report(report))
        if args.split and report.get("jnkie_loader"):
            print("split:   -> %s (loader.json)" % args.split)
    return 0 if report.get("jnkie_loader") else 2


def main(argv=None):
    print(ATTRIBUTION)
    args = build_parser().parse_args(argv)
    if args.cmd == "probe":
        return cmd_probe(args)

    from jnkie_crack import fetcher
    try:
        if args.cmd == "fetch":
            if not (args.slug or args.loader_url or args.loader or args.script_id):
                print("error: give a source (--slug / --loader-url / --loader / "
                      "--script-id)", file=sys.stderr)
                return 1
            fetcher.run_fetch(args)
        elif args.cmd == "resolve":
            import json
            report = fetcher.run_resolve(args)
            if args.json:
                print(json.dumps(report, indent=2))
    except fetcher.common.JnkieError as e:
        print("\n[!] %s" % e, file=sys.stderr)
        return 1
    except (ValueError, OSError) as e:
        print("\n[!] %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
