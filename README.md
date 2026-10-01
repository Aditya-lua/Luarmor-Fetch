# Luarmor-Fetch

A standalone fetcher and research toolkit for the **Luarmor v4** bootstrap
chain. It packages the reversed loader protocol (loader stub → sephal init →
sandbox bootstrap → live auth handshake → session response) as a clean CLI,
plus a static analyzer for captured Luarmor whitelist clients.

> Tool by **@adi.codz** (Discord). See [AUTHORS.md](AUTHORS.md).

The full protocol reference is in [docs/LUARMOR_NOTES.md](docs/LUARMOR_NOTES.md).

---

## Scope and authorization

This is a **protocol-research and analysis** tool for Luarmor's *public*
bootstrap chain (the ungated loader stub and the client file format). It does
**not** bypass key auth, forge licenses, or attack Luarmor infrastructure:
the session response is bound to the real `script_key` and a per-process nonce,
so without a key you own, the chain soft-fails by design (see *Known limits*).

Use it only on material you are authorized to analyze (your own scripts/keys,
CTF/research samples). Keep request rates conservative — the live handshake
hits real Luarmor hosts. Never commit keys, HWIDs, cookies, captured responses,
or large payloads; `.gitignore` keeps `work/` and raw artifacts out of git.

## What it does

| Stage | Where | Notes |
|-------|-------|-------|
| 1. Loader stub | `loader.parse_stub` | `_bsdata0` (rotates ~hourly), module id, CDN init URL |
| 2. Sephal init | `loader.parse_init` | `superflow_bytecode` blob + Luraph v15 VM chunk |
| 3. Bootstrap | `fetcher` (sandbox) | runs the real bootstrap, builds the auth request (`a`/`d`/`b`) |
| 4. Handshake | `fetcher` (live) | replays the request; classifies the answer |
| 5. Session | `fetcher` two-phase | in-process NEEDFETCH/resume loop; decrypts in-sandbox |
| 6. Client probe | `probe` | static signatures, loader/payload split, IOC scan |

## Requirements

- **Python 3.8+** (standard library only — no third-party packages).
- For `fetch` / `two-phase`: the **Deobfuscator-Luraph-V15** sandbox (the Luau
  runtime + the envlog harness). It is *discovered*, not vendored (see below).
- `probe` is fully standalone — no sandbox needed.

## The sandbox (discovered dependency)

The `fetch` and `two-phase` pipelines run the bootstrap inside the Luau/envlog
sandbox that lives in the **Deobfuscator-Luraph-V15** repo. This tool finds it
automatically; point it explicitly if needed:

```
--repo /path/to/Deobfuscator-Luraph-V15      # or set LUARMOR_REPO
```

Discovery order: `--repo` → `LUARMOR_REPO` → sibling directories of this repo
and your home (one level deep). A repo qualifies when it has
`core/harness.py` + `runtime/envlog.luau`.

**The luau binary.** The sandbox needs a `luau` that runs on your CPU. The
repo ships a prebuilt `bin/luau`, but a prebuilt binary can be compiled for a
microarchitecture your machine does not implement — it then aborts with
`SIGILL` (illegal instruction). The tool runs a **preflight self-test** and, if
the binary can't execute, tells you exactly that. Supply a working build with:

```
--luau /path/to/luau                          # or set LUARMOR_LUAU
```

A compatible, patched build is produced by `python build_luau.py` in the
sandbox repo (needs git, cmake, a C++ compiler). Stock Luau is missing the
Vector3 members the harness installs, so use that patched build rather than a
distro package.

No Node.js is required — this tool drives the Python harness
(`core/harness.py`) and the Luau VM patcher
(`core/obfuscators/luraph_v15/driver.py`) directly, replacing the parent repo's
`scripts/run_raw.js` / `scripts/patch_primed.js`.

## Usage

```
python main.py <command> [options]
```

Every run prints the attribution banner:
`[adi.codz] Luarmor fetcher -- Tool by @adi.codz (Discord)`

### probe — static client analysis (no sandbox)

```
python main.py probe client.lua
python main.py probe client.lua --json
python main.py probe client.lua --split out/     # loader.lua / payload.lua / opaque.json
```

Exit code `0` = Luarmor client detected, `2` = not a Luarmor client.

### fetch — single sandbox run + live handshake

```
python main.py fetch --loader-url https://api.luarmor.net/files/v4/loaders/<md5>.lua \
                     --init init-<module>-sephal.lua --script-key <KEY>
python main.py fetch --loader saved_loader.lua --init cached_init.lua --skip-live
```

Fetches/parses the loader, obtains the init, runs the bootstrap in the sandbox,
captures the auth request, replays it live, and classifies the answer
(`session-response` / `stale-loader` / `executor-trap`).

### two-phase — same-process driver (in-run live fetch)

```
LRM_SCRIPT_KEY=<KEY> python main.py two-phase \
    --loader-url https://api.luarmor.net/files/v4/loaders/<md5>.lua \
    --init init-<module>-sephal.lua
```

Runs the whole protocol in **one** luau process: build the handshake →
`NEEDFETCH` yield → fetch live → plant the response → resume. Same process =
same per-process nonce, so the response decrypts in-sandbox. Each
`loadstring`'d client chunk the run emits is recovered automatically to
`work/out/recovered_<key>.lua`. On a successful chain with a valid key this is
the decrypted Luarmor client (typically a further Luraph-obfuscated layer).

### Common options

| Option | Meaning |
|--------|---------|
| `--loader-url URL` / `--loader FILE` | loader source (URL preferred; blobs rotate ~hourly) |
| `--init FILE` | cached sephal init (the CDN gate serves the real one only to executors) |
| `--script-key KEY` / `LRM_SCRIPT_KEY` | your script key |
| `--repo DIR` / `LUARMOR_REPO` | sandbox repo location |
| `--luau BIN` / `LUARMOR_LUAU` | luau binary (override an incompatible bundled one) |
| `--output DIR` | artifact directory (default `work/out`, gitignored) |

Exit codes: `0` ok, `1` input/runtime error, `3` sandbox repo not found,
`4` sandbox cannot execute (incompatible luau).

## Tests

```
python -m unittest discover -s tests
```

Pure parsing, escape decoding, response classification, detection signatures,
and the split logic — no sandbox or network required.

## Known limits

- **State848 (the research frontier).** With a real key the chain reaches the
  bootstrap's baked-in fail state. The session verdict is parsed by pure VM
  arithmetic on captured locals (no library calls), so interception can't see
  the plaintext. Lifting the nested protos is the open work — see
  `docs/LUARMOR_NOTES.md` §15 and `progress.md`.
- **Nonce binding.** `b` carries a per-process allocation-derived nonce, so a
  response captured in one process can't be replayed into another. The
  `two-phase` driver exists precisely to keep everything in one process.
- **Loader rotation.** `_bsdata0` blobs rotate ~hourly; a stale loader's
  handshake gets the "outdated" tripwire. Prefer `--loader-url` for a fresh one.
- **CDN gate.** `cdn.luarmor.net/v4_init_sephal.lua` serves the real init only
  to executor clients; pass a cached copy with `--init`.

## Layout

```
luarmor_crack/   common.py  loader.py  fetcher.py  probe.py  __init__.py
tests/           test_loader.py  test_common.py  test_probe.py
docs/            LUARMOR_NOTES.md
work/            runtime artifacts (gitignored)
main.py          CLI
```

## Credits

Tool, protocol reversing and research: **@adi.codz** (Discord).
Sandbox runtime (discovered, not vendored): the Deobfuscator-Luraph-V15 project.

## Support / Donate

<div align="center">
  <img src="assets/donate/donate_header.png" width="520" alt="Buy me a coffee — fund future projects">
</div>

If these tools are useful to you, you can help fund future projects by sending
crypto to the addresses below. Thank you for the support. — **@adi.codz** (Discord)

| Network | Address | Scan |
|---|---|---|
| **Bitcoin** (BTC) | `bc1q3nprh6e0y4fz88ft4uu5dad7xsx629z498dkay` | <img src="assets/donate/btc.png" width="120" alt="Bitcoin QR"> |
| **Ethereum** (ERC-20) | `0x11369a1d18eb442581D1e675dAdD94eBA1c4bE52` | <img src="assets/donate/eth.png" width="120" alt="Ethereum QR"> |
| **BNB Smart Chain** (BEP-20) | `0x11369a1d18eb442581D1e675dAdD94eBA1c4bE52` | <img src="assets/donate/bnb.png" width="120" alt="BNB Smart Chain QR"> |
| **Solana** (SOL) | `AVKBDNT2PzYDJ7njVrjt7MoVZ1tY4DvNSsADdujiGKTC` | <img src="assets/donate/sol.png" width="120" alt="Solana QR"> |
| **Litecoin** (LTC) | `ltc1qu4ahsjff622xqjlqwafhlgmacd5ea477sqpx9z` | <img src="assets/donate/ltc.png" width="120" alt="Litecoin QR"> |

> Send each asset only on its own network. ETH and BNB share one EVM address —
> use it for ERC-20 on Ethereum and BEP-20 on BNB Smart Chain. Assets sent on the
> wrong network may be lost.
