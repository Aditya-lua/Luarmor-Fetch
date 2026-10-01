# Progress Log

Chronological research/engineering log for Luarmor-Fetch. Newest entries on top.

---

## 2026-10-01 — Full chain completes: past State848, client recovered

First end-to-end run with a **real script key** (fresh loader, cached sephal
init, compatible locally-built luau). The chain ran to success — **no
State848, no kick**:

```
round 1 NEEDFETCH  ->  session-response (630 B)      handshake accepted
round 2 NEEDFETCH  ->  json (412,648 B)              encrypted client chunk
round 3 NEEDFETCH  ->  json (230,077 B)              encrypted client chunk
loadstring() of 624,009 bytes                        decrypted client
run finished: fetches=3 states=- kicked=False
```

The 624,009-byte `loadstring`'d chunk is the decrypted Luarmor client:
`-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]`.
The tool now recovers it automatically (`fetcher.run_two_phase` scans the run's
`\0<nonce>CHUNK` markers → `work/out/recovered_<key>.lua`).

### Root cause of the previous State848 wall

With the placeholder key the chain always died at State848 *before* a second
request, so the serve handler's second-round path was never exercised. The real
key makes round 1 decrypt, and the loader issues a **second** request (the
client-chunk fetch). That URL isn't planted yet (it's the driver's cue to fetch
it), so it takes the `urls.__lrm_plant` **plant-MISS** branch — which should log
and fall through to `NEEDFETCH`. But the diagnostics in that branch called
`R.math.min`/`R.math.max`, and `R.math` is nil in that handler's scope (the only
`R.math` site in `envlog.luau`, hence latent). The nil-index crash aborted the
run → "Luarmor V4 loader failed to fetch a chunk: ...attempt to index nil with
'min'" → the baked-in Loader-Failed UI (a 281-byte spawner) → Kick.

### The fix (sandbox dependency, not this repo)

`runtime/envlog.luau` plant-MISS diagnostics made math-free (plain comparisons
instead of `R.math.min`/`R.math.max`) so a MISS logs and falls through to the
`NEEDFETCH` yield. With that, round 2/3 fetch cleanly and the client decrypts.

> This edit lives in the **discovered Deobfuscator-Luraph-V15 clone**, not in
> Luarmor-Fetch (the sandbox is not vendored here). It is a one-line-class,
> reversible change and should be upstreamed to that repo separately. Recorded
> here so the result is reproducible.

### Where it stands now

- The outer Luarmor protocol is **fully traversed**: auth → session → client
  chunk fetch → decrypt → load. The recovered payload is a *further* layer
  (Luraph Obfuscator v14.7); peeling that is the parent repo's Luraph
  devirtualizer's job, a separate stage from the Luarmor loader chain.
- Reproduce: `LRM_SCRIPT_KEY=<key> python main.py two-phase --loader-url <fresh>
  --init <cached sephal init> --output work/out` (needs a luau that runs on the
  host and the envlog plant-MISS fix above).

## 2026-10-01 — Extraction into a standalone, Node-free tool

Extracted the working Luarmor tooling out of **Deobfuscator-Luraph-V15**
(`tools/luarmor_fetch.py`, `tools/luarmor_two_phase.py`, `tools/luarmor_probe.py`,
`docs/LUARMOR_NOTES.md`, `test/luarmor_fetch_test.py`) and refactored it into
this standalone repo.

**What changed in the extraction**

- **Node.js removed.** The parent tool shelled out to `scripts/run_raw.js`
  (sandbox run) and `scripts/patch_primed.js` (VM entry/spin patch). Both are
  now driven directly from Python: `core/harness.py` for
  `build_harness`/`run_once`/serve mode, and
  `core/obfuscators/luraph_v15/driver.py` for `patch_entries`/`patch_spin`.
  No `node` process is spawned anywhere.
- **Hardcoded paths removed.** The `/home/z/my-project/...` constants in the
  two-phase driver are gone. The sandbox repo is discovered at runtime
  (`common.find_sandbox_repo`: `--repo` → `LUARMOR_REPO` → sibling scan), and
  the luau binary is resolved separately (`common.resolve_luau`: `--luau` →
  `LUARMOR_LUAU` → `bin/luau` → PATH).
- **Modular package.** `common` (http, classify, Lua escapes, discovery),
  `loader` (pure stub/init parsing + input assembly + handshake extraction),
  `fetcher` (sandbox bootstrap, live handshake, two-phase driver), `probe`
  (static analyzer). A single `main.py` exposes `fetch` / `two-phase` / `probe`.
- **Preflight self-test.** Before any sandbox run the tool executes a trivial
  luau script. If luau can't run (e.g. the prebuilt `bin/luau` was built for an
  incompatible microarchitecture and aborts with `SIGILL`), it raises a clear,
  actionable `SandboxError` instead of surfacing an empty trace downstream.

**Validation done**

- Unit tests: 21/21 pass (`python -m unittest discover -s tests`) covering stub
  parsing, `_bsdata0` decode, init split, input assembly, time-pin derivation,
  handshake extraction, response classification, Lua escapes, discovery, and
  the probe detector/splitter.
- `probe` verified end-to-end on real text (no sandbox needed).
- Sandbox wiring verified: harness + luraph_v15 driver import from the
  discovered repo; `patch_spin` applies; `run_once` builds and launches the
  luau subprocess.
- Environment note: the sandbox repo's prebuilt `bin/luau` aborts with `SIGILL`
  (invalid opcode at a fixed address) on this container's CPU — it runs
  `--help` but faults in the VM dispatch path on any script. The tool detects
  this via preflight; a locally compiled patched luau (`build_luau.py`) is the
  fix. Live `fetch`/`two-phase` runs therefore require a compatible luau build
  on the host.

## Inherited protocol state (from Deobfuscator-Luraph-V15)

The reversing that this tool packages, condensed (full detail in
`docs/LUARMOR_NOTES.md`):

- **Bootstrap mapped.** The public v4 loader stub, the sephal init
  (`superflow_bytecode` blob + Luraph v15 chunk), and the stub-faithful primed
  input are fully understood and reproduced.
- **Handshake accepted live.** With a fresh loader, the sandbox-built `b`
  signature is accepted by `x.luarmor.net` (the earlier "outdated" rejections
  were stale `_bsdata0`, not sandbox detection).
- **Same-process decrypt works.** The two-phase driver gets the real session
  response back into the same process (same nonce) and runs the session decrypt
  in-sandbox — no State848 on the first response, no harness crash.
- **Frontier: State848.** With a real key the run still ends in the baked-in
  fail state. The verdict is parsed by pure VM arithmetic (zero
  string/table/bit32/buffer calls recorded), so library interception can't read
  the plaintext. Open work: lift the nested protos behind
  `luraph_runtime1(...)` (force-decode for metatable-less tables) to read the
  verdict checks and the response cipher statically, or diff real-executor
  fingerprint/`d` bytes against the sandbox's.

## Next steps

1. Live end-to-end run with a compatible luau + the user's loader URL, cached
   init, and script key (validate `fetch` then `two-phase` to the State848
   frontier).
2. Nested-proto lift (the response cipher + verdict logic) — the standing
   research goal carried over from the parent repo.
