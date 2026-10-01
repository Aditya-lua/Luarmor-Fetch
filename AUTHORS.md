# Authors

## Tool author

**@adi.codz** (Discord) — author and maintainer of the Luarmor-Fetch tool:
protocol reversing, the end-to-end fetch pipeline, the two-phase same-process
driver, the static client probe, and the Luarmor protocol notes.

All source files in this repository carry the header:

```
# Tool by @adi.codz (Discord)
```

and the CLI prints its attribution on startup:

```
[adi.codz] Luarmor fetcher -- Tool by @adi.codz (Discord)
```

## Discovered dependency

The sandbox runtime (the `luau` binary, `core/harness.py` and
`runtime/envlog.luau`) lives in the **Deobfuscator-Luraph-V15** project and is
discovered at runtime, not vendored here. See the README's *Sandbox* section
for how the discovery works and how to point the tool at that repo.
