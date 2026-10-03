# JNKIE protocol notes

Research notes for the **JNKIE** Roblox script-whitelist / delivery service, as
packaged by the `jnkie_crack` tool. Companion to `LUARMOR_NOTES.md`.

> Tool and reversing: **@adi.codz** (Discord).

---

## 0. TL;DR — how JNKIE differs from Luarmor v4

Luarmor v4 hides its auth inside a Luraph-v15 VM: you must run the bootstrap in
a Luau sandbox to build the signed `a`/`d`/`b` request, and the session response
is bound to a per-process nonce. JNKIE does **none of that**. Its loader is
plain, readable Lua, and the delivery handshake is a single HTTP POST whose only
secret is the **plaintext `script_key`**. There is no VM to run, no signature to
forge, and no nonce — so `jnkie_crack` needs no sandbox and no sibling repo. If
you hold a valid key, reproducing the exact executor request recovers the
delivered script directly.

## 1. Endpoints

| Purpose | Method | URL |
|---|---|---|
| Site loader (slug) | GET | `https://jnkie.com/loaders/<slug>` → 302 |
| Game-loader download | GET | `https://api.jnkie.com/api/v1/loaders/public/<slug>/download` → 302 → `cdn.jnkie.com/<hash>.lua` |
| Script-key loader download | GET | `https://api.jnkie.com/api/v1/luascripts/public/<script_id>/download` → 302 → `cdn.jnkie.com/<hash>.lua` |
| **Delivery** | **POST** | `https://api.jnkie.com/api/v1/luascripts/delivery/<script_id>?v=2&errors=text` |

`<script_id>` is a 64-hex string. The CDN loader hash in the 302 is unrelated to
the script id (it rotates independently).

## 2. The two loader variants

Both are unobfuscated Lua that run under a Roblox executor. The first line pokes
a watermark string (`("JNKIE Loader …"):sub(1,1)`) — a no-op tamper banner.

### 2a. Script-key loader (`luascripts/public/<id>/download`)

~2.5 KB bound to **one** script id. It:

1. reads `k = getgenv().SCRIPT_KEY or SCRIPT_KEY`;
2. picks an executor HTTP fn: `syn.request` / `request` / `http_request` /
   `http.request`;
3. **POSTs** `k` (header `Content-Type: text/plain`) to the delivery endpoint;
4. on `400/401/403` whose body is `LDR-DENIED[:CODE]` → shows the message and
   kicks;
5. on `200` whose body starts with `https://` → **GET**s that CDN url;
   on `302/303` with a `Location` → **GET**s that;
6. `loadstring(body)()` the final result.

### 2b. Game-loader (`jnkie.com/loaders/<slug>`)

A bundle for a whole hub/game-family. Its head declares:

```lua
local S,P,G = { "<id1>", "<id2>", … },   -- 76 ids in the `ivory` sample
              { [<placeId>]=i, … },        -- PlaceId  -> 1-based index
              { [<gameId>]=i, … }          -- GameId   -> 1-based index
local i = P[game.PlaceId] or G[game.GameId]
```

It then runs the **same** delivery handshake on `S[i]`. So the game you are in
selects which protected script you get. `jnkie_crack` reproduces this selection
with `--place-id` / `--game-id` / `--index`.

## 3. The delivery answer

POST body = the key, nothing else. Observed answers:

| Status | Body | Meaning |
|---|---|---|
| `403` | `LDR-DENIED:KEY_INVALID\n<message>` | key rejected (also used for an empty key, with a "No key provided" message) |
| `200` | `https://cdn.jnkie.com/<hash>.lua` | url-body indirection → GET it for the script |
| `302/303` | (empty) + `Location:` | redirect indirection → GET the `Location` |
| `200` | Lua/bytecode | the script inline (no indirection) |

`?errors=text` requests the plaintext `LDR-DENIED` shape (the loader matches it
exactly). The denial code is `LDR-DENIED` or `LDR-DENIED:<UPPER_SNAKE>`; the
second line is a human message (≤512 chars, else the loader substitutes its own).

## 4. What the tool does

```
reference ──resolve──► loader stub ──parse──► {variant, script_ids, place/game maps}
                                                        │
                        (script id, chosen)◄────────────┘
                                │
                           deliver(id, key)
                                │  POST key → classify
                     ┌──────────┼───────────────┐
                  denied     url-body/redirect   payload
                             │  GET cdn          │
                             └──────────────► save payload_<id>.lua
```

- `common` — the executor-UA HTTP client (redirects off by default so `Location`
  is inspectable, `follow=True` to walk the public→CDN chain), reference
  resolution, delivery/payload classification, denial parsing.
- `loader` — pure parsing of both variants (brace-balanced `S,P,G` extraction).
- `fetcher` — `resolve_loader`, the `deliver` handshake, CLI orchestration.
- `probe` — static detection/IOC extraction on a captured loader or payload.

## 5. Delivered payload

The thing `loadstring` runs is a further JNKIE-obfuscated layer (its own VM /
constant encryption), analogous to the Luraph layer under a recovered Luarmor
client. `jnkie_crack` saves it verbatim (`payload_<id16>.lua`, or `.luauc` when
it is compiled Luau bytecode); peeling that layer is a separate devirtualization
stage, not part of the delivery fetch.

## 6. Scope / limits

- **Key-gated by design.** Without a valid `script_key` the delivery edge
  returns `LDR-DENIED`; the tool reports it and stops. It does not brute-force,
  forge, or bypass key auth — it reproduces the *authorized* executor request.
- **Loader/CDN rotation.** The CDN loader hash in the 302 rotates; always
  resolve fresh from the slug / public edge rather than a saved hash url.
- **No HWID/nonce.** Unlike Luarmor there is no per-process binding, so a
  recovered payload url is only gated by the key check at delivery time.
