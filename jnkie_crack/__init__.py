# Tool by @adi.codz (Discord)
"""jnkie-fetch -- standalone JNKIE loader fetcher and research toolkit.

JNKIE is a Roblox script-whitelist/delivery service (like Luarmor). Unlike the
Luarmor v4 chain, its loader is an *unobfuscated* stub whose only secret is the
delivery handshake: POST your ``script_key`` (plaintext) to the delivery edge,
follow the returned CDN url, and the final ``loadstring``'d body comes back. No
VM sandbox is required -- the whole protocol is plain HTTP -- so this package is
fully standalone (no sibling-repo dependency, standard library only).

Modules mirror the Luarmor-Fetch layout:
  common   HTTP client, reference resolution, response classification
  loader   pure parsing of both loader variants (script-key / game-loader)
  fetcher  live loader resolution + the delivery handshake
  probe    static analysis of a captured loader or delivered payload
"""

__version__ = "1.0.0"
__author__ = "@adi.codz (Discord)"

ATTRIBUTION = "[adi.codz] JNKIE fetcher -- Tool by @adi.codz (Discord)"
