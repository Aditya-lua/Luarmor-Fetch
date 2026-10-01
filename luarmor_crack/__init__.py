# Tool by @adi.codz (Discord)
"""Luarmor-Fetch -- standalone Luarmor v4 loader fetcher and research toolkit.

Packages the reversed Luarmor bootstrap pipeline (loader stub -> sephal init ->
sandbox bootstrap -> live auth handshake -> session response) together with a
static client probe. The sandbox runtime (luau + envlog) is a discovered
dependency from the Deobfuscator-Luraph-V15 project; see ``common.find_sandbox_repo``.
"""

__version__ = "1.0.0"
__author__ = "@adi.codz (Discord)"

ATTRIBUTION = "[adi.codz] Luarmor fetcher -- Tool by @adi.codz (Discord)"
