# Tool by @adi.codz (Discord)
"""Pure tests for jnkie_crack.common (no network)."""
import unittest

from jnkie_crack import common


class TestReferenceResolution(unittest.TestCase):
    def test_bare_script_id(self):
        sid = "a" * 64
        self.assertEqual(common.resolve_reference(sid), ("script-id", sid))

    def test_mixed_hex_is_lowered(self):
        self.assertEqual(common.resolve_reference("A" * 64), ("script-id", "a" * 64))

    def test_full_url(self):
        u = "https://jnkie.com/loaders/ivory"
        self.assertEqual(common.resolve_reference(u), ("url", u))

    def test_slug_from_site_path(self):
        self.assertEqual(common.resolve_reference("jnkie.com/loaders/ivory"),
                         ("slug", "ivory"))

    def test_bare_slug(self):
        self.assertEqual(common.resolve_reference("ivory"), ("slug", "ivory"))

    def test_delivery_url_template(self):
        sid = "b" * 64
        self.assertEqual(common.delivery_url(sid),
                         common.API_HOST + "/api/v1/luascripts/delivery/%s?v=2&errors=text" % sid)


class TestClassifyDelivery(unittest.TestCase):
    def test_denied(self):
        self.assertEqual(
            common.classify_delivery(403, {}, "LDR-DENIED:KEY_INVALID\nnope"), "denied")

    def test_url_body(self):
        self.assertEqual(
            common.classify_delivery(200, {}, "https://cdn.jnkie.com/x.lua"), "url-body")

    def test_redirect(self):
        self.assertEqual(
            common.classify_delivery(302, {"Location": "https://cdn.jnkie.com/x.lua"}, ""),
            "redirect")

    def test_inline_payload(self):
        self.assertEqual(
            common.classify_delivery(200, {}, "local a=1 return a"), "payload")

    def test_error(self):
        self.assertEqual(common.classify_delivery(500, {}, ""), "error")


class TestDenialParsing(unittest.TestCase):
    def test_code_and_message(self):
        code, msg = common.parse_denial("LDR-DENIED:KEY_INVALID\nBad key, try again")
        self.assertEqual(code, "LDR-DENIED:KEY_INVALID")
        self.assertEqual(msg, "Bad key, try again")

    def test_bare_code(self):
        code, msg = common.parse_denial("LDR-DENIED")
        self.assertEqual(code, "LDR-DENIED")
        self.assertEqual(msg, "LDR-DENIED")


class TestClassifyPayload(unittest.TestCase):
    def test_lua(self):
        self.assertEqual(common.classify_payload("local a = 1\nreturn a"), "lua")

    def test_url(self):
        self.assertEqual(common.classify_payload("https://cdn.jnkie.com/x.lua"), "url")

    def test_bytecode(self):
        self.assertEqual(common.classify_payload("\x1bLua..."), "luau-bc")

    def test_denied(self):
        self.assertEqual(common.classify_payload("LDR-DENIED:KEY_INVALID\nx"), "denied")

    def test_html(self):
        self.assertEqual(common.classify_payload("<!doctype html><html></html>"), "html")

    def test_empty(self):
        self.assertEqual(common.classify_payload(""), "empty")


class TestHeaderGet(unittest.TestCase):
    def test_case_insensitive(self):
        h = {"Content-Type": "text/plain", "location": "https://x"}
        self.assertEqual(common.header_get(h, "LOCATION"), "https://x")
        self.assertEqual(common.header_get(h, "content-type"), "text/plain")
        self.assertIsNone(common.header_get(h, "missing"))


if __name__ == "__main__":
    unittest.main()
