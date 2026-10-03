# Tool by @adi.codz (Discord)
"""Offline tests for jnkie_crack.fetcher.deliver and the HWID handshake.

``common.http`` is monkeypatched so no network is touched: we assert the
delivery POST carries the fingerprint header and that each delivery shape
(denied / url-body / redirect / inline payload) is handled."""
import unittest

from jnkie_crack import common, fetcher

SID = "a" * 64
CDN = "https://cdn.jnkie.com/deadbeef.lua"


class _FakeHTTP:
    """Scriptable stand-in for common.http; records calls, returns queued responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, method="GET", headers=None, body=None, timeout=25, follow=False):
        self.calls.append({"url": url, "method": method, "headers": headers or {},
                           "body": body, "follow": follow})
        return self.responses.pop(0)


class TestNormalizeHwid(unittest.TestCase):
    def test_passthrough(self):
        self.assertEqual(common.normalize_hwid("MYHWID"), "MYHWID")

    def test_derived_is_32_hex(self):
        fp = common.normalize_hwid(None)
        self.assertEqual(len(fp), 32)
        self.assertRegex(fp, r"^[0-9a-f]{32}$")

    def test_derived_is_stable(self):
        self.assertEqual(common.normalize_hwid(None), common.normalize_hwid(None))


class TestDeliverHandshake(unittest.TestCase):
    def setUp(self):
        self._orig = common.http

    def tearDown(self):
        common.http = self._orig

    def _patch(self, responses):
        fake = _FakeHTTP(responses)
        common.http = fake
        return fake

    def test_sends_fingerprint_header(self):
        fake = self._patch([(200, {}, CDN), (200, {}, "local a=1")])
        fetcher.deliver(SID, "KEY", hwid="HW123")
        post = fake.calls[0]
        self.assertEqual(post["method"], "POST")
        self.assertEqual(post["headers"].get(common.HWID_HEADER), "HW123")
        self.assertEqual(post["headers"].get("Content-Type"), "text/plain")
        self.assertEqual(post["body"], "KEY")

    def test_url_body_followed_to_payload(self):
        fake = self._patch([(200, {}, CDN), (200, {}, "print('loaded')")])
        res = fetcher.deliver(SID, "KEY", hwid="HW")
        self.assertFalse(res["denied"])
        self.assertEqual(res["final_url"], CDN)
        self.assertEqual(res["payload"], "print('loaded')")
        self.assertEqual(res["payload_kind"], "lua")
        self.assertEqual(fake.calls[1]["url"], CDN)

    def test_redirect_followed_to_payload(self):
        self._patch([(302, {"Location": CDN}, ""), (200, {}, "return 1")])
        res = fetcher.deliver(SID, "KEY", hwid="HW")
        self.assertEqual(res["final_url"], CDN)
        self.assertEqual(res["payload"], "return 1")

    def test_inline_payload(self):
        self._patch([(200, {}, "local x = 2 return x")])
        res = fetcher.deliver(SID, "KEY", hwid="HW")
        self.assertIsNone(res["final_url"])
        self.assertEqual(res["payload"], "local x = 2 return x")

    def test_denied_hwid_required(self):
        self._patch([(403, {}, "LDR-DENIED:HWID_REQUIRED\nneed hwid")])
        res = fetcher.deliver(SID, "KEY")
        self.assertTrue(res["denied"])
        self.assertEqual(res["code"], "LDR-DENIED:HWID_REQUIRED")
        self.assertIsNone(res["payload"])

    def test_bad_script_id(self):
        with self.assertRaises(ValueError):
            fetcher.deliver("not-hex", "KEY")


if __name__ == "__main__":
    unittest.main()
