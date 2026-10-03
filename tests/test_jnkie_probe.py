# Tool by @adi.codz (Discord)
"""Pure tests for jnkie_crack.probe (no network)."""
import tempfile
import unittest
from pathlib import Path

from jnkie_crack import probe

ID1 = "a" * 64
ID2 = "b" * 64

GAME_LOADER = (
    'do ("JNKIE Game Loader"):sub(1,1);'
    'local S,P,G={"' + ID1 + '","' + ID2 + '"},{[111]=1},{[222]=2};'
    'local i=P[game.PlaceId]or G[game.GameId];'
    'local k=getgenv().SCRIPT_KEY;local r=syn.request or http_request;'
    'local a,x=q({Url="https://api.jnkie.com/api/v1/luascripts/delivery/"..S[i]..'
    '"?v=2&errors=text",Body=k});'
    'if h then warn("[Hub] Failed to load: bad key") end;'
    'local p=game.CoreGui.ErrorPrompt;p.TitleFrame.ErrorTitle.Text="JNKIE";'
    'LDR-DENIED;loadstring(x.Body)()end'
)

PLAIN = "local Window = Library:CreateWindow('x')\nreturn Window"


def _write(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False, encoding="latin-1")
    f.write(text)
    f.close()
    return f.name


class TestDetect(unittest.TestCase):
    def test_loader_detected(self):
        hits, conf = probe.detect(GAME_LOADER)
        self.assertGreaterEqual(conf, 0.9)
        self.assertIn("spg_bundle_head", hits)
        self.assertIn("brand_jnkie", hits)

    def test_plain_not_detected(self):
        _, conf = probe.detect(PLAIN)
        self.assertLess(conf, 0.9)


class TestAnalyze(unittest.TestCase):
    def test_game_loader_report(self):
        report = probe.analyze(_write(GAME_LOADER))
        self.assertTrue(report["jnkie_loader"])
        self.assertEqual(report["variant"], "game-loader")
        self.assertEqual(report["script_ids"]["count"], 2)
        self.assertEqual(report["delivery_host"], "https://api.jnkie.com")
        self.assertEqual(report["coverage"], {"place_entries": 1, "game_entries": 1})
        kinds = {i["kind"] for i in report["iocs"]}
        self.assertIn("error_title", kinds)
        self.assertIn("message", kinds)

    def test_plain_report(self):
        report = probe.analyze(_write(PLAIN))
        self.assertFalse(report["jnkie_loader"])
        self.assertEqual(report["payload_kind"], "lua")

    def test_split(self):
        path = _write(GAME_LOADER)
        report = probe.analyze(path)
        with tempfile.TemporaryDirectory() as d:
            probe.split_loader(path, d, report)
            import json
            data = json.loads(Path(d, "loader.json").read_text())
            self.assertEqual(data["variant"], "game-loader")
            self.assertEqual(data["script_ids"], [ID1, ID2])


class TestFormat(unittest.TestCase):
    def test_format_runs(self):
        report = probe.analyze(_write(GAME_LOADER))
        out = probe.format_report(report)
        self.assertIn("JNKIE LOADER", out)
        self.assertIn("game-loader", out)


if __name__ == "__main__":
    unittest.main()
