# Tool by @adi.codz (Discord)
"""Pure tests for jnkie_crack.loader parsing (no network)."""
import unittest

from jnkie_crack.loader import parse_loader, select_script_id, _brace_group

ID1 = "a" * 64
ID2 = "b" * 64
ID3 = "c" * 64

SCRIPT_KEY_STUB = (
    'do ("JNKIE Loader"):sub(1,1);'
    'local k=getgenv().SCRIPT_KEY or SCRIPT_KEY;'
    'local r=(type(syn)=="table" and syn.request) or request or http_request '
    'or (type(http)=="table" and http.request);'
    'local a,x=q({Url="https://api.jnkie.com/api/v1/luascripts/delivery/' + ID1 +
    '?v=2&errors=text",Method="POST",Headers={["Content-Type"]="text/plain"},Body=k});'
    'if h=="LDR-DENIED" then end;'
    'local b=x.Body;local f=loadstring(b);f()end'
)

GAME_LOADER_STUB = (
    'do ("JNKIE Game Loader"):sub(1,1);'
    'local S,P,G={"' + ID1 + '","' + ID2 + '","' + ID3 + '"},'
    '{[111]=1,[222]=2},{[333]=3};'
    'local i=P[game.PlaceId]or G[game.GameId];'
    'local k=getgenv().SCRIPT_KEY;'
    'local r=request or http_request;'
    'local a,x=q({Url="https://api.jnkie.com/api/v1/luascripts/delivery/"..S[i]..'
    '"?v=2&errors=text",Method="POST",Body=k});'
    'LDR-DENIED;loadstring(x.Body)()end'
)


class TestBraceGroup(unittest.TestCase):
    def test_simple(self):
        s = "x={1,2,3}y"
        inner, end = _brace_group(s, s.index("{"))
        self.assertEqual(inner, "1,2,3")
        self.assertEqual(s[end], "y")

    def test_string_with_brace(self):
        s = '{"a}b", 2}'
        inner, end = _brace_group(s, 0)
        self.assertEqual(inner, '"a}b", 2')
        self.assertEqual(end, len(s))

    def test_nested(self):
        s = "{[1]={2,3},[2]=4}"
        inner, _ = _brace_group(s, 0)
        self.assertEqual(inner, "[1]={2,3},[2]=4")


class TestScriptKeyLoader(unittest.TestCase):
    def setUp(self):
        self.info = parse_loader(SCRIPT_KEY_STUB)

    def test_detected(self):
        self.assertTrue(self.info["is_jnkie"])
        self.assertEqual(self.info["variant"], "script-key")

    def test_single_id(self):
        self.assertEqual(self.info["script_ids"], [ID1])

    def test_host(self):
        self.assertEqual(self.info["delivery_host"], "https://api.jnkie.com")

    def test_getgenv_and_reqfns(self):
        self.assertTrue(self.info["uses_getgenv_key"])
        self.assertIn("syn.request", self.info["request_fns"])
        self.assertIn("request", self.info["request_fns"])

    def test_select_default(self):
        sid, how = select_script_id(self.info)
        self.assertEqual(sid, ID1)
        self.assertEqual(how, "default")


class TestGameLoader(unittest.TestCase):
    def setUp(self):
        self.info = parse_loader(GAME_LOADER_STUB)

    def test_detected(self):
        self.assertTrue(self.info["is_jnkie"])
        self.assertEqual(self.info["variant"], "game-loader")

    def test_ids_order(self):
        self.assertEqual(self.info["script_ids"], [ID1, ID2, ID3])

    def test_maps(self):
        self.assertEqual(self.info["place_map"], {111: 1, 222: 2})
        self.assertEqual(self.info["game_map"], {333: 3})

    def test_select_by_place(self):
        self.assertEqual(select_script_id(self.info, place_id=222)[0], ID2)

    def test_select_by_game(self):
        self.assertEqual(select_script_id(self.info, game_id=333)[0], ID3)

    def test_select_by_index(self):
        self.assertEqual(select_script_id(self.info, index=1)[0], ID1)

    def test_bad_index(self):
        with self.assertRaises(ValueError):
            select_script_id(self.info, index=99)

    def test_uncovered_place(self):
        with self.assertRaises(ValueError):
            select_script_id(self.info, place_id=999)


class TestNonLoader(unittest.TestCase):
    def test_plain_lua(self):
        info = parse_loader("print('hello world')")
        self.assertFalse(info["is_jnkie"])
        self.assertEqual(info["variant"], "unknown")
        self.assertEqual(info["script_ids"], [])


if __name__ == "__main__":
    unittest.main()
