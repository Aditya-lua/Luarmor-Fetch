# Tool by @adi.codz (Discord)
"""Unit tests for luarmor_crack.loader (pure parsing/building) and the
handshake/time-pin helpers. Adapted from the parent repo's luarmor_fetch_test."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from luarmor_crack import loader as L  # noqa: E402

STUB = """-- Do not save this file
-- Always use the loadstring
  _bsdata0={339253403,"\\164\\109\\57",2167875005,92540919,"783e9b5f",1128507,"72b8b951637a",1790615855,33828300,"\\218\\157\\138",4314001,71740338};
local f,b,a="static_content_170926","f07dbcbe19a-sephal";pcall(function()a=readfile(f.."/init-"..b..".lua")end) if a and #a>2000 then a=loadstring(a) else a=nil; end;
if a then return a() else pcall(makefolder,f) a=game:HttpGet("https://cdn.luarmor.net/v4_init_sephal.lua"..(_ca920af6193 or "")) writefile(f.."/init-"..b..".lua", a); ldrupd8m=a; return loadstring(a)(b) end
   """

INIT = (
    "--[[\n        Luarmor V4 bootstrapper for scripts.\n]]--"
    + 'superflow_bytecode={"\\136\\221\\229\\183"}'
    + "x=1;"
    + "return setmetatable({[80]=unpack,[31]=bit32.bxor},{}):TK()(...);"
)
INIT_NOARG = INIT.replace(":TK()(...);", ":TK();")


class StubTest(unittest.TestCase):
    def test_parse_stub(self):
        s = L.parse_stub(STUB)
        self.assertEqual(s["module_id"], "f07dbcbe19a-sephal")
        self.assertEqual(s["init_url"], "https://cdn.luarmor.net/v4_init_sephal.lua")
        self.assertIn("_bsdata0={339253403", s["bsdata0_line"])

    def test_parse_bsdata0(self):
        bs = L.parse_bsdata0(L.parse_stub(STUB)["bsdata0_line"])
        self.assertEqual(len(bs), 12)
        self.assertEqual(bs[1], 339253403)
        self.assertEqual(bs[2], bytes([164, 109, 57]))
        self.assertEqual(bs[7], b"72b8b951637a")
        self.assertEqual(bs[10], bytes([218, 157, 138]))
        self.assertEqual(bs[12], 71740338)

    def test_parse_stub_rejects_non_luarmor(self):
        with self.assertRaises(ValueError):
            L.parse_stub("print('hello world')")


class InitTest(unittest.TestCase):
    def test_parse_init_shapes(self):
        for text in (INIT, INIT_NOARG):
            ini = L.parse_init(text)
            self.assertEqual(ini["blob"], 'superflow_bytecode={"\\136\\221\\229\\183"}')
            self.assertIn('return setmetatable({[80]=unpack,[31]=bit32.bxor},{})', ini["chunk"])
            self.assertIn(':TK()(__MODULE_ID__);', ini["chunk"])

    def test_build_input(self):
        s = L.parse_stub(STUB)
        ini = L.parse_init(INIT)
        text = L.build_input(s, ini, "f07dbcbe19a-sephal", "KEY123", "INITTEXT")
        lines = text.split("\n")
        self.assertEqual(lines[0], 'script_key="KEY123";')
        self.assertTrue(lines[1].startswith("_bsdata0={339253403"))
        self.assertTrue(lines[2].startswith("superflow_bytecode={"))
        self.assertIn("ldrupd8m=[========[INITTEXT]========];", lines[3])
        self.assertIn(':TK()("f07dbcbe19a-sephal");', lines[4])

    def test_build_input_default_key(self):
        s = L.parse_stub(STUB)
        ini = L.parse_init(INIT)
        text = L.build_input(s, ini, "f07dbcbe19a-sephal", None, "x")
        self.assertTrue(text.startswith('script_key="'))  # placeholder filled


class TimePinTest(unittest.TestCase):
    def test_time_pin_picks_epoch(self):
        import time
        now = int(time.time())
        stub = "_bsdata0={1,%d,2};" % (now - 3600)
        self.assertEqual(L.loader_time_pin(stub), now - 3600)

    def test_time_pin_falls_back_to_now(self):
        import time
        pin = L.loader_time_pin("_bsdata0={1,2,3};")
        self.assertAlmostEqual(pin, int(time.time()), delta=5)


class HandshakeTest(unittest.TestCase):
    def test_extract_handshake(self):
        raw = ('Url = "https://x.luarmor.net/a9b90889ea88d2a9cfaac?a=fa6607'
               '&d=abcd&b=1234"\n--   https://other.example/x\n'
               'Error: State848\nError: State848\nScreenGui\nLocalPlayer:Kick("x")')
        hs = L.extract_handshake(raw)
        self.assertEqual(hs["a"], "fa6607")
        self.assertEqual(hs["d"], "abcd")
        self.assertEqual(hs["b"], "1234")
        self.assertEqual(hs["states"], ["State848"])
        self.assertTrue(hs["gui"])
        self.assertTrue(hs["kicked"])
        self.assertIn("https://other.example/x", hs["urls"])


if __name__ == "__main__":
    unittest.main()
