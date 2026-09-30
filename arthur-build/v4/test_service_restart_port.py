"""Execute the ported restart control flow with synthetic Lua service calls."""

import ctypes
import ctypes.util
import shutil
import subprocess
import unittest

from prepare_current_singbox_ui import port_restart_services


LEGACY = '''local function restart_services()
    sys.call("/etc/init.d/sing-box-setup stop >/dev/null 2>&1")
    sys.call("/etc/init.d/sing-box stop >/dev/null 2>&1")
    sys.call("sleep 1")
    if sys.call("/etc/init.d/sing-box start")==0 then return true end
    return nil,"start failed"
end
'''


class RestartControlFlowTests(unittest.TestCase):
    def execute(self, scenario, expected_count, expected_success):
        code = '''
local calls={}
sys={call=function(command)
    calls[#calls+1]=command
    if command:find("sing-box-setup stop",1,true) then
        return SCENARIO=="setup_stop_failure" and 1 or 0
    elseif command:find("sing-box stop",1,true) then
        return SCENARIO=="core_stop_failure" and 1 or 0
    elseif command:find("pidof sing-box",1,true) then
        return SCENARIO=="old_process_running" and 0 or 1
    end
    return 0
end}
'''.replace("SCENARIO", '"' + scenario + '"') + port_restart_services(LEGACY)
        code += '''
local ok,reason=restart_services()
assert(#calls==COUNT, "unexpected service command count")
assert((ok==true)==SUCCESS, "unexpected restart result")
if not ok then
    assert(type(reason)=="string")
    for _,command in ipairs(calls) do
        assert(not command:find("sing-box start",1,true), "core started after failed stop")
    end
end
'''.replace("COUNT", str(expected_count)).replace("SUCCESS", str(expected_success).lower())
        executable = shutil.which("lua5.1")
        if executable:
            result = subprocess.run([executable, "-"], input=code, text=True,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return
        library = ctypes.util.find_library("lua5.4")
        if not library:
            self.skipTest("host Lua 5.1 executable or Lua 5.4 library required")
        lua = ctypes.CDLL(library)
        lua.luaL_newstate.restype = ctypes.c_void_p
        lua.luaL_openlibs.argtypes = [ctypes.c_void_p]
        lua.luaL_loadstring.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lua.lua_pcallk.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_ssize_t, ctypes.c_void_p]
        lua.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        lua.lua_tolstring.restype = ctypes.c_char_p
        lua.lua_close.argtypes = [ctypes.c_void_p]
        state = lua.luaL_newstate()
        try:
            lua.luaL_openlibs(state)
            result = lua.luaL_loadstring(state, code.encode())
            if result == 0:
                result = lua.lua_pcallk(state, 0, 0, 0, 0, None)
            error = lua.lua_tolstring(state, -1, None) if result else None
            self.assertEqual(result, 0, error.decode() if error else "")
        finally:
            lua.lua_close(state)

    def test_setup_stop_failure_never_stops_or_starts_core(self):
        self.execute("setup_stop_failure", 1, False)

    def test_core_stop_failure_never_starts_core(self):
        self.execute("core_stop_failure", 2, False)

    def test_remaining_old_process_blocks_second_core_start(self):
        self.execute("old_process_running", 4, False)

    def test_clean_stop_reaches_core_start(self):
        self.execute("success", 5, True)


if __name__ == "__main__":
    unittest.main()
