from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_uint64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: python demo/pybpf2.py
# 3. Run the program with sudo: sudo examples/check.sh run demo/pybpf2.o
# 4. Start a Python repl and `import os` and then keep entering `os.sync()` to see reponses.

@bpf
@map
def last() -> HashMap:
    return HashMap(key_type=c_uint64, value_type=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def do_trace(ctx: c_void_p) -> c_int64:
    key = 0
    tsp = last().lookup(key)
    if tsp:
        kt = ktime()
        delta = (kt - tsp)
        if delta < 1000000000:
            time_ms = (delta // 1000000)
            print(f"sync called within last second, last {time_ms} ms ago")
        last().delete(key)
    else:
        kt = ktime()
        last().update(key, kt)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
