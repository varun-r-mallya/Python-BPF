from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_uint64


@bpf
@map
def last() -> HashMap:
    return HashMap(key_type=c_uint64, value_type=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_sync")
def do_trace(ctx: c_void_p) -> c_int64:
    key = 0
    tsp = last().lookup(key)
    if tsp:
        delta = (ktime() - tsp)
        if delta < 1000000000:
            time_ms = (delta // 1000000)
            print(f"sync called within last second, last {time_ms} ms ago")
        last().delete(key)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
