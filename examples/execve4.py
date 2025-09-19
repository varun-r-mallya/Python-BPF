from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime, deref
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("blk_start_request")
def trace_start(ctx: c_void_p) -> c_int32:
    ts = ktime()
    print("req started")
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
