from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime, pid
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int32:
    ts = ktime()
    process_id = pid()
    print(f"clone called at {ts} by pid {process_id}")
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
