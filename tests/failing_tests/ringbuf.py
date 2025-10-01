from pythonbpf import bpf, map, bpfglobal, section
from pythonbpf.maps import RingBuf
from ctypes import c_int32, c_void_p


# Define a map
@bpf
@map
def mymap() -> RingBuf:
    return RingBuf(max_entries=(1 << 24))


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def testing(ctx: c_void_p) -> c_int32:
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
