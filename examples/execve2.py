from pythonbpf.decorators import bpf, section
# from pythonbpf.decorators import tracepoint, syscalls
from ctypes import c_void_p, c_int32


@bpf
@section("kprobe/sys_clone")
def hello(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    return c_int32(0)


LICENSE = "GPL"
