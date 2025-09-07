from pythonbpf.decorators import bpf, section
from ctypes import c_void_p, c_int32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    return c_int32(0)

LICENSE = "GPL"
