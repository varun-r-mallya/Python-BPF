from pythonbpf.decorators import section
# from pythonbpf.decorators import tracepoint, syscalls
from ctypes import c_void_p, c_int32

# @tracepoint(syscalls.sys_enter_execve)


@section("kprobe/sys_clone")
def hello(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    return c_int32(0)


LICENSE = "GPL"
