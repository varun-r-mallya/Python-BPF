from pythonbpf.decorators import tracepoint, syscalls
from ctypes import c_void_p, c_int32


@tracepoint(syscalls.sys_clone)
def trace_clone(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    return c_int32(0)


LICENSE = "GPL"
