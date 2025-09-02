from pythonbpf.decorators import tracepoint, syscalls
from ctypes import c_void_p, c_int32


@tracepoint(syscalls.sys_enter_execve)
def trace_execve(ctx: c_void_p) -> c_int32:
    print("execve called")
    return c_int32(0)


LICENSE = "GPL"
