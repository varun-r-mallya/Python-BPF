from pythonbpf.decorators import tracepoint
from ctypes import c_void_p, c_int32

@tracepoint("syscalls:sys_enter_execve")
def trace_execve(ctx: c_void_p) -> c_int32:
    print("execve called\n")
    return c_int32(0)

LICENSE = "GPL"
