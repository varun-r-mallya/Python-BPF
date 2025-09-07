# This is what it is going to look like
# pylint: disable-all# type: ignore
from pythonbpf.decorators import tracepoint, syscalls, bpfglobal, bpf
from ctypes import c_void_p, c_int32

@bpf
@tracepoint(syscalls.sys_clone)
def trace_clone(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    return c_int32(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
