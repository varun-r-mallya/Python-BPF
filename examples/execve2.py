from pythonbpf.decorators import bpf, section
from ctypes import c_void_p, c_int64, c_int32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    print("entered")
    return c_int32(0)

@bpf
@section("tracepoint/syscalls/sys_exit_execve")
def hello_again(ctx: c_void_p) -> c_int64:
    print("exited")
    return c_int64(0)

LICENSE = "GPL"
