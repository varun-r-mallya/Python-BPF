from pythonbpf.decorators import bpf, section
from ctypes import c_void_p, c_int64, c_int32
from pythonbpf.helpers import bpf_ktime_get_ns

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    print("entered")
    print("multi constant support")
    return c_int32(0)

@bpf
@section("tracepoint/syscalls/sys_exit_execve")
def hello_again(ctx: c_void_p) -> c_int64:
    print("exited")
    ts = bpf_ktime_get_ns()
    return c_int64(0)

LICENSE = "GPL"
