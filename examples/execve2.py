from pythonbpf.decorators import bpf, map, section, bpfglobal
from ctypes import c_void_p, c_int64, c_int32, c_uint64
from pythonbpf.helpers import bpf_ktime_get_ns
from pythonbpf.maps import HashMap


@bpf
@map
def last() -> HashMap:
    return HashMap(key_type=c_uint64, value_type=c_uint64, max_entries=1)


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
    key = 0
    tsp = last().lookup(key)
    print(tsp)
    ts = bpf_ktime_get_ns()
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
