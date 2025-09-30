from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime, deref
from pythonbpf.maps.maps import HashMap

from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


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
    delta = 0
    dddelta = 0
    tsp = last().lookup(key)
    if True:
        delta = ktime()
        ddelta = deref(delta)
        ttsp = deref(deref(tsp))
        dddelta = ddelta - ttsp
        if dddelta < 1000000000:
            print("execve called within last second")
        last().delete(key)
    ts = ktime()
    last().update(key, ts)

    va = 8
    nm = 5 + va
    al = 6 & 3
    print(f"this is a variable {nm}")

    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
