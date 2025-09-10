from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helpers import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@map
def last() -> HashMap:
    return HashMap(key_type=c_uint64, value_type=c_uint64, max_entries=3)


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
#    if tsp:
#        delta = (bpf_ktime_get_ns() - tsp.value)
#        if delta < 1000000000:
#            print("execve called within last second")
#        last().delete(key)
    x = 1
    y = False
    if x > 0:
        if x < 2:
            print(f"we prevailed {x}")
        else:
            print(f"we did not prevail {x}")
    ts = ktime()
    last().update(key, ts)

    st = "st"
    last().update(key, ts)

    keena = 2 + 1
    # below breaks
    # keela = keena + 1
    keema = 8 * 9
    keesa = 10 - 11
    keeda = 10 / 5
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

compile()
