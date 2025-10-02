from pythonbpf import bpf, map, struct, section, bpfglobal, compile, compile_to_ir, BPF
from pythonbpf.helper import ktime, pid
from pythonbpf.maps import PerfEventArray
import logging
from ctypes import c_void_p, c_int32, c_uint64


# PLACEHOLDER EXAMPLE. THIS SHOULD TECHNICALLY STILL FAIL TESTS
@bpf
@struct
class data_t:
    pid: c_uint64
    ts: c_uint64
    comm: str(16)


@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_int32, value_size=c_int32)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int32:
    dataobj = data_t()
    ts = ktime()
    strobj = "hellohellohello"
    dataobj.pid = pid()
    dataobj.ts = ktime()
    # dataobj.comm = strobj
    print(
        f"clone called at {dataobj.ts} by pid {dataobj.pid}, comm {strobj} at time {ts}"
    )
    events.output(dataobj)
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("perf_buffer_map.py", "perf_buffer_map.ll")
compile(loglevel=logging.INFO)
b = BPF()
b.load_and_attach()

while True:
    print("running")
