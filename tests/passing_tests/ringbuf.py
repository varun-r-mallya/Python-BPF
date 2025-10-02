from pythonbpf import bpf, map, bpfglobal, section, compile, compile_to_ir, BPF
from pythonbpf.maps import RingBuf
from ctypes import c_int32, c_void_p


# Define a map
@bpf
@map
def mymap() -> RingBuf:
    return RingBuf(max_entries=(1024))

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def random_section(ctx: c_void_p) -> c_int32:
    print("Hello")
    e = mymap().reserve(6)
    if e:
        mymap().submit(e)
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("ringbuf.py", "ringbuf.ll")
compile()
b = BPF()
b.load_and_attach()
while True:
    print("running")