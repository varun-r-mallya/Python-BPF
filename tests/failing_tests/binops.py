from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    a = 1 + 2 + 1
    print(f"{a}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
