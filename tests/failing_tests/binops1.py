from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    b = 1 + 2
    a = 1 + b
    return c_int64(a)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
