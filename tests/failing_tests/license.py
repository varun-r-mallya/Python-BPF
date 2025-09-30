from pythonbpf import compile, bpf, section
from ctypes import c_void_p, c_int64


# FAILS WHEN THERE IS NO LICENSE. which is wrong.
@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    a = 1 + 2
    return c_int64(0)


compile()
