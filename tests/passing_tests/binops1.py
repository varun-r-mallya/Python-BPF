from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def sometag(ctx: c_void_p) -> c_int64:
    b = 1 + 2
    a = 1 + b
    print(f"{a}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
