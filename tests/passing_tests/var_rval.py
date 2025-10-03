import logging

from pythonbpf import compile, bpf, section, bpfglobal, compile_to_ir
from ctypes import c_void_p, c_int64


@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    a = 1 - 1
    return c_int64(a)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

compile_to_ir("var_rval.py", "var_rval.ll")
compile(loglevel=logging.INFO)
