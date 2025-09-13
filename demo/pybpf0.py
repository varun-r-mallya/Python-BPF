from pythonbpf import bpf, section, bpfglobal, compile

from ctypes import c_void_p, c_int64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: python demo/pybpf0.py
# 3. Run the program with sudo: sudo examples/check.sh run demo/pybpf0.o
# 4. Start up any program and watch the output


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

compile()
