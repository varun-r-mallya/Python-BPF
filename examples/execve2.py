from pythonbpf import bpf, map, section, bpfglobal, compile_to_ir, compile, BPF
from ctypes import c_uint32, c_void_p, c_int64, c_int32, c_uint64
from pythonbpf.helpers import ktime
from pythonbpf.maps import HashMap
import sys


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint32, max_entries=69)


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
    print(tsp)
    ts = ktime()
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

compile_to_ir("execve2.py", "execve2.ll")
compile()
b = BPF()
b.load_and_attach()

def main():
    try:
        with open("/sys/kernel/debug/tracing/trace_pipe", "r") as f:
            for line in f:
                sys.stdout.write(line)
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.stderr.write("Need root privileges to read trace_pipe\n")

if __name__ == "__main__":
    main()
