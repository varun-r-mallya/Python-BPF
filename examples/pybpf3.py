from pythonbpf import *
from pylibbpf import *
import sys
from ctypes import c_void_p, c_int64, c_uint64

@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def do_trace(ctx: c_void_p) -> c_int64:
    key = 0
    tsp = last().lookup(key)
    if tsp:
        kt = ktime()
        delta = (kt - tsp)
        if delta < 1000000000:
            time_ms = (delta // 1000000)
            print(f"Clone syscall entered within last second, last {time_ms} ms ago")
        last().delete(key)
    else:
        kt = ktime()
        last().update(key, kt)
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
# autoattaches tracepoints
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
