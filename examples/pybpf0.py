from pythonbpf import bpf, section, bpfglobal, BPF
import sys
from ctypes import c_void_p, c_int64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. `sudo /path/to/venv/bin/python ./python-bpf/demo/pybpf0.py`

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

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
