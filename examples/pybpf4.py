import time

from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.helpers import pid
from pythonbpf.maps import HashMap
from pylibbpf import BpfMap

from ctypes import c_void_p, c_int64, c_uint64, c_int32
import matplotlib.pyplot as plt

# This program attaches an eBPF tracepoint to sys_enter_clone,
# counts per-PID clone syscalls, stores them in a hash map,
# and then plots the distribution as a histogram using matplotlib.
# It provides a quick view of process creation activity over 10 seconds.
# Everything is done with Python only code and with the new pylibbpf library.
# Run `sudo /path/to/python/binary/ pybpf4.py`

@bpf
@map
def hist() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int64:
    process_id = pid()
    one = 1
    prev = hist().lookup(process_id)
    if prev:
        previous_value = prev + 1
        print(f"count: {previous_value} with {process_id}")
        hist().update(process_id, previous_value)
        return c_int64(0)
    else:
        hist().update(process_id, one)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
hist = BpfMap(b, hist)
print("Recording")
time.sleep(10)

counts = list(hist.values())
x = 0
for key in hist.keys():
    if hist[key] > 40:
        x += 1
        print(f"PID {key} called clone() >40 times")

print(f"Total PIDs with clone() >40 times: {x}")
plt.hist(counts, bins=20)
plt.xlabel("Clone calls per PID")
plt.ylabel("Number of processes that called clone() x times in last 10 seconds")
plt.title("x")
plt.show()
