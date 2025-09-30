from pythonbpf import bpf, map, bpfglobal, BPF, section
from pythonbpf.maps import HashMap
from pylibbpf import BpfMap
from ctypes import c_int32, c_uint64, c_void_p


# Define a map
@bpf
@map
def mymap() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=16)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def testing(ctx: c_void_p) -> c_int32:
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Load program (no sections -> nothing attached, just map exists)
b = BPF()
b.load_and_attach()

# Access the map
bpymap = BpfMap(b, mymap)

# Insert values
bpymap.update(1, 100)
bpymap.update(2, 200)

# Read values
print("Key 1 =", bpymap.lookup(1))
print("Key 2 =", bpymap.lookup(2))

# Update again
bpymap.update(1, bpymap.lookup(1) + 50)
print("Key 1 updated =", bpymap.lookup(1))

# Iterate through keys
for k in bpymap.keys():
    print("Key:", k, "Value:", bpymap[k])
