import ctypes

def bpf_ktime_get_ns():
    return ctypes.c_int64(0)
