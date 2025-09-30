import ctypes

def ktime():
    return ctypes.c_int64(0)

def pid():
    return ctypes.c_int32(0)

def deref(ptr):
    "dereference a pointer"
    result = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value
    return result if result is not None else 0

XDP_DROP = ctypes.c_int64(1)
XDP_PASS = ctypes.c_int64(2)
