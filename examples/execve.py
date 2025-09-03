from pythonbpf.decorators import tracepoint, syscalls
from ctypes import c_void_p, c_int32

#This is a test function
def test_function():
    print("test_function called")

@tracepoint(syscalls.sys_enter_execve)
def trace_execve(ctx: c_void_p) -> c_int32:
    print("execve called")
    print("execve2 called")
    test_function()
    return c_int32(0)


LICENSE = "GPL"
