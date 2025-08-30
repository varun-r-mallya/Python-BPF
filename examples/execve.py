from pythonbpf.decorators import tracepoint

@tracepoint("syscalls:sys_enter_execve")
def trace_execve(ctx) -> int:
    print("execve called\n")
    return 0

LICENSE = "GPL"
