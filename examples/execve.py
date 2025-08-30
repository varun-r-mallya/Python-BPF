from pythonbpf import decorators 

@decorators.tracepoint("syscalls:sys_enter_execve")
def trace_execve(ctx) -> int:
    decorators.trace_printk("execve called\n")
    return 0

@decorators.license("GPL")
def _():
    pass
