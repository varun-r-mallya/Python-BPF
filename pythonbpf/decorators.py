from types import SimpleNamespace

syscalls = SimpleNamespace(
    sys_enter_execve="syscalls:sys_enter_execve",
    sys_exit_execve="syscalls:sys_exit_execve",
)


def tracepoint(name: str):
    def wrapper(fn):
        fn._section = f"tracepoint/{name}"
        return fn
    return wrapper
