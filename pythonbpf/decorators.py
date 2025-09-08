def bpf(func):
    """Decorator to mark a function for BPF compilation."""
    func._is_bpf = True
    return func


def bpfglobal(func):
    """Decorator to mark a function as a BPF global variable."""
    func._is_bpfglobal = True
    return func

def map(func):
    """Decorator to mark a function as a BPF map."""
    func._is_map = True
    return func

def section(name: str):
    def wrapper(fn):
        fn._section = name
        return fn
    return wrapper

# from types import SimpleNamespace

# syscalls = SimpleNamespace(
#     sys_enter_execve="syscalls:sys_enter_execve",
#     sys_exit_execve="syscalls:sys_exit_execve",
#     sys_clone="syscalls:sys_clone",
# )


# def tracepoint(name: str):
#     def wrapper(fn):
#         fn._section = f"tracepoint/{name}"
#         fn._section = name
#         return fn
#     return wrapper
