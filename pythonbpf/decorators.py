def tracepoint(name: str):
    def wrapper(fn):
        fn._section = f"tracepoint/{name}"
        return fn
    return wrapper

def license(name: str):
    def wrapper(fn):
        fn._license = name
        return fn
    return wrapper

def trace_printk(msg: str):
    # placeholder — real version lowers to IR later
    print(f"[trace_printk] {msg}")
