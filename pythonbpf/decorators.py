def tracepoint(name: str):
    def wrapper(fn):
        fn._section = f"tracepoint/{name}"
        return fn
    return wrapper

def license(license_type: str):
    return license_type

def trace_printk(msg: str):
    # placeholder — real version lowers to IR later
    print(f"[trace_printk] {msg}")
