def tracepoint(name: str):
    def wrapper(fn):
        fn._section = f"tracepoint/{name}"
        return fn
    return wrapper
