def tracepoint(name: str):
    def wrapper(fn):
        fn._section = f"tracepoint/{name}"
        return fn
    return wrapper

def license(license_type: str):
    return license_type
