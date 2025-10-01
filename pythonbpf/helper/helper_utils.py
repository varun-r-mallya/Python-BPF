import ast
from llvmlite import ir


class HelperHandlerRegistry:
    """Registry for BPF helpers"""
    _handlers = {}

    @classmethod
    def register(cls, helper_name):
        """Decorator to register a handler function for a helper"""
        def decorator(func):
            cls._handlers[helper_name] = func
            return func
        return decorator

    @classmethod
    def get_handler(cls, helper_name):
        """Get the handler function for a helper"""
        return cls._handlers.get(helper_name)


def get_var_ptr_from_name(var_name, local_sym_tab):
    """Get a pointer to a variable from the symbol table."""
    if local_sym_tab and var_name in local_sym_tab:
        return local_sym_tab[var_name][0]
    raise ValueError(f"Variable '{var_name}' not found in local symbol table")


def create_int_constant_ptr(value, builder, int_width=64):
    """Create a pointer to an integer constant."""
    # Default to 64-bit integer
    int_type = ir.IntType(int_width)
    ptr = builder.alloca(int_type)
    ptr.align = int_type.width // 8
    builder.store(ir.Constant(int_type, value), ptr)
    return ptr


def get_or_create_ptr_from_arg(arg, builder, local_sym_tab):
    """Extract or create pointer from the call arguments."""

    if isinstance(arg, ast.Name):
        ptr = get_var_ptr_from_name(arg.id, local_sym_tab)
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        ptr = create_int_constant_ptr(arg.value, builder)
    else:
        raise NotImplementedError(
            "Only simple variable names are supported as args in map helpers.")
    return ptr
