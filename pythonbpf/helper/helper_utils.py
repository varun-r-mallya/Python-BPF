import ast
import logging
from llvmlite import ir

logger = logging.getLogger(__name__)


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


def get_flags_val(arg, builder, local_sym_tab):
    """Extract or create flags value from the call arguments."""
    if not arg:
        return 0

    if isinstance(arg, ast.Name):
        if local_sym_tab and arg.id in local_sym_tab:
            flags_ptr = local_sym_tab[arg.id][0]
            return builder.load(flags_ptr)
        else:
            raise ValueError(
                f"Variable '{arg.id}' not found in local symbol table")
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        return arg.value

    raise NotImplementedError(
        "Only simple variable names or integer constants are supported as flags in map helpers.")


def _handle_fstring_print(joined_str, module, builder, func,
                          local_sym_tab=None, struct_sym_tab=None,
                          local_var_metadata=None):
    """Handle f-string formatting for bpf_printk emitter."""
    fmt_parts = []
    exprs = []

    for value in joined_str.values:
        logger.debug(f"Processing f-string value: {ast.dump(value)}")

        if isinstance(value, ast.Constant):
            _process_constant_in_fstring(value, fmt_parts, exprs)
        elif isinstance(value, ast.FormattedValue):
            _process_fval(value, fmt_parts, exprs,
                          local_sym_tab, struct_sym_tab,
                          local_var_metadata)


def _process_constant_in_fstring(cst, fmt_parts, exprs):
    """Process constant values in f-string."""
    if isinstance(cst.value, str):
        fmt_parts.append(cst.value)
    elif isinstance(cst.value, int):
        fmt_parts.append("%lld")
        exprs.append(ir.Constant(ir.IntType(64), cst.value))
    else:
        raise NotImplementedError(
            f"Unsupported constant type in f-string: {type(cst.value)}")


def _process_fval(fval, fmt_parts, exprs,
                  local_sym_tab, struct_sym_tab,
                  local_var_metadata):
    """Process formatted values in f-string."""
    logger.debug(f"Processing formatted value: {ast.dump(fval)}")

    if isinstance(fval.value, ast.Name):
        _process_name_in_fval(fval.value, fmt_parts, exprs, local_sym_tab)
    elif isinstance(fval.value, ast.Attribute):
        _process_attr_in_fval(fval.value, fmt_parts, exprs,
                              local_sym_tab, struct_sym_tab,
                              local_var_metadata)
    else:
        raise NotImplementedError(
            f"Unsupported formatted value type in f-string: {type(fval.value)}")


def _process_name_in_fval(name_node, fmt_parts, exprs, local_sym_tab):
    """Process name nodes in formatted values."""
    if local_sym_tab and name_node.id in local_sym_tab:
        _, var_type = local_sym_tab[name_node.id]
        _populate_fval(var_type, name_node, fmt_parts, exprs)


def _process_attr_in_fval(attr_node, fmt_parts, exprs,
                          local_sym_tab, struct_sym_tab,
                          local_var_metadata):
    """Process attribute nodes in formatted values."""
    if (isinstance(attr_node.value, ast.Name) and
            local_sym_tab and attr_node.value.id in local_sym_tab):
        var_name = attr_node.value.id
        field_name = attr_node.attr

        if not local_var_metadata or var_name not in local_var_metadata:
            raise ValueError(
                f"Variable metadata for '{var_name}' not found in local variable metadata")

        var_type = local_sym_tab[var_name][1]
        if var_type not in struct_sym_tab:
            raise ValueError(
                f"Struct type '{var_type}' for variable '{var_name}' not found in struct symbol table")

        struct_info = struct_sym_tab[var_type]
        if field_name not in struct_info.fields:
            raise ValueError(
                f"Field '{field_name}' not found in struct '{var_type}'")

        field_type = struct_info.field_type(field_name)
        _populate_fval(field_type, attr_node, fmt_parts, exprs)
    else:
        raise NotImplementedError(
            "Only simple attribute access on local variables is supported in f-strings.")


def _populate_fval(ftype, node, fmt_parts, exprs):
    """Populate format parts and expressions based on field type."""
    if isinstance(ftype, ir.IntType):
        # TODO: We print as signed integers only for now
        if ftype.width == 64:
            fmt_parts.append("%lld")
            exprs.append(node)
        elif ftype.width == 32:
            fmt_parts.append("%d")
            exprs.append(node)
        else:
            raise NotImplementedError(
                f"Unsupported integer width in f-string: {ftype.width}")
    elif ftype == ir.PointerType(ir.IntType(8)):
        # NOTE: We assume i8* is a string
        fmt_parts.append("%s")
        exprs.append(node)
    else:
        raise NotImplementedError(
            f"Unsupported field type in f-string: {ftype}")
