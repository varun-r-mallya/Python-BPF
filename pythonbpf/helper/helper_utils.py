import ast
import logging
from llvmlite import ir
from pythonbpf.expr_pass import eval_expr

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
        else:
            raise NotImplementedError(
                f"Unsupported f-string value type: {type(value)}")

    fmt_str = "".join(fmt_parts) + "\n\0"
    fmt_ptr = _create_format_string_global(fmt_str, func, module, builder)

    args = [fmt_ptr, ir.Constant(ir.IntType(32), len(fmt_str))]

    # NOTE: Process expressions (limited to 3 due to BPF constraints)
    if len(exprs) > 3:
        logger.warn(
            "bpf_printk supports up to 3 arguments, extra arguments will be ignored.")

    for expr in exprs[:3]:
        arg_value = _prepare_expr_args(expr, func, module, builder,
                                       local_sym_tab, struct_sym_tab,
                                       local_var_metadata)
        args.append(arg_value)

    # Call the BPF_PRINTK helper
    return _call_bpf_printk_helper(args, builder)


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


def _create_format_string_global(fmt_str, func, module, builder):
    """Create a global variable for the format string."""
    fmt_name = f"{func.name}____fmt{func._fmt_counter}"
    func._fmt_counter += 1

    fmt_gvar = ir.GlobalVariable(
        module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=fmt_name)
    fmt_gvar.global_constant = True
    fmt_gvar.initializer = ir.Constant(
        ir.ArrayType(ir.IntType(8), len(fmt_str)),
        bytearray(fmt_str.encode("utf8"))
    )
    fmt_gvar.linkage = "internal"
    fmt_gvar.align = 1

    return builder.bitcast(fmt_gvar, ir.PointerType())


def _prepare_expr_args(expr, func, module, builder,
                       local_sym_tab, struct_sym_tab,
                       local_var_metadata):
    """Evaluate and prepare an expression to be used as an argument for bpf_printk."""
    print(f"{ast.dump(expr)}")
    val, _ = eval_expr(func, module, builder, expr,
                       local_sym_tab, None, struct_sym_tab,
                       local_var_metadata)

    if val:
        if isinstance(val.type, ir.PointerType):
            val = builder.ptrtoint(val, ir.IntType(64))
        elif isinstance(val.type, ir.IntType):
            if val.type.width < 64:
                val = builder.sext(val, ir.IntType(64))
        else:
            logger.warn(
                "Only int and ptr supported in bpf_printk arguments. Others default to 0.")
            val = ir.Constant(ir.IntType(64), 0)
        return val
    else:
        logger.warn(
            "Failed to evaluate expression for bpf_printk argument. It will be converted to 0.")
        return ir.Constant(ir.IntType(64), 0)


def _call_bpf_printk_helper(args, builder):
    """Call the BPF_PRINTK helper function with the provided arguments."""
    fn_type = ir.FunctionType(
        ir.IntType(64), [ir.PointerType(), ir.IntType(32)], var_arg=True)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_PRINTK.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    return builder.call(fn_ptr, args, tail=True)
