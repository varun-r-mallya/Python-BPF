import ast
from llvmlite import ir


def bpf_ktime_get_ns_emitter(call, module, builder, func):
    """
    Emit LLVM IR for bpf_ktime_get_ns helper function call.
    """
    # func is an arg to just have a uniform signature with other emitters
    helper_id = ir.Constant(ir.IntType(64), 5)
    fn_type = ir.FunctionType(ir.IntType(64), [], var_arg=False)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_ptr = builder.inttoptr(helper_id, fn_ptr_type)
    result = builder.call(fn_ptr, [], tail=False)
    return result


def bpf_map_lookup_elem_emitter(call, map_ptr, module, builder, local_sym_tab=None):
    """
    Emit LLVM IR for bpf_map_lookup_elem helper function call.
    """

    if call.args and len(call.args) != 1:
        raise ValueError("Map lookup expects exactly one argument, got "
                         f"{len(call.args)}")
    key_arg = call.args[0]
    if isinstance(key_arg, ast.Name):
        key_name = key_arg.id
        if local_sym_tab and key_name in local_sym_tab:
            key_ptr = local_sym_tab[key_name]
        else:
            raise ValueError(
                f"Key variable {key_name} not found in local symbol table.")
    elif isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, int):
        # handle constant integer keys
        key_val = key_arg.value
        key_type = ir.IntType(64)
        key_ptr = builder.alloca(key_type)
        key_ptr.align = key_type // 8
        builder.store(ir.Constant(key_type, key_val), key_ptr)
    else:
        raise NotImplementedError(
            "Only simple variable names are supported as keys in map lookup.")

    if key_ptr is None:
        raise ValueError("Key pointer is None.")

    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())

    fn_type = ir.FunctionType(
        ir.PointerType(),  # Return type: void*
        [ir.PointerType(), ir.PointerType()],  # Args: (void*, void*)
        var_arg=False
    )
    fn_ptr_type = ir.PointerType(fn_type)

    # Helper ID 1 is bpf_map_lookup_elem
    fn_addr = ir.Constant(ir.IntType(64), 1)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(fn_ptr, [map_void_ptr, key_ptr], tail=False)

    return result


def bpf_printk_emitter(call, module, builder, func):
    if not hasattr(func, "_fmt_counter"):
        func._fmt_counter = 0

    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            fmt_str = arg.value + "\n" + "\0"
            fmt_name = f"{func.name}____fmt{func._fmt_counter}"
            func._fmt_counter += 1

            fmt_gvar = ir.GlobalVariable(
                module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=fmt_name)
            fmt_gvar.global_constant = True
            fmt_gvar.initializer = ir.Constant(     # type: ignore
                ir.ArrayType(ir.IntType(8), len(fmt_str)),
                bytearray(fmt_str.encode("utf8"))
            )
            fmt_gvar.linkage = "internal"
            fmt_gvar.align = 1      # type: ignore

            fmt_ptr = builder.bitcast(fmt_gvar, ir.PointerType())

            fn_type = ir.FunctionType(ir.IntType(
                64), [ir.PointerType(), ir.IntType(32)], var_arg=True)
            fn_ptr_type = ir.PointerType(fn_type)
            fn_addr = ir.Constant(ir.IntType(64), 6)
            fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

            builder.call(fn_ptr, [fmt_ptr, ir.Constant(
                ir.IntType(32), len(fmt_str))], tail=True)


helper_func_list = {
    "lookup": bpf_map_lookup_elem_emitter,
    "print": bpf_printk_emitter,
    "ktime": bpf_ktime_get_ns_emitter,
}


def handle_helper_call(call, module, builder, func, local_sym_tab=None, map_sym_tab=None):
    if isinstance(call.func, ast.Name):
        func_name = call.func.id
        if func_name in helper_func_list:
            # it is not a map method call
            helper_func_list[func_name](call, module, builder, func)
        else:
            raise NotImplementedError(
                f"Function {func_name} is not implemented as a helper function.")
    elif isinstance(call.func, ast.Attribute):
        # likely a map method call
        if isinstance(call.func.value, ast.Call) and isinstance(call.func.value.func, ast.Name):
            map_name = call.func.value.func.id
            method_name = call.func.attr
            if map_sym_tab and map_name in map_sym_tab:
                map_ptr = map_sym_tab[map_name]
                if method_name in helper_func_list:
                    helper_func_list[method_name](
                        call, map_ptr, module, builder, local_sym_tab)
                else:
                    raise NotImplementedError(
                        f"Map method {method_name} is not implemented as a helper function.")
            else:
                raise ValueError(
                    f"Map variable {map_name} not found in symbol tables.")
        else:
            raise NotImplementedError(
                "Attribute not supported for map method calls.")
