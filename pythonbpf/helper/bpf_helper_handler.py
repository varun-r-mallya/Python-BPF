import ast
from llvmlite import ir
from pythonbpf.expr_pass import eval_expr
from enum import Enum
from .helper_utils import HelperHandlerRegistry, get_key_ptr


class BPFHelperID(Enum):
    BPF_MAP_LOOKUP_ELEM = 1
    BPF_MAP_UPDATE_ELEM = 2
    BPF_MAP_DELETE_ELEM = 3
    BPF_KTIME_GET_NS = 5
    BPF_PRINTK = 6
    BPF_GET_CURRENT_PID_TGID = 14
    BPF_PERF_EVENT_OUTPUT = 25


@HelperHandlerRegistry.register("ktime")
def bpf_ktime_get_ns_emitter(call, map_ptr, module, builder, func,
                             local_sym_tab=None, struct_sym_tab=None,
                             local_var_metadata=None):
    """
    Emit LLVM IR for bpf_ktime_get_ns helper function call.
    """
    # func is an arg to just have a uniform signature with other emitters
    helper_id = ir.Constant(ir.IntType(64), BPFHelperID.BPF_KTIME_GET_NS.value)
    fn_type = ir.FunctionType(ir.IntType(64), [], var_arg=False)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_ptr = builder.inttoptr(helper_id, fn_ptr_type)
    result = builder.call(fn_ptr, [], tail=False)
    return result, ir.IntType(64)


@HelperHandlerRegistry.register("lookup")
def bpf_map_lookup_elem_emitter(call, map_ptr, module, builder, func,
                                local_sym_tab=None, struct_sym_tab=None,
                                local_var_metadata=None):
    """
    Emit LLVM IR for bpf_map_lookup_elem helper function call.
    """
    key_ptr = get_key_ptr(call, builder, local_sym_tab)
    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())

    fn_type = ir.FunctionType(
        ir.PointerType(),  # Return type: void*
        [ir.PointerType(), ir.PointerType()],  # Args: (void*, void*)
        var_arg=False
    )
    fn_ptr_type = ir.PointerType(fn_type)

    fn_addr = ir.Constant(ir.IntType(
        64), BPFHelperID.BPF_MAP_LOOKUP_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(fn_ptr, [map_void_ptr, key_ptr], tail=False)

    return result, ir.PointerType()


@HelperHandlerRegistry.register("print")
def bpf_printk_emitter(call, map_ptr, module, builder, func,
                       local_sym_tab=None, struct_sym_tab=None,
                       local_var_metadata=None):
    if not hasattr(func, "_fmt_counter"):
        func._fmt_counter = 0

    if not call.args:
        raise ValueError("print expects at least one argument")

    if isinstance(call.args[0], ast.JoinedStr):
        fmt_parts = []
        exprs = []

        for value in call.args[0].values:
            print("Value in f-string:", ast.dump(value))
            if isinstance(value, ast.Constant):
                if isinstance(value.value, str):
                    fmt_parts.append(value.value)
                elif isinstance(value.value, int):
                    fmt_parts.append("%lld")
                    exprs.append(ir.Constant(ir.IntType(64), value.value))
                else:
                    raise NotImplementedError(
                        "Only string and integer constants are supported in f-string.")
            elif isinstance(value, ast.FormattedValue):
                print("Formatted value:", ast.dump(value))
                # TODO: Dirty handling here, only checks for int or str
                if isinstance(value.value, ast.Name):
                    if local_sym_tab and value.value.id in local_sym_tab:
                        var_ptr, var_type = local_sym_tab[value.value.id]
                        if isinstance(var_type, ir.IntType):
                            fmt_parts.append("%lld")
                            exprs.append(value.value)
                        elif var_type == ir.PointerType(ir.IntType(8)):
                            # Case with string
                            fmt_parts.append("%s")
                            exprs.append(value.value)
                        else:
                            raise NotImplementedError(
                                "Only integer and pointer types are supported in formatted values.")
                    else:
                        raise ValueError(
                            f"Variable {value.value.id} not found in local symbol table.")
                elif isinstance(value.value, ast.Attribute):
                    # object field access from struct
                    if (isinstance(value.value.value, ast.Name) and
                        local_sym_tab and
                            value.value.value.id in local_sym_tab):
                        var_name = value.value.value.id
                        field_name = value.value.attr
                        if local_var_metadata and var_name in local_var_metadata:
                            var_type = local_var_metadata[var_name]
                            if var_type in struct_sym_tab:
                                struct_info = struct_sym_tab[var_type]
                                if field_name in struct_info.fields:
                                    field_type = struct_info.field_type(
                                        field_name)
                                    if isinstance(field_type, ir.IntType):
                                        fmt_parts.append("%lld")
                                        exprs.append(value.value)
                                    elif field_type == ir.PointerType(ir.IntType(8)):
                                        fmt_parts.append("%s")
                                        exprs.append(value.value)
                                    else:
                                        raise NotImplementedError(
                                            "Only integer and pointer types are supported in formatted values.")
                                else:
                                    raise ValueError(
                                        f"Field {field_name} not found in struct {var_type}.")
                            else:
                                raise ValueError(
                                    f"Struct type {var_type} for variable {var_name} not found in struct symbol table.")
                        else:
                            raise ValueError(
                                f"Metadata for variable {var_name} not found in local variable metadata.")
                    else:
                        raise ValueError(
                            f"Variable {value.value.value.id} not found in local symbol table.")
                else:
                    raise NotImplementedError(
                        "Only simple variable names are supported in formatted values.")
            else:
                raise NotImplementedError(
                    "Unsupported value type in f-string.")

        fmt_str = "".join(fmt_parts) + "\n" + "\0"
        fmt_name = f"{func.name}____fmt{func._fmt_counter}"
        func._fmt_counter += 1

        fmt_gvar = ir.GlobalVariable(
            module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=fmt_name)
        fmt_gvar.global_constant = True
        fmt_gvar.initializer = ir.Constant(                 # type: ignore
            ir.ArrayType(ir.IntType(8), len(fmt_str)),
            bytearray(fmt_str.encode("utf8"))
        )
        fmt_gvar.linkage = "internal"
        fmt_gvar.align = 1              # type: ignore

        fmt_ptr = builder.bitcast(fmt_gvar, ir.PointerType())

        args = [fmt_ptr, ir.Constant(ir.IntType(32), len(fmt_str))]

        # Only 3 args supported in bpf_printk
        if len(exprs) > 3:
            print(
                "Warning: bpf_printk supports up to 3 arguments, extra arguments will be ignored.")

        for expr in exprs[:3]:
            print(f"{ast.dump(expr)}")
            val, _ = eval_expr(func, module, builder,
                               expr, local_sym_tab, None, struct_sym_tab, local_var_metadata)
            if val:
                if isinstance(val.type, ir.PointerType):
                    val = builder.ptrtoint(val, ir.IntType(64))
                elif isinstance(val.type, ir.IntType):
                    if val.type.width < 64:
                        val = builder.sext(val, ir.IntType(64))
                else:
                    print(
                        "Warning: Only integer and pointer types are supported in bpf_printk arguments. Others will be converted to 0.")
                    val = ir.Constant(ir.IntType(64), 0)
                args.append(val)
            else:
                print(
                    "Warning: Failed to evaluate expression for bpf_printk argument. It will be converted to 0.")
                args.append(ir.Constant(ir.IntType(64), 0))
        fn_type = ir.FunctionType(ir.IntType(
            64), [ir.PointerType(), ir.IntType(32)], var_arg=True)
        fn_ptr_type = ir.PointerType(fn_type)
        fn_addr = ir.Constant(ir.IntType(64), 6)
        fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)
        return builder.call(fn_ptr, args, tail=True)

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
            fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_PRINTK.value)
            fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

            builder.call(fn_ptr, [fmt_ptr, ir.Constant(
                ir.IntType(32), len(fmt_str))], tail=True)
    return None


@HelperHandlerRegistry.register("update")
def bpf_map_update_elem_emitter(call, map_ptr, module, builder, func,
                                local_sym_tab=None, struct_sym_tab=None,
                                local_var_metadata=None):
    """
    Emit LLVM IR for bpf_map_update_elem helper function call.
    Expected call signature: map.update(key, value, flags=0)
    """
    if (not call.args or
        len(call.args) < 2 or
            len(call.args) > 3):
        raise ValueError("Map update expects 2 or 3 arguments (key, value, flags), got "
                         f"{len(call.args)}")

    key_arg = call.args[0]
    value_arg = call.args[1]
    flags_arg = call.args[2] if len(call.args) > 2 else None

    # Handle key
    if isinstance(key_arg, ast.Name):
        key_name = key_arg.id
        if local_sym_tab and key_name in local_sym_tab:
            key_ptr = local_sym_tab[key_name][0]
        else:
            raise ValueError(
                f"Key variable {key_name} not found in local symbol table.")
    elif isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, int):
        # Handle constant integer keys
        key_val = key_arg.value
        key_type = ir.IntType(64)
        key_ptr = builder.alloca(key_type)
        key_ptr.align = key_type.width // 8
        builder.store(ir.Constant(key_type, key_val), key_ptr)
    else:
        raise NotImplementedError(
            "Only simple variable names and integer constants are supported as keys in map update.")

    # Handle value
    if isinstance(value_arg, ast.Name):
        value_name = value_arg.id
        if local_sym_tab and value_name in local_sym_tab:
            value_ptr = local_sym_tab[value_name][0]
        else:
            raise ValueError(
                f"Value variable {value_name} not found in local symbol table.")
    elif isinstance(value_arg, ast.Constant) and isinstance(value_arg.value, int):
        # Handle constant integers
        value_val = value_arg.value
        value_type = ir.IntType(64)
        value_ptr = builder.alloca(value_type)
        value_ptr.align = value_type.width // 8
        builder.store(ir.Constant(value_type, value_val), value_ptr)
    else:
        raise NotImplementedError(
            "Only simple variable names and integer constants are supported as values in map update.")

    # Handle flags argument (defaults to 0)
    if flags_arg is not None:
        if isinstance(flags_arg, ast.Constant) and isinstance(flags_arg.value, int):
            flags_val = flags_arg.value
        elif isinstance(flags_arg, ast.Name):
            flags_name = flags_arg.id
            if local_sym_tab and flags_name in local_sym_tab:
                # Assume it's a stored integer value, load it
                flags_ptr = local_sym_tab[flags_name][0]
                flags_val = builder.load(flags_ptr)
            else:
                raise ValueError(
                    f"Flags variable {flags_name} not found in local symbol table.")
        else:
            raise NotImplementedError(
                "Only integer constants and simple variable names are supported as flags in map update.")
    else:
        flags_val = 0

    if key_ptr is None or value_ptr is None:
        raise ValueError("Key pointer or value pointer is None.")

    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())
    fn_type = ir.FunctionType(
        ir.IntType(64),
        [ir.PointerType(), ir.PointerType(), ir.PointerType(), ir.IntType(64)],
        var_arg=False
    )
    fn_ptr_type = ir.PointerType(fn_type)

    # helper id
    fn_addr = ir.Constant(ir.IntType(
        64), BPFHelperID.BPF_MAP_UPDATE_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    if isinstance(flags_val, int):
        flags_const = ir.Constant(ir.IntType(64), flags_val)
    else:
        flags_const = flags_val

    result = builder.call(
        fn_ptr, [map_void_ptr, key_ptr, value_ptr, flags_const], tail=False)

    return result, None


@HelperHandlerRegistry.register("delete")
def bpf_map_delete_elem_emitter(call, map_ptr, module, builder, func,
                                local_sym_tab=None, struct_sym_tab=None,
                                local_var_metadata=None):
    """
    Emit LLVM IR for bpf_map_delete_elem helper function call.
    Expected call signature: map.delete(key)
    """
    key_ptr = get_key_ptr(call, builder, local_sym_tab)
    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())

    # Define function type for bpf_map_delete_elem
    fn_type = ir.FunctionType(
        ir.IntType(64),  # Return type: int64 (status code)
        [ir.PointerType(), ir.PointerType()],  # Args: (void*, void*)
        var_arg=False
    )
    fn_ptr_type = ir.PointerType(fn_type)

    fn_addr = ir.Constant(ir.IntType(
        64), BPFHelperID.BPF_MAP_DELETE_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(fn_ptr, [map_void_ptr, key_ptr], tail=False)

    return result, None


@HelperHandlerRegistry.register("pid")
def bpf_get_current_pid_tgid_emitter(call, map_ptr, module, builder, func,
                                     local_sym_tab=None, struct_sym_tab=None,
                                     local_var_metadata=None):
    """
    Emit LLVM IR for bpf_get_current_pid_tgid helper function call.
    """
    # func is an arg to just have a uniform signature with other emitters
    helper_id = ir.Constant(ir.IntType(
        64), BPFHelperID.BPF_GET_CURRENT_PID_TGID.value)
    fn_type = ir.FunctionType(ir.IntType(64), [], var_arg=False)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_ptr = builder.inttoptr(helper_id, fn_ptr_type)
    result = builder.call(fn_ptr, [], tail=False)

    # Extract the lower 32 bits (PID) using bitwise AND with 0xFFFFFFFF
    mask = ir.Constant(ir.IntType(64), 0xFFFFFFFF)
    pid = builder.and_(result, mask)
    return pid, ir.IntType(64)


def bpf_perf_event_output_handler(call, map_ptr, module, builder, func,
                                  local_sym_tab=None, struct_sym_tab=None,
                                  local_var_metadata=None):
    if len(call.args) != 1:
        raise ValueError("Perf event output expects exactly one argument (data), got "
                         f"{len(call.args)}")
    data_arg = call.args[0]
    ctx_ptr = func.args[0]  # First argument to the function is ctx

    if isinstance(data_arg, ast.Name):
        data_name = data_arg.id
        if local_sym_tab and data_name in local_sym_tab:
            data_ptr = local_sym_tab[data_name][0]
        else:
            raise ValueError(
                f"Data variable {data_name} not found in local symbol table.")
        # Check is data_name is a struct
        if local_var_metadata and data_name in local_var_metadata:
            data_type = local_var_metadata[data_name]
            if data_type in struct_sym_tab:
                struct_info = struct_sym_tab[data_type]
                size_val = ir.Constant(ir.IntType(64), struct_info.size)
            else:
                raise ValueError(
                    f"Struct type {data_type} for variable {data_name} not found in struct symbol table.")
        else:
            raise ValueError(
                f"Metadata for variable {data_name} not found in local variable metadata.")

        # BPF_F_CURRENT_CPU is -1 in 32 bit
        flags_val = ir.Constant(ir.IntType(64), 0xFFFFFFFF)

        map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())
        data_void_ptr = builder.bitcast(data_ptr, ir.PointerType())
        fn_type = ir.FunctionType(
            ir.IntType(64),
            [ir.PointerType(ir.IntType(8)), ir.PointerType(), ir.IntType(64),
             ir.PointerType(), ir.IntType(64)],
            var_arg=False
        )
        fn_ptr_type = ir.PointerType(fn_type)

        # helper id
        fn_addr = ir.Constant(ir.IntType(
            64), BPFHelperID.BPF_PERF_EVENT_OUTPUT.value)
        fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

        result = builder.call(
            fn_ptr, [ctx_ptr, map_void_ptr, flags_val, data_void_ptr, size_val], tail=False)
        return result, None
    else:
        raise NotImplementedError(
            "Only simple object names are supported as data in perf event output.")


def handle_helper_call(call, module, builder, func,
                       local_sym_tab=None, map_sym_tab=None,
                       struct_sym_tab=None, local_var_metadata=None):
    print(local_var_metadata)
    if isinstance(call.func, ast.Name):
        func_name = call.func.id
        hdl_func = HelperHandlerRegistry.get_handler(func_name)
        if hdl_func:
            # it is not a map method call
            return hdl_func(call, None, module, builder, func, local_sym_tab, struct_sym_tab, local_var_metadata)
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
                hdl_func = HelperHandlerRegistry.get_handler(method_name)
                if hdl_func:
                    print(local_var_metadata)
                    return hdl_func(
                        call, map_ptr, module, builder, func, local_sym_tab, struct_sym_tab, local_var_metadata)
                else:
                    raise NotImplementedError(
                        f"Map method {method_name} is not implemented as a helper function.")
            else:
                raise ValueError(
                    f"Map variable {map_name} not found in symbol tables.")
        elif isinstance(call.func.value, ast.Name):
            obj_name = call.func.value.id
            method_name = call.func.attr
            if map_sym_tab and obj_name in map_sym_tab:
                map_ptr = map_sym_tab[obj_name]
                hdl_func = HelperHandlerRegistry.get_handler(method_name)
                if hdl_func:
                    return hdl_func(
                        call, map_ptr, module, builder, func, local_sym_tab, struct_sym_tab, local_var_metadata)
                else:
                    raise NotImplementedError(
                        f"Map method {method_name} is not implemented as a helper function.")
            else:
                raise ValueError(
                    f"Map variable {obj_name} not found in symbol tables.")
        else:
            raise NotImplementedError(
                "Attribute not supported for map method calls.")
    return None
