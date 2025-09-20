from llvmlite import ir
import ast


from .bpf_helper_handler import helper_func_list, handle_helper_call
from .type_deducer import ctypes_to_ir
from .binary_ops import handle_binary_op
from .expr_pass import eval_expr, handle_expr

local_var_metadata = {}


def get_probe_string(func_node):
    """Extract the probe string from the decorator of the function node."""
    # TODO: right now we have the whole string in the section decorator
    # But later we can implement typed tuples for tracepoints and kprobes
    # For helper functions, we return "helper"

    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "bpfglobal":
            return None
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "section" and len(decorator.args) == 1:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    return "helper"


def handle_assign(func, module, builder, stmt, map_sym_tab, local_sym_tab, structs_sym_tab):
    """Handle assignment statements in the function body."""
    if len(stmt.targets) != 1:
        print("Unsupported multiassignment")
        return

    num_types = ("c_int32", "c_int64", "c_uint32", "c_uint64")

    target = stmt.targets[0]
    print(f"Handling assignment to {ast.dump(target)}")
    if not isinstance(target, ast.Name) and not isinstance(target, ast.Attribute):
        print("Unsupported assignment target")
        return
    var_name = target.id if isinstance(target, ast.Name) else target.value.id
    rval = stmt.value
    if isinstance(target, ast.Attribute):
        # struct field assignment
        field_name = target.attr
        if var_name in local_sym_tab and var_name in local_var_metadata:
            struct_type = local_var_metadata[var_name]
            struct_info = structs_sym_tab[struct_type]

            if field_name in struct_info["fields"]:
                field_idx = struct_info["fields"][field_name]
                struct_ptr = local_sym_tab[var_name]
                field_ptr = builder.gep(
                    struct_ptr, [ir.Constant(ir.IntType(32), 0),
                                 ir.Constant(ir.IntType(32), field_idx)],
                    inbounds=True)
                val = eval_expr(func, module, builder, rval,
                                local_sym_tab, map_sym_tab)
                if val is None:
                    print("Failed to evaluate struct field assignment")
                    return
                builder.store(val, field_ptr)
                print(f"Assigned to struct field {var_name}.{field_name}")
                return
    elif isinstance(rval, ast.Constant):
        if isinstance(rval.value, bool):
            if rval.value:
                builder.store(ir.Constant(ir.IntType(1), 1),
                              local_sym_tab[var_name])
            else:
                builder.store(ir.Constant(ir.IntType(1), 0),
                              local_sym_tab[var_name])
            print(f"Assigned constant {rval.value} to {var_name}")
        elif isinstance(rval.value, int):
            # Assume c_int64 for now
            # var = builder.alloca(ir.IntType(64), name=var_name)
            # var.align = 8
            builder.store(ir.Constant(ir.IntType(64), rval.value),
                          local_sym_tab[var_name])
            # local_sym_tab[var_name] = var
            print(f"Assigned constant {rval.value} to {var_name}")
        else:
            print("Unsupported constant type")
    elif isinstance(rval, ast.Call):
        if isinstance(rval.func, ast.Name):
            call_type = rval.func.id
            print(f"Assignment call type: {call_type}")
            if call_type in num_types and len(rval.args) == 1 and isinstance(rval.args[0], ast.Constant) and isinstance(rval.args[0].value, int):
                ir_type = ctypes_to_ir(call_type)
                # var = builder.alloca(ir_type, name=var_name)
                # var.align = ir_type.width // 8
                builder.store(ir.Constant(
                    ir_type, rval.args[0].value), local_sym_tab[var_name])
                print(f"Assigned {call_type} constant "
                      f"{rval.args[0].value} to {var_name}")
                # local_sym_tab[var_name] = var
            elif call_type in helper_func_list:
                # var = builder.alloca(ir.IntType(64), name=var_name)
                # var.align = 8
                val = handle_helper_call(
                    rval, module, builder, None, local_sym_tab, map_sym_tab)
                builder.store(val, local_sym_tab[var_name])
                # local_sym_tab[var_name] = var
                print(f"Assigned constant {rval.func.id} to {var_name}")
            elif call_type == "deref" and len(rval.args) == 1:
                print(f"Handling deref assignment {ast.dump(rval)}")
                val = eval_expr(func, module, builder, rval,
                                local_sym_tab, map_sym_tab)
                if val is None:
                    print("Failed to evaluate deref argument")
                    return
                print(f"Dereferenced value: {val}, storing in {var_name}")
                builder.store(val, local_sym_tab[var_name])
                # local_sym_tab[var_name] = var
                print(f"Dereferenced and assigned to {var_name}")
            elif call_type in structs_sym_tab and len(rval.args) == 0:
                struct_info = structs_sym_tab[call_type]
                ir_type = struct_info["type"]
                # var = builder.alloca(ir_type, name=var_name)
                # Null init
                builder.store(ir.Constant(ir_type, None),
                              local_sym_tab[var_name])
                local_var_metadata[var_name] = call_type
                print(f"Assigned struct {call_type} to {var_name}")
                # local_sym_tab[var_name] = var
            else:
                print(f"Unsupported assignment call type: {call_type}")
        elif isinstance(rval.func, ast.Attribute):
            print(f"Assignment call attribute: {ast.dump(rval.func)}")
            if isinstance(rval.func.value, ast.Name):
                # TODO: probably a struct access
                print(f"TODO STRUCT ACCESS {ast.dump(rval)}")
            elif isinstance(rval.func.value, ast.Call) and isinstance(rval.func.value.func, ast.Name):
                map_name = rval.func.value.func.id
                method_name = rval.func.attr
                if map_name in map_sym_tab:
                    map_ptr = map_sym_tab[map_name]
                    if method_name in helper_func_list:
                        val = handle_helper_call(
                            rval, module, builder, func, local_sym_tab, map_sym_tab)
                        # var = builder.alloca(ir.IntType(64), name=var_name)
                        # var.align = 8
                        builder.store(val, local_sym_tab[var_name])
                        # local_sym_tab[var_name] = var
            else:
                print("Unsupported assignment call structure")
        else:
            print("Unsupported assignment call function type")
    elif isinstance(rval, ast.BinOp):
        handle_binary_op(rval, module, builder, var_name,
                         local_sym_tab, map_sym_tab, func)
    else:
        print("Unsupported assignment value type")


def handle_cond(func, module, builder, cond, local_sym_tab, map_sym_tab):
    if isinstance(cond, ast.Constant):
        if isinstance(cond.value, bool):
            return ir.Constant(ir.IntType(1), int(cond.value))
        elif isinstance(cond.value, int):
            return ir.Constant(ir.IntType(1), int(bool(cond.value)))
        else:
            print("Unsupported constant type in condition")
            return None
    elif isinstance(cond, ast.Name):
        if cond.id in local_sym_tab:
            var = local_sym_tab[cond.id]
            val = builder.load(var)
            if val.type != ir.IntType(1):
                # Convert nonzero values to true, zero to false
                if isinstance(val.type, ir.PointerType):
                    # For pointer types, compare with null pointer
                    zero = ir.Constant(val.type, None)
                else:
                    # For integer types, compare with zero
                    zero = ir.Constant(val.type, 0)
                val = builder.icmp_signed("!=", val, zero)
            return val
        else:
            print(f"Undefined variable {cond.id} in condition")
            return None
    elif isinstance(cond, ast.Compare):
        lhs = eval_expr(func, module, builder, cond.left,
                        local_sym_tab, map_sym_tab)
        if len(cond.ops) != 1 or len(cond.comparators) != 1:
            print("Unsupported complex comparison")
            return None
        rhs = eval_expr(func, module, builder,
                        cond.comparators[0], local_sym_tab, map_sym_tab)
        op = cond.ops[0]

        if lhs.type != rhs.type:
            if isinstance(lhs.type, ir.IntType) and isinstance(rhs.type, ir.IntType):
                # Extend the smaller type to the larger type
                if lhs.type.width < rhs.type.width:
                    lhs = builder.sext(lhs, rhs.type)
                elif lhs.type.width > rhs.type.width:
                    rhs = builder.sext(rhs, lhs.type)
            else:
                print("Type mismatch in comparison")
                return None

        if isinstance(op, ast.Eq):
            return builder.icmp_signed("==", lhs, rhs)
        elif isinstance(op, ast.NotEq):
            return builder.icmp_signed("!=", lhs, rhs)
        elif isinstance(op, ast.Lt):
            return builder.icmp_signed("<", lhs, rhs)
        elif isinstance(op, ast.LtE):
            return builder.icmp_signed("<=", lhs, rhs)
        elif isinstance(op, ast.Gt):
            return builder.icmp_signed(">", lhs, rhs)
        elif isinstance(op, ast.GtE):
            return builder.icmp_signed(">=", lhs, rhs)
        else:
            print("Unsupported comparison operator")
            return None
    else:
        print("Unsupported condition expression")
        return None


def handle_if(func, module, builder, stmt, map_sym_tab, local_sym_tab):
    """Handle if statements in the function body."""
    print("Handling if statement")
    start = builder.block.parent
    then_block = func.append_basic_block(name="if.then")
    merge_block = func.append_basic_block(name="if.end")
    if stmt.orelse:
        else_block = func.append_basic_block(name="if.else")
    else:
        else_block = None

    cond = handle_cond(func, module, builder, stmt.test,
                       local_sym_tab, map_sym_tab)
    if else_block:
        builder.cbranch(cond, then_block, else_block)
    else:
        builder.cbranch(cond, then_block, merge_block)

    builder.position_at_end(then_block)
    for s in stmt.body:
        process_stmt(func, module, builder, s,
                     local_sym_tab, map_sym_tab, False)
    if not builder.block.is_terminated:
        builder.branch(merge_block)

    if else_block:
        builder.position_at_end(else_block)
        for s in stmt.orelse:
            process_stmt(func, module, builder, s,
                         local_sym_tab, map_sym_tab, False)
        if not builder.block.is_terminated:
            builder.branch(merge_block)

    builder.position_at_end(merge_block)


def process_stmt(func, module, builder, stmt, local_sym_tab, map_sym_tab, structs_sym_tab, did_return, ret_type=ir.IntType(64)):
    print(f"Processing statement: {ast.dump(stmt)}")
    if isinstance(stmt, ast.Expr):
        handle_expr(func, module, builder, stmt, local_sym_tab, map_sym_tab)
    elif isinstance(stmt, ast.Assign):
        handle_assign(func, module, builder, stmt, map_sym_tab,
                      local_sym_tab, structs_sym_tab)
    elif isinstance(stmt, ast.AugAssign):
        raise SyntaxError("Augmented assignment not supported")
    elif isinstance(stmt, ast.If):
        handle_if(func, module, builder, stmt, map_sym_tab, local_sym_tab)
    elif isinstance(stmt, ast.Return):
        if stmt.value is None:
            builder.ret(ir.Constant(ir.IntType(32), 0))
            did_return = True
        elif isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and len(stmt.value.args) == 1 and isinstance(stmt.value.args[0], ast.Constant) and isinstance(stmt.value.args[0].value, int):
            call_type = stmt.value.func.id
            if ctypes_to_ir(call_type) != ret_type:
                raise ValueError("Return type mismatch: expected"
                                 f"{ctypes_to_ir(call_type)}, got {call_type}")
            else:
                builder.ret(ir.Constant(
                    ret_type, stmt.value.args[0].value))
                did_return = True
        elif isinstance(stmt.value, ast.Name):
            if stmt.value.id == "XDP_PASS":
                builder.ret(ir.Constant(ret_type, 2))
                did_return = True
            elif stmt.value.id == "XDP_DROP":
                builder.ret(ir.Constant(ret_type, 1))
                did_return = True
            else:
                raise ValueError("Failed to evaluate return expression")
        else:
            raise ValueError("Unsupported return value")
    return did_return


def allocate_mem(module, builder, body, func, ret_type, map_sym_tab, local_sym_tab, structs_sym_tab):
    for stmt in body:
        if isinstance(stmt, ast.If):
            if stmt.body:
                local_sym_tab = allocate_mem(
                    module, builder, stmt.body, func, ret_type, map_sym_tab, local_sym_tab, structs_sym_tab)
            if stmt.orelse:
                local_sym_tab = allocate_mem(
                    module, builder, stmt.orelse, func, ret_type, map_sym_tab, local_sym_tab, structs_sym_tab)
        elif isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1:
                print("Unsupported multiassignment")
                continue
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                print("Unsupported assignment target")
                continue
            var_name = target.id
            rval = stmt.value
            if isinstance(rval, ast.Call):
                if isinstance(rval.func, ast.Name):
                    call_type = rval.func.id
                    if call_type in ("c_int32", "c_int64", "c_uint32", "c_uint64"):
                        ir_type = ctypes_to_ir(call_type)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        print(
                            f"Pre-allocated variable {var_name} of type {call_type}")
                    elif call_type in helper_func_list:
                        # Assume return type is int64 for now
                        ir_type = ir.IntType(64)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        print(
                            f"Pre-allocated variable {var_name} for helper")
                    elif call_type == "deref" and len(rval.args) == 1:
                        # Assume return type is int64 for now
                        ir_type = ir.IntType(64)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        print(
                            f"Pre-allocated variable {var_name} for deref")
                    elif call_type in structs_sym_tab:
                        struct_info = structs_sym_tab[call_type]
                        ir_type = struct_info["type"]
                        var = builder.alloca(ir_type, name=var_name)
                        local_var_metadata[var_name] = call_type
                        print(
                            f"Pre-allocated variable {var_name} for struct {call_type}")
                elif isinstance(rval.func, ast.Attribute):
                    ir_type = ir.PointerType(ir.IntType(64))
                    var = builder.alloca(ir_type, name=var_name)
                    # var.align = ir_type.width // 8
                    print(
                        f"Pre-allocated variable {var_name} for map")
                else:
                    print("Unsupported assignment call function type")
                    continue
            elif isinstance(rval, ast.Constant):
                if isinstance(rval.value, bool):
                    ir_type = ir.IntType(1)
                    var = builder.alloca(ir_type, name=var_name)
                    var.align = 1
                    print(
                        f"Pre-allocated variable {var_name} of type c_bool")
                elif isinstance(rval.value, int):
                    # Assume c_int64 for now
                    ir_type = ir.IntType(64)
                    var = builder.alloca(ir_type, name=var_name)
                    var.align = ir_type.width // 8
                    print(
                        f"Pre-allocated variable {var_name} of type c_int64")
                else:
                    print("Unsupported constant type")
                    continue
            elif isinstance(rval, ast.BinOp):
                # Assume c_int64 for now
                ir_type = ir.IntType(64)
                var = builder.alloca(ir_type, name=var_name)
                var.align = ir_type.width // 8
                print(
                    f"Pre-allocated variable {var_name} of type c_int64")
            else:
                print("Unsupported assignment value type")
                continue
            local_sym_tab[var_name] = var
    return local_sym_tab


def process_func_body(module, builder, func_node, func, ret_type, map_sym_tab, structs_sym_tab):
    """Process the body of a bpf function"""
    # TODO: A lot.  We just have print -> bpf_trace_printk for now
    did_return = False

    local_sym_tab = {}

    # pre-allocate dynamic variables
    local_sym_tab = allocate_mem(
        module, builder, func_node.body, func, ret_type, map_sym_tab, local_sym_tab, structs_sym_tab)

    print(f"Local symbol table: {local_sym_tab.keys()}")

    for stmt in func_node.body:
        did_return = process_stmt(func, module, builder, stmt, local_sym_tab,
                                  map_sym_tab, structs_sym_tab, did_return, ret_type)

    if not did_return:
        builder.ret(ir.Constant(ir.IntType(32), 0))


def process_bpf_chunk(func_node, module, return_type, map_sym_tab, structs_sym_tab):
    """Process a single BPF chunk (function) and emit corresponding LLVM IR."""

    func_name = func_node.name

    ret_type = return_type

    # TODO: parse parameters
    param_types = []
    if func_node.args.args:
        # Assume first arg to be ctx
        param_types.append(ir.PointerType())

    func_ty = ir.FunctionType(ret_type, param_types)
    func = ir.Function(module, func_ty, func_name)

    func.linkage = "dso_local"
    func.attributes.add("nounwind")
    func.attributes.add("noinline")
    func.attributes.add("optnone")

    if func_node.args.args:
        # Only look at the first argument for now
        param = func.args[0]
        param.add_attribute("nocapture")

    probe_string = get_probe_string(func_node)
    if probe_string is not None:
        func.section = probe_string

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)

    process_func_body(module, builder, func_node, func,
                      ret_type, map_sym_tab, structs_sym_tab)

    return func


def func_proc(tree, module, chunks, map_sym_tab, structs_sym_tab):
    for func_node in chunks:
        is_global = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in ("map", "bpfglobal", "struct"):
                is_global = True
                break
        if is_global:
            continue
        func_type = get_probe_string(func_node)
        print(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(func_node, module, ctypes_to_ir(
            infer_return_type(func_node)), map_sym_tab, structs_sym_tab)


def infer_return_type(func_node: ast.FunctionDef):
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise TypeError("Expected ast.FunctionDef")
    if func_node.returns is not None:
        try:
            return ast.unparse(func_node.returns)
        except Exception:
            node = func_node.returns
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return getattr(node, "attr", type(node).__name__)
            try:
                return str(node)
            except Exception:
                return type(node).__name__
    found_type = None

    def _expr_type(e):
        if e is None:
            return "None"
        if isinstance(e, ast.Constant):
            return type(e.value).__name__
        if isinstance(e, ast.Name):
            return e.id
        if isinstance(e, ast.Call):
            f = e.func
            if isinstance(f, ast.Name):
                return f.id
            if isinstance(f, ast.Attribute):
                try:
                    return ast.unparse(f)
                except Exception:
                    return getattr(f, "attr", type(f).__name__)
            try:
                return ast.unparse(f)
            except Exception:
                return type(f).__name__
        if isinstance(e, ast.Attribute):
            try:
                return ast.unparse(e)
            except Exception:
                return getattr(e, "attr", type(e).__name__)
        try:
            return ast.unparse(e)
        except Exception:
            return type(e).__name__
    for node in ast.walk(func_node):
        if isinstance(node, ast.Return):
            t = _expr_type(node.value)
            if found_type is None:
                found_type = t
            elif found_type != t:
                raise ValueError("Conflicting return types:"
                                 f"{found_type} vs {t}")
    return found_type or "None"
