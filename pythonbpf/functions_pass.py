from llvmlite import ir
import ast

from .bpf_helper_handler import helper_func_list, handle_helper_call
from .type_deducer import ctypes_to_ir


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


def handle_assign(module, builder, stmt, map_sym_tab, local_sym_tab):
    """Handle assignment statements in the function body."""
    if len(stmt.targets) != 1:
        print("Unsupported multiassignment")
        return

    num_types = ("c_int32", "c_int64", "c_uint32", "c_uint64")

    target = stmt.targets[0]
    if not isinstance(target, ast.Name):
        print("Unsupported assignment target")
        return
    var_name = target.id
    rval = stmt.value
    if isinstance(rval, ast.Constant):
        if isinstance(rval.value, int):
            # Assume c_int64 for now
            # TODO: make symtab for this
            var = builder.alloca(ir.IntType(64), name=var_name)
            var.align = 8
            builder.store(ir.Constant(ir.IntType(64), rval.value), var)
            local_sym_tab[var_name] = var
            print(f"Assigned constant {rval.value} to {var_name}")
    elif isinstance(rval, ast.Call):
        if isinstance(rval.func, ast.Name):
            call_type = rval.func.id
            print(f"Assignment call type: {call_type}")
            if call_type in num_types and len(rval.args) == 1 and isinstance(rval.args[0], ast.Constant) and isinstance(rval.args[0].value, int):
                ir_type = ctypes_to_ir(call_type)
                var = builder.alloca(ir_type, name=var_name)
                var.align = ir_type.width // 8
                builder.store(ir.Constant(ir_type, rval.args[0].value), var)
                print(f"Assigned {call_type} constant "
                      f"{rval.args[0].value} to {var_name}")
                local_sym_tab[var_name] = var
            else:
                print(f"Unsupported assignment call type: {call_type}")
        elif isinstance(rval.func, ast.Attribute):
            if isinstance(rval.func.value, ast.Call) and isinstance(rval.func.value.func, ast.Name):
                map_name = rval.func.value.func.id
                method_name = rval.func.attr
                if map_name in map_sym_tab:
                    map_ptr = map_sym_tab[map_name]
                    if method_name in helper_func_list:
                        handle_helper_call(
                            rval, module, builder, None, local_sym_tab, map_sym_tab)
            else:
                print("Unsupported assignment call structure")


def process_func_body(module, builder, func_node, func, ret_type, map_sym_tab):
    """Process the body of a bpf function"""
    # TODO: A lot.  We just have print -> bpf_trace_printk for now
    did_return = False

    local_sym_tab = {}

    for stmt in func_node.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if isinstance(call.func, ast.Name):
                # check for helpers first
                if call.func.id in helper_func_list:
                    handle_helper_call(
                        call, module, builder, func, local_sym_tab, map_sym_tab)
        elif isinstance(stmt, ast.Assign):
            handle_assign(module, builder, stmt, map_sym_tab, local_sym_tab)
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
            else:
                print("Unsupported return value")
    if not did_return:
        builder.ret(ir.Constant(ir.IntType(32), 0))


def process_bpf_chunk(func_node, module, return_type, map_sym_tab):
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

    process_func_body(module, builder, func_node, func, ret_type, map_sym_tab)

    return func


def func_proc(tree, module, chunks, map_sym_tab):
    for func_node in chunks:
        is_global = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "map":
                is_global = True
                break
            elif isinstance(decorator, ast.Name) and decorator.id == "bpfglobal":
                is_global = True
                break
        if is_global:
            continue
        func_type = get_probe_string(func_node)
        print(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(func_node, module, ctypes_to_ir(
            infer_return_type(func_node)), map_sym_tab)


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
