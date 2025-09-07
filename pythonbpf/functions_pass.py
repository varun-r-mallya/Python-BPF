from llvmlite import ir
import ast

from .bpf_helper_handler import bpf_printk_emitter
from .type_deducer import ctypes_to_ir

def get_probe_string(func_node):
    """Extract the probe string from the decorator of the function node."""
    # TODO: right now we have the whole string in the section decorator
    # But later we can implement typed tuples for tracepoints and kprobes
    # For helper functions, we return "helper"

    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "section" and len(decorator.args) == 1:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    return "helper"


def process_func_body(module, builder, func_node, func, ret_type):
    """Process the body of a bpf function"""
    # TODO: A lot.  We just have print -> bpf_trace_printk for now
    did_return = False

    for stmt in func_node.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if isinstance(call.func, ast.Name) and call.func.id == "print":
                bpf_printk_emitter(call, module, builder, func)
        elif isinstance(stmt, ast.Return):
            if stmt.value is None:
                builder.ret(ir.Constant(ir.IntType(32), 0))
                did_return = True
            elif isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and len(stmt.value.args) == 1 and isinstance(stmt.value.args[0], ast.Constant) and isinstance(stmt.value.args[0].value, int):
                call_type = stmt.value.func.id
                if ctypes_to_ir(call_type) != ret_type:
                    raise ValueError(f"Return type mismatch: expected {ctypes_to_ir(call_type)}, got {call_type}")
                else:
                    builder.ret(ir.Constant(ret_type, stmt.value.args[0].value))
                    did_return = True
            else:
                print("Unsupported return value")
    if not did_return:
        builder.ret(ir.Constant(ir.IntType(32), 0))


def process_bpf_chunk(func_node, module, return_type):
    """Process a single BPF chunk (function) and emit corresponding LLVM IR."""

    func_name = func_node.name

    #TODO: The function actual arg retgurn type is parsed, 
    # but the actual output is not. It's still very wrong. Try uncommenting the 
    # code in execve2.py once
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

    func.section = get_probe_string(func_node)

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)

    process_func_body(module, builder, func_node, func, ret_type)

    print(func)
    print(module)
    return func


def func_proc(tree, module, chunks):
    for func_node in chunks:
        func_type = get_probe_string(func_node)
        print(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(func_node, module, ctypes_to_ir(infer_return_type(func_node)))

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
                raise ValueError(f"Conflicting return types: {found_type} vs {t}")
    return found_type or "None"
