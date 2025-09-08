from llvmlite import ir
import ast

from .bpf_helper_handler import bpf_printk_emitter, bpf_ktime_get_ns_emitter
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
            if isinstance(call.func, ast.Name) and call.func.id == "bpf_ktime_get_ns":
                bpf_ktime_get_ns_emitter(call, module, builder, func)
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


def process_bpf_chunk(func_node, module, return_type):
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

    func.section = get_probe_string(func_node)

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)

    process_func_body(module, builder, func_node, func, ret_type)

    return func


def create_bpf_map(module, map_name, map_params):
    """Create a BPF map in the module with the given parameters"""

    key_type_str = map_params.get('key_type', 'c_uint32')
    value_type_str = map_params.get('value_type', 'c_uint32')

    key_type = ctypes_to_ir(key_type_str)
    value_type = ctypes_to_ir(value_type_str)

    map_struct_type = ir.LiteralStructType([
        ir.PointerType(),  # type
        ir.PointerType(),  # max_entries
        ir.PointerType(),  # key_type
        ir.PointerType()   # value_type
    ])

    map_global = ir.GlobalVariable(module, map_struct_type, name=map_name)
    map_global.linkage = 'external'
    map_global.initializer = ir.Constant(
        map_struct_type, [None, None, None, None])
    map_global.section = ".maps"
    map_global.align = 8

    # TODO: Store map parameters in metadata or a suitable structure
    # maps[map_name] = {
    #    'global': map_global,
    #    'key_type': key_type,
    #    'value_type': value_type,
    #    'max_entries': map_params.get('max_entries', 1),
    #    'map_type': map_params.get('map_type', 'BPF_MAP_TYPE_HASH')
    # }

    print(f"Created BPF map: {map_name}")
    return map_global


def process_bpf_global(func_node, module):
    """Process a BPF global (a function decorated with @bpfglobal)"""
    global_name = func_node.name
    print(f"Processing BPF global: {global_name}")

    # For now, assume single return statement
    return_stmt = None
    for stmt in func_node.body:
        if isinstance(stmt, ast.Return):
            return_stmt = stmt
            break
    if return_stmt is None:
        raise ValueError("BPF global must have a return statement")

    rval = return_stmt.value

    # For now, just handle maps
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name) and rval.func.id == "HashMap":
        print(f"Creating HashMap global: {global_name}")
        map_params = {'map_type': 'HASH'}
        # Handle positional arguments
        if rval.args:
            # Assuming order is: key_type, value_type, max_entries
            if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
                map_params['key_type'] = rval.args[0].id
            if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
                map_params['value_type'] = rval.args[1].id
            if len(rval.args) >= 3 and isinstance(rval.args[2], ast.Constant):
                map_params['max_entries'] = rval.args[2].value

            # Handle keyword arguments (these will override any positional args)
        for keyword in rval.keywords:
            if keyword.arg == "key_type" and isinstance(keyword.value, ast.Name):
                map_params['key_type'] = keyword.value.id
            elif keyword.arg == "value_type" and isinstance(keyword.value, ast.Name):
                map_params['value_type'] = keyword.value.id
            elif keyword.arg == "max_entries" and isinstance(keyword.value, ast.Constant):
                map_params['max_entries'] = keyword.value.value
        print(f"Map parameters: {map_params}")
        print(create_bpf_map(module, global_name, map_params))


def func_proc(tree, module, chunks):
    for func_node in chunks:
        # Check if this function is a global
        is_global = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "bpfglobal":
                is_global = True
                break
        if is_global:
            print(f"Found BPF global: {func_node.name}")
            process_bpf_global(func_node, module)
            continue
        func_type = get_probe_string(func_node)
        print(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(func_node, module, ctypes_to_ir(
            infer_return_type(func_node)))


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
