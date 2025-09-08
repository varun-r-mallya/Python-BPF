import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir

map_sym_tab = {}


def maps_proc(tree, module, chunks):
    for func_node in chunks:
        # Check if this function is a map
        is_map = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "map":
                is_map = True
                break
        if is_map:
            print(f"Found BPF map: {func_node.name}")
            process_bpf_map(func_node, module)
            continue


def create_bpf_map(module, map_name, map_params):
    """Create a BPF map in the module with the given parameters"""

    # Create the anonymous struct type for BPF map
    map_struct_type = ir.LiteralStructType([
        ir.PointerType(),
        ir.PointerType(),
        ir.PointerType(),
        ir.PointerType()
    ])

    # Create the global variable
    map_global = ir.GlobalVariable(module, map_struct_type, name=map_name)
    map_global.linkage = 'dso_local'
    map_global.global_constant = False

    # Initialize with zeroinitializer (all null pointers)
    map_global.initializer = ir.Constant(map_struct_type, None)  # type: ignore

    map_global.section = ".maps"
    map_global.align = 8    # type: ignore

    print(f"Created BPF map: {map_name}")
    map_sym_tab[map_name] = map_global
    return map_global


def process_hash_map(map_name, rval, module):
    print(f"Creating HashMap map: {map_name}")
    map_params: dict[str, object] = {"map_type": "HASH"}

    # Assuming order: key_type, value_type, max_entries
    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
        map_params["key_type"] = rval.args[0].id
    if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
        map_params["value_type"] = rval.args[1].id
    if len(rval.args) >= 3 and isinstance(rval.args[2], ast.Constant):
        const_val = rval.args[2].value
        if isinstance(const_val, (int, str)):  # safe check
            map_params["max_entries"] = const_val

    for keyword in rval.keywords:
        if keyword.arg == "key_type" and isinstance(keyword.value, ast.Name):
            map_params["key_type"] = keyword.value.id
        elif keyword.arg == "value_type" and isinstance(keyword.value, ast.Name):
            map_params["value_type"] = keyword.value.id
        elif keyword.arg == "max_entries" and isinstance(keyword.value, ast.Constant):
            const_val = keyword.value.value
            if isinstance(const_val, (int, str)):
                map_params["max_entries"] = const_val

    print(f"Map parameters: {map_params}")
    return create_bpf_map(module, map_name, map_params)


def process_bpf_map(func_node, module):
    """Process a BPF map (a function decorated with @map)"""
    map_name = func_node.name
    print(f"Processing BPF map: {map_name}")

    # For now, assume single return statement
    return_stmt = None
    for stmt in func_node.body:
        if isinstance(stmt, ast.Return):
            return_stmt = stmt
            break
    if return_stmt is None:
        raise ValueError("BPF map must have a return statement")

    rval = return_stmt.value

    # Handle only HashMap maps
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name) and rval.func.id == "HashMap":
        process_hash_map(map_name, rval, module)
    else:
        raise ValueError("Function under @map must return a map")
