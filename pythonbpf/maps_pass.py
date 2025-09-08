import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir

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
    map_global.initializer = ir.Constant(       #   type: ignore
        map_struct_type, [None, None, None, None])
    map_global.section = ".maps"
    map_global.align = 8        # type: ignore

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

    # For now, just handle maps
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name) and rval.func.id == "HashMap":
        print(f"Creating HashMap map: {map_name}")
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
        print(create_bpf_map(module, map_name, map_params))
