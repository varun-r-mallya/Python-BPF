import ast
from llvmlite import ir
from .debuginfo import dwarf_constants as dc, DebugInfoGenerator

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
    return map_sym_tab


BPF_MAP_MAPPINGS = {
    "HASH": 1,                # BPF_MAP_TYPE_HASH
    "PERF_EVENT_ARRAY": 4,    # BPF_MAP_TYPE_PERF_EVENT_ARRAY
}


def create_bpf_map(module, map_name, map_params):
    """Create a BPF map in the module with the given parameters and debug info"""

    map_type_str = map_params.get("type", "HASH")
    map_type = BPF_MAP_MAPPINGS.get(map_type_str)

    # Create the anonymous struct type for BPF map
    map_struct_type = ir.LiteralStructType(
        [ir.PointerType() for _ in range(len(map_params))])

    # Create the global variable
    map_global = ir.GlobalVariable(module, map_struct_type, name=map_name)
    map_global.linkage = 'dso_local'
    map_global.global_constant = False
    map_global.initializer = ir.Constant(        # type: ignore
        map_struct_type, None)
    map_global.section = ".maps"
    map_global.align = 8        # type: ignore

    # Generate debug info for BTF
    create_map_debug_info(module, map_global, map_name, map_params)

    print(f"Created BPF map: {map_name}")
    map_sym_tab[map_name] = map_global
    return map_global


def create_map_debug_info(module, map_global, map_name, map_params):
    """Generate debug information metadata for BPF map"""
    generator = DebugInfoGenerator(module)

    #TODO: remove these
    file_metadata = module._file_metadata
    compile_unit = module._debug_compile_unit


    uint_type = generator.get_uint32_type()
    ulong_type = generator.get_uint64_type()

    # Create array type for map type field (array of 1 unsigned int)
    array_type = generator.create_array_type(uint_type, BPF_MAP_MAPPINGS[map_params.get("type", "HASH")])

    # Create pointer types
    type_ptr = generator.create_pointer_type(array_type, 64)
    key_ptr = generator.create_pointer_type(array_type if "key_size" in map_params else ulong_type, 64)
    value_ptr = generator.create_pointer_type(array_type if "value_size" in map_params else ulong_type, 64)

    elements_arr = []

    # Create struct members
    # scope field does not appear for some reason
    cnt = 0
    for elem in map_params:
        if elem == "max_entries":
            continue
        if elem == "type":
            ptr = type_ptr
        elif "key" in elem:
            ptr = key_ptr
        else:
            ptr = value_ptr
        #TODO: the best way to do this is not 64, but get the size each time. this will not work for structs.
        member = generator.create_struct_member(elem, ptr, cnt * 64)
        elements_arr.append(member)
        cnt += 1

    if "max_entries" in map_params:
        max_entries_array = generator.create_array_type(uint_type, map_params["max_entries"])
        max_entries_ptr = generator.create_pointer_type(max_entries_array, 64)
        max_entries_member = generator.create_struct_member("max_entries", max_entries_ptr, cnt * 64)
        elements_arr.append(max_entries_member)

    # Create the struct type
    struct_type = generator.create_struct_type(elements_arr, 64 * len(elements_arr), is_distinct=True)

    # Create global variable debug info
    global_var = generator.create_global_var_debug_info(map_name, struct_type, is_local=False)

    # Attach debug info to the global variable
    map_global.set_metadata("dbg", global_var)

    return global_var


def process_hash_map(map_name, rval, module):
    print(f"Creating HashMap map: {map_name}")
    map_params: dict[str, object] = {"type": "HASH"}

    # Assuming order: key_type, value_type, max_entries
    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
        map_params["key"] = rval.args[0].id
    if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
        map_params["value"] = rval.args[1].id
    if len(rval.args) >= 3 and isinstance(rval.args[2], ast.Constant):
        const_val = rval.args[2].value
        if isinstance(const_val, (int, str)):  # safe check
            map_params["max_entries"] = const_val

    for keyword in rval.keywords:
        if keyword.arg == "key" and isinstance(keyword.value, ast.Name):
            map_params["key"] = keyword.value.id
        elif keyword.arg == "value" and isinstance(keyword.value, ast.Name):
            map_params["value"] = keyword.value.id
        elif keyword.arg == "max_entries" and isinstance(keyword.value, ast.Constant):
            const_val = keyword.value.value
            if isinstance(const_val, (int, str)):
                map_params["max_entries"] = const_val

    print(f"Map parameters: {map_params}")
    return create_bpf_map(module, map_name, map_params)


def process_perf_event_map(map_name, rval, module):
    print(f"Creating PerfEventArray map: {map_name}")
    map_params = {"type": "PERF_EVENT_ARRAY"}

    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
        map_params["key_size"] = rval.args[0].id
    if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
        map_params["value_size"] = rval.args[1].id

    for keyword in rval.keywords:
        if keyword.arg == "key_size" and isinstance(keyword.value, ast.Name):
            map_params["key_size"] = keyword.value.id
        elif keyword.arg == "value_size" and isinstance(keyword.value, ast.Name):
            map_params["value_size"] = keyword.value.id

    print(f"Map parameters: {map_params}")
    return create_bpf_map(module, map_name, map_params)


def process_bpf_map(func_node, module):
    """Process a BPF map (a function decorated with @map)"""
    map_name = func_node.name
    print(f"Processing BPF map: {map_name}")

    BPF_MAP_TYPES = {"HashMap": process_hash_map,            # BPF_MAP_TYPE_HASH
                     "PerfEventArray": process_perf_event_map,   # BPF_MAP_TYPE_PERF_EVENT_ARRAY
                     }

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
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name):
        if rval.func.id in BPF_MAP_TYPES:
            handler = BPF_MAP_TYPES[rval.func.id]
            handler(map_name, rval, module)
        else:
            print(f"Unknown map type {rval.func.id}, defaulting to HashMap")
            process_hash_map(map_name, rval, module)
    else:
        raise ValueError("Function under @map must return a map")
