import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir
from . import dwarf_constants as dc

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


def create_bpf_map(module, map_name, map_params):
    """Create a BPF map in the module with the given parameters and debug info"""

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
    map_global.initializer = ir.Constant(map_struct_type, None)     # type: ignore
    map_global.section = ".maps"
    map_global.align = 8        # type: ignore

    # Generate debug info for BTF
    create_map_debug_info(module, map_global, map_name, map_params)

    print(f"Created BPF map: {map_name}")
    map_sym_tab[map_name] = map_global
    return map_global

def create_map_debug_info(module, map_global, map_name, map_params):
    """Generate debug information metadata for BPF map"""
    file_metadata = module._file_metadata
    compile_unit = module._debug_compile_unit

    # Create basic type for unsigned int (32-bit)
    uint_type = module.add_debug_info("DIBasicType", {
        "name": "unsigned int",
        "size": 32,
        "encoding": dc.DW_ATE_unsigned
    })

    # Create basic type for unsigned long long (64-bit)
    ulong_type = module.add_debug_info("DIBasicType", {
        "name": "unsigned long long",
        "size": 64,
        "encoding": dc.DW_ATE_unsigned
    })

    # Create array type for map type field (array of 1 unsigned int)
    array_subrange = module.add_debug_info("DISubrange", {"count": 1})
    array_type = module.add_debug_info("DICompositeType", {
        "tag": dc.DW_TAG_array_type,
        "baseType": uint_type,
        "size": 32,
        "elements": [array_subrange]
    })

    # Create pointer types
    type_ptr = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_pointer_type,
        "baseType": array_type,
        "size": 64
    })

    max_entries_ptr = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_pointer_type,
        "baseType": array_type,
        "size": 64
    })

    key_ptr = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_pointer_type,
        "baseType": uint_type,  # Adjust based on actual key type
        "size": 64
    })

    value_ptr = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_pointer_type,
        "baseType": ulong_type,  # Adjust based on actual value type
        "size": 64
    })

    # Create struct members
    # scope field does not appear for some reason
    type_member = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_member,
        "name": "type",
        "file": file_metadata,
        "baseType": type_ptr,
        "size": 64,
        "offset": 0
    })

    max_entries_member = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_member,
        "name": "max_entries",
        "file": file_metadata,
        "baseType": max_entries_ptr,
        "size": 64,
        "offset": 64
    })

    key_member = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_member,
        "name": "key",
        "file": file_metadata,
        "baseType": key_ptr,
        "size": 64,
        "offset": 128
    })

    value_member = module.add_debug_info("DIDerivedType", {
        "tag": dc.DW_TAG_member,
        "name": "value",
        "file": file_metadata,
        "baseType": value_ptr,
        "size": 64,
        "offset": 192
    })

    # Create the struct type
    struct_type = module.add_debug_info("DICompositeType", {
        "tag": dc.DW_TAG_structure_type,
        "file": file_metadata,
        "size": 256,  # 4 * 64-bit pointers
        "elements": [type_member, max_entries_member, key_member, value_member]
    }, is_distinct=True)

    # Create global variable debug info
    global_var = module.add_debug_info("DIGlobalVariable", {
        "name": map_name,
        "scope": compile_unit,
        "file": file_metadata,
        "type": struct_type,
        "isLocal": False,
        "isDefinition": True
    }, is_distinct=True)

    # Create global variable expression
    global_var_expr = module.add_debug_info("DIGlobalVariableExpression", {
        "var": global_var,
        "expr": module.add_debug_info("DIExpression", {})
    })

    # Attach debug info to the global variable
    map_global.set_metadata("dbg", global_var_expr)

    return global_var_expr


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
