import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir


def is_bpf_struct(cls_node):
    return any(
        isinstance(decorator, ast.Name) and decorator.id == "struct"
        for decorator in cls_node.decorator_list
    )


def structs_proc(tree, module, chunks):
    """ Process all class definitions to find BPF structs """
    structs_sym_tab = {}
    for cls_node in chunks:
        if is_bpf_struct(cls_node):
            print(f"Found BPF struct: {cls_node.name}")
            struct_info = process_bpf_struct(cls_node, module)
            structs_sym_tab[cls_node.name] = struct_info
    return structs_sym_tab


def process_bpf_struct(cls_node, module):
    """ Process a single BPF struct definition """

    field_names = []
    field_types = []

    for item in cls_node.body:
        #
        # field syntax:
        # class struct_example:
        #     num: c_uint64
        #
        if isinstance(item, ast.AnnAssign):
            if isinstance(item.target, ast.Name):
                print(f"Field: {item.target.id}, Type: "
                      f"{ast.dump(item.annotation)}")
                field_names.append(item.target.id)
                if isinstance(item.annotation, ast.Call):
                    if isinstance(item.annotation.func, ast.Name):
                        if item.annotation.func.id == "str":
                            # This is a char array with fixed length
                            # TODO: For now assume str is always with constant
                            field_types.append(ir.ArrayType(
                                ir.IntType(8), item.annotation.args[0].value))
                        else:
                            field_types.append(
                                ctypes_to_ir(item.annotation.id))
        else:
            print(f"Unsupported struct field: {ast.dump(item)}")
            return

    curr_offset = 0
    for ftype in field_types:
        if isinstance(ftype, ir.IntType):
            fsize = ftype.width // 8
            alignment = fsize
        elif isinstance(ftype, ir.ArrayType):
            fsize = ftype.count * (ftype.element.width // 8)
            alignment = ftype.element.width // 8
        elif isinstance(ftype, ir.PointerType):
            fsize = 8
            alignment = 8
        else:
            print(f"Unsupported field type in struct {cls_node.name}")
            return
        padding = (alignment - (curr_offset % alignment)) % alignment
        curr_offset += padding
        curr_offset += fsize
    final_padding = (8 - (curr_offset % 8)) % 8
    total_size = curr_offset + final_padding

    struct_type = ir.LiteralStructType(field_types)
    structs_sym_tab[cls_node.name] = {
        "type": struct_type,
        "fields": {name: idx for idx, name in enumerate(field_names)},
        "size": total_size,
        "field_types": field_types,
    }
    print(f"Created struct {cls_node.name} with fields {field_names}")
