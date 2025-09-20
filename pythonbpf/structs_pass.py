import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir
from . import dwarf_constants as dc

structs_sym_tab = {}


def structs_proc(tree, module, chunks):
    for cls_node in chunks:
        # Check if this class is a struct
        is_struct = False
        for decorator in cls_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "struct":
                is_struct = True
                break
        if is_struct:
            print(f"Found BPF struct: {cls_node.name}")
            process_bpf_struct(cls_node, module)
            continue
    return structs_sym_tab


def process_bpf_struct(cls_node, module):
    struct_name = cls_node.name
    field_names = []
    field_types = []

    for item in cls_node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            field_names.append(item.target.id)
            field_types.append(ctypes_to_ir(item.annotation.id))

    struct_type = ir.LiteralStructType(field_types)
    structs_sym_tab[struct_name] = {
        "type": struct_type,
        "fields": {name: idx for idx, name in enumerate(field_names)}
    }
    print(f"Created struct {struct_name} with fields {field_names}")
