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
            continue
    return structs_sym_tab
