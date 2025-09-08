import ast
from llvmlite import ir
from .license_pass import license_processing
from .functions_pass import func_proc
from .maps_pass import maps_proc
# from .constants_pass import constants_processing
from .globals_pass import globals_processing


def find_bpf_chunks(tree):
    """Find all functions decorated with @bpf in the AST."""
    bpf_functions = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id == "bpf":
                    bpf_functions.append(node)
                    break
    return bpf_functions


def processor(source_code, filename, module):
    tree = ast.parse(source_code, filename)
    print(ast.dump(tree, indent=4))

    bpf_chunks = find_bpf_chunks(tree)
    for func_node in bpf_chunks:
        print(f"Found BPF function: {func_node.name}")

    map_sym_tab = maps_proc(tree, module, bpf_chunks)
    func_proc(tree, module, bpf_chunks, map_sym_tab)
    # For now, we will parse the BPF specific parts of AST

    # constants_processing(tree, module)
    license_processing(tree, module)
    globals_processing(tree, module)
    # functions_processing(tree, module)


def compile_to_ir(filename: str, output: str):
    with open(filename) as f:
        source = f.read()

    module = ir.Module(name=filename)
    module.data_layout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
    module.triple = "bpf"

    processor(source, filename, module)
    wchar_size = module.add_metadata([ir.Constant(ir.IntType(32), 1),
                                      "wchar_size",
                                      ir.Constant(ir.IntType(32), 4)])
    frame_pointer = module.add_metadata([ir.Constant(ir.IntType(32), 7),
                                         "frame-pointer",
                                         ir.Constant(ir.IntType(32), 2)])
    module.add_named_metadata("llvm.module.flags", wchar_size)
    module.add_named_metadata("llvm.module.flags", frame_pointer)
    module.add_named_metadata("llvm.ident", ["llvmlite PythonBPF v0.0.0"])

    with open(output, "w") as f:
        f.write(f"source_filename = \"{filename}\"\n")
        f.write(str(module))

    return output
