import ast
from llvmlite import ir
from .license_pass import license_processing
from .functions_pass import func_proc
from .maps_pass import maps_proc
from .globals_pass import globals_processing
import os


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

    license_processing(tree, module)
    globals_processing(tree, module)


def compile_to_ir(filename: str, output: str):
    with open(filename) as f:
        source = f.read()

    module = ir.Module(name=filename)
    module.data_layout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
    module.triple = "bpf"

    if not hasattr(module, '_debug_compile_unit'):
        module._file_metadata = module.add_debug_info("DIFile", {       # type: ignore
            "filename": filename,
            "directory": os.path.dirname(filename)
        })
        
        module._debug_compile_unit = module.add_debug_info("DICompileUnit", {       # type: ignore
            "language": 29,  # DW_LANG_C11
            "file": module._file_metadata,      # type: ignore
            "producer": "PythonBPF DSL Compiler",
            "isOptimized": True,
            "runtimeVersion": 0,
            "emissionKind": 1,
            "splitDebugInlining": False,
            "nameTableKind": 0
        }, is_distinct=True)

        module.add_named_metadata("llvm.dbg.cu", module._debug_compile_unit)        # type: ignore

    processor(source, filename, module)

    wchar_size = module.add_metadata([ir.Constant(ir.IntType(32), 1),
                                      "wchar_size",
                                      ir.Constant(ir.IntType(32), 4)])
    frame_pointer = module.add_metadata([ir.Constant(ir.IntType(32), 7),
                                         "frame-pointer",
                                         ir.Constant(ir.IntType(32), 2)])
    # Add Debug Info Version (3 = DWARF v3, which LLVM expects)
    debug_info_version = module.add_metadata([ir.Constant(ir.IntType(32), 2),
                                              "Debug Info Version",
                                              ir.Constant(ir.IntType(32), 3)])

    # Add explicit DWARF version (4 is common, works with LLVM BPF backend)
    dwarf_version = module.add_metadata([ir.Constant(ir.IntType(32), 2),
                                         "Dwarf Version",
                                         ir.Constant(ir.IntType(32), 4)])

    module.add_named_metadata("llvm.module.flags", wchar_size)
    module.add_named_metadata("llvm.module.flags", frame_pointer)
    module.add_named_metadata("llvm.module.flags", debug_info_version)
    module.add_named_metadata("llvm.module.flags", dwarf_version)

    module.add_named_metadata("llvm.ident", ["llvmlite PythonBPF v0.0.1"])

    with open(output, "w") as f:
        f.write(f"source_filename = \"{filename}\"\n")
        f.write(str(module))
        f.write("\n")

    return output
