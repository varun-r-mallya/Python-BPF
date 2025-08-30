from llvmlite import ir
import ast

def emit_function(module: ir.Module, license_str: str):
    license_bytes = license_str.encode("utf8") + b"\x00"
    elems = [ir.Constant(ir.IntType(8), b) for b in license_bytes]
    ty = ir.ArrayType(ir.IntType(8), len(elems))

    gvar = ir.GlobalVariable(module, ty, name="LICENSE")

    gvar.initializer = ir.Constant(ty, elems)  # type: ignore

    gvar.align = 1                      # type: ignore
    gvar.linkage = "dso_local"          # type: ignore
    gvar.global_constant = False
    gvar.section = "license"            # type: ignore

    return gvar

def functions_processing(tree, module):
    bpf_functions = []
    helper_functions = []
    for node in tree.body:
        section_name = ""
        if isinstance(node, ast.FunctionDef):
            if len(node.decorator_list) == 1:
                bpf_functions.append(node)
            else:
                if 'helper_functions' not in locals():
                    helper_functions.append(node)
    
    
