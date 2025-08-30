from llvmlite import ir
import ast

def emit_license(module: ir.Module, license_str: str):
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

def license_processing(tree, module):
    """Process the LICENSE assignment in the given AST tree and return the section name"""
    count = 0
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "LICENSE":
                    if count == 0:
                        count += 1
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            emit_license(module, node.value.value)
                            return "LICENSE"
                        else:
                            print("ERROR: LICENSE must be a string literal")
                            return None
                    else:
                        print("ERROR: LICENSE already assigned")
                        return None
