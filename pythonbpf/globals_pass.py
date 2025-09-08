from llvmlite import ir
import ast


def emit_globals(module: ir.Module, names: list[str]):
    """
    Emit the @llvm.compiler.used global given a list of function/global names.
    """
    ptr_ty = ir.PointerType()
    used_array_ty = ir.ArrayType(ptr_ty, len(names))

    elems = []
    for name in names:
        # Reuse existing globals (like LICENSE), don't redeclare
        if name in module.globals:
            g = module.get_global(name)
        else:
            g = ir.GlobalValue(module, ptr_ty, name)
        elems.append(g.bitcast(ptr_ty))

    gv = ir.GlobalVariable(module, used_array_ty, "llvm.compiler.used")
    gv.linkage = "appending"
    gv.initializer = ir.Constant(used_array_ty, elems)  # type: ignore
    gv.section = "llvm.metadata"


def globals_processing(tree, module: ir.Module):
    collected = ["LICENSE"]

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Name)
                    and dec.func.id == "section"
                    and len(dec.args) == 1
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    collected.append(node.name)

                elif isinstance(dec, ast.Name) and dec.id == "bpfglobal":
                    collected.append(node.name)

                elif isinstance(dec, ast.Name) and dec.id == "map":
                    collected.append(node.name)

    emit_globals(module, collected)
