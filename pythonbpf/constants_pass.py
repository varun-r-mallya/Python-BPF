from llvmlite import ir
import ast

def emit_constants(module: ir.Module, constant_str: str, name: str):
    constant_bytes = constant_str.encode("utf8") + b"\x00"
    elems = [ir.Constant(ir.IntType(8), b) for b in constant_bytes]
    ty = ir.ArrayType(ir.IntType(8), len(elems))

    gvar = ir.GlobalVariable(module, ty, name=name)

    gvar.initializer = ir.Constant(ty, elems)  # type: ignore

    gvar.align = 1                      # type: ignore
    gvar.linkage = "internal"           # type: ignore
    gvar.global_constant = True

    return gvar

def constants_processing(tree, module):
    """Process string constants in the given AST tree and emit them to rodata"""
    constant_count = 0
    current_function = None

    class ConstantVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            nonlocal current_function
            old_function = current_function
            current_function = node.name
            for child in ast.iter_child_nodes(node):
                if not (hasattr(node, 'decorator_list') and child in node.decorator_list):
                    self.visit(child)
            current_function = old_function

        def visit_Constant(self, node):
            nonlocal constant_count
            if isinstance(node.value, str) and current_function is not None:
                if constant_count == 0:
                    constant_name = f"{current_function}.____fmt"
                else:
                    constant_name = f"{current_function}.____fmt.{constant_count}"
                emit_constants(module, node.value, constant_name)
                constant_count += 1
            self.generic_visit(node)

    visitor = ConstantVisitor()
    visitor.visit(tree)

    return constant_count