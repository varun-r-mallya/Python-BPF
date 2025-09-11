import ast
from llvmlite import ir


def eval_expr(func, module, builder, expr, local_sym_tab, map_sym_tab):
    print(f"Evaluating expression: {expr}")
    if isinstance(expr, ast.Name):
        if expr.id in local_sym_tab:
            var = local_sym_tab[expr.id]
            val = builder.load(var)
            return val
        else:
            print(f"Undefined variable {expr.id}")
            return None
    elif isinstance(expr, ast.Constant):
        if isinstance(expr.value, int):
            return ir.Constant(ir.IntType(64), expr.value)
        elif isinstance(expr.value, bool):
            return ir.Constant(ir.IntType(1), int(expr.value))
        else:
            print("Unsupported constant type")
            return None
    elif isinstance(expr, ast.Call):
        # delayed import to avoid circular dependency
        from .bpf_helper_handler import helper_func_list, handle_helper_call

        if isinstance(expr.func, ast.Name):
            # check deref
            if expr.func.id == "deref":
                print(f"Handling deref {ast.dump(expr)}")
                if len(expr.args) != 1:
                    print("deref takes exactly one argument")
                    return None
                arg = expr.args[0]
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "deref":
                    print("Multiple deref not supported")
                    return None
                if isinstance(arg, ast.Name):
                    if arg.id in local_sym_tab:
                        arg = local_sym_tab[arg.id]
                    else:
                        print(f"Undefined variable {arg.id}")
                        return None
                if arg is None:
                    print("Failed to evaluate deref argument")
                    return None
                val = builder.load(arg)
                return val

            # check for helpers
            if expr.func.id in helper_func_list:
                return handle_helper_call(
                    expr, module, builder, func, local_sym_tab, map_sym_tab)
        elif isinstance(expr.func, ast.Attribute):
            if isinstance(expr.func.value, ast.Call) and isinstance(expr.func.value.func, ast.Name):
                method_name = expr.func.attr
                if method_name in helper_func_list:
                    return handle_helper_call(
                        expr, module, builder, func, local_sym_tab, map_sym_tab)
    print("Unsupported expression evaluation")
    return None


def handle_expr(func, module, builder, expr, local_sym_tab, map_sym_tab):
    """Handle expression statements in the function body."""
    print(f"Handling expression: {ast.dump(expr)}")
    call = expr.value
    if isinstance(call, ast.Call):
        eval_expr(func, module, builder, call, local_sym_tab, map_sym_tab)
    else:
        print("Unsupported expression type")
