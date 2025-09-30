import ast
from llvmlite import ir


def eval_expr(func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab=None, local_var_metadata=None):
    print(f"Evaluating expression: {ast.dump(expr)}")
    print(local_var_metadata)
    if isinstance(expr, ast.Name):
        if expr.id in local_sym_tab:
            var = local_sym_tab[expr.id][0]
            val = builder.load(var)
            return val, local_sym_tab[expr.id][1]  # return value and type
        else:
            print(f"Undefined variable {expr.id}")
            return None
    elif isinstance(expr, ast.Constant):
        if isinstance(expr.value, int):
            return ir.Constant(ir.IntType(64), expr.value), ir.IntType(64)
        elif isinstance(expr.value, bool):
            return ir.Constant(ir.IntType(1), int(expr.value)), ir.IntType(1)
        else:
            print("Unsupported constant type")
            return None
    elif isinstance(expr, ast.Call):
        # delayed import to avoid circular dependency
        from .helper.bpf_helper_handler import helper_func_list, handle_helper_call

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
                        arg = local_sym_tab[arg.id][0]
                    else:
                        print(f"Undefined variable {arg.id}")
                        return None
                if arg is None:
                    print("Failed to evaluate deref argument")
                    return None
                # Since we are handling only name case, directly take type from sym tab
                val = builder.load(arg)
                return val, local_sym_tab[expr.args[0].id][1]

            # check for helpers
            if expr.func.id in helper_func_list:
                return handle_helper_call(
                    expr, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab, local_var_metadata)
        elif isinstance(expr.func, ast.Attribute):
            print(f"Handling method call: {ast.dump(expr.func)}")
            if isinstance(expr.func.value, ast.Call) and isinstance(expr.func.value.func, ast.Name):
                method_name = expr.func.attr
                if method_name in helper_func_list:
                    return handle_helper_call(
                        expr, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab, local_var_metadata)
            elif isinstance(expr.func.value, ast.Name):
                obj_name = expr.func.value.id
                method_name = expr.func.attr
                if obj_name in map_sym_tab:
                    if method_name in helper_func_list:
                        return handle_helper_call(
                            expr, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab, local_var_metadata)
    elif isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name):
            var_name = expr.value.id
            attr_name = expr.attr
            if var_name in local_sym_tab:
                var_ptr, var_type = local_sym_tab[var_name]
                print(f"Loading attribute "
                      f"{attr_name} from variable {var_name}")
                print(f"Variable type: {var_type}, Variable ptr: {var_ptr}")
                print(local_var_metadata)
                if local_var_metadata and var_name in local_var_metadata:
                    metadata = structs_sym_tab[local_var_metadata[var_name]]
                    if attr_name in metadata.fields:
                        gep = metadata.gep(builder, var_ptr, attr_name)
                        val = builder.load(gep)
                        field_type = metadata.field_type(attr_name)
                        return val, field_type
    print("Unsupported expression evaluation")
    return None


def handle_expr(func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab, local_var_metadata):
    """Handle expression statements in the function body."""
    print(f"Handling expression: {ast.dump(expr)}")
    print(local_var_metadata)
    call = expr.value
    if isinstance(call, ast.Call):
        eval_expr(func, module, builder, call, local_sym_tab,
                  map_sym_tab, structs_sym_tab, local_var_metadata)
    else:
        print("Unsupported expression type")
