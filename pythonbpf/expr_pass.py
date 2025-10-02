import ast
from llvmlite import ir
from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)


def eval_expr(
    func,
    module,
    builder,
    expr,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    logger.info(f"Evaluating expression: {ast.dump(expr)}")
    if isinstance(expr, ast.Name):
        if expr.id in local_sym_tab:
            var = local_sym_tab[expr.id].var
            val = builder.load(var)
            return val, local_sym_tab[expr.id].ir_type  # return value and type
        else:
            logger.info(f"Undefined variable {expr.id}")
            return None
    elif isinstance(expr, ast.Constant):
        if isinstance(expr.value, int):
            return ir.Constant(ir.IntType(64), expr.value), ir.IntType(64)
        elif isinstance(expr.value, bool):
            return ir.Constant(ir.IntType(1), int(expr.value)), ir.IntType(1)
        else:
            logger.info("Unsupported constant type")
            return None
    elif isinstance(expr, ast.Call):
        # delayed import to avoid circular dependency
        from pythonbpf.helper import HelperHandlerRegistry, handle_helper_call

        if isinstance(expr.func, ast.Name):
            # check deref
            if expr.func.id == "deref":
                logger.info(f"Handling deref {ast.dump(expr)}")
                if len(expr.args) != 1:
                    logger.info("deref takes exactly one argument")
                    return None
                arg = expr.args[0]
                if (
                    isinstance(arg, ast.Call)
                    and isinstance(arg.func, ast.Name)
                    and arg.func.id == "deref"
                ):
                    logger.info("Multiple deref not supported")
                    return None
                if isinstance(arg, ast.Name):
                    if arg.id in local_sym_tab:
                        arg = local_sym_tab[arg.id].var
                    else:
                        logger.info(f"Undefined variable {arg.id}")
                        return None
                if arg is None:
                    logger.info("Failed to evaluate deref argument")
                    return None
                # Since we are handling only name case, directly take type from sym tab
                val = builder.load(arg)
                return val, local_sym_tab[expr.args[0].id].ir_type

            # check for helpers
            if HelperHandlerRegistry.has_handler(expr.func.id):
                return handle_helper_call(
                    expr,
                    module,
                    builder,
                    func,
                    local_sym_tab,
                    map_sym_tab,
                    structs_sym_tab,
                )
        elif isinstance(expr.func, ast.Attribute):
            logger.info(f"Handling method call: {ast.dump(expr.func)}")
            if isinstance(expr.func.value, ast.Call) and isinstance(
                expr.func.value.func, ast.Name
            ):
                method_name = expr.func.attr
                if HelperHandlerRegistry.has_handler(method_name):
                    return handle_helper_call(
                        expr,
                        module,
                        builder,
                        func,
                        local_sym_tab,
                        map_sym_tab,
                        structs_sym_tab,
                    )
            elif isinstance(expr.func.value, ast.Name):
                obj_name = expr.func.value.id
                method_name = expr.func.attr
                if obj_name in map_sym_tab:
                    if HelperHandlerRegistry.has_handler(method_name):
                        return handle_helper_call(
                            expr,
                            module,
                            builder,
                            func,
                            local_sym_tab,
                            map_sym_tab,
                            structs_sym_tab,
                        )
    elif isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name):
            var_name = expr.value.id
            attr_name = expr.attr
            if var_name in local_sym_tab:
                var_ptr, var_type, var_metadata = local_sym_tab[var_name]
                logger.info(f"Loading attribute {attr_name} from variable {var_name}")
                logger.info(f"Variable type: {var_type}, Variable ptr: {var_ptr}")
                metadata = structs_sym_tab[var_metadata]
                if attr_name in metadata.fields:
                    gep = metadata.gep(builder, var_ptr, attr_name)
                    val = builder.load(gep)
                    field_type = metadata.field_type(attr_name)
                    return val, field_type
    logger.info("Unsupported expression evaluation")
    return None


def handle_expr(
    func,
    module,
    builder,
    expr,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab,
):
    """Handle expression statements in the function body."""
    logger.info(f"Handling expression: {ast.dump(expr)}")
    call = expr.value
    if isinstance(call, ast.Call):
        eval_expr(
            func,
            module,
            builder,
            call,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
    else:
        logger.info("Unsupported expression type")
