import ast
from llvmlite import ir
from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)


def recursive_dereferencer(var, builder):
    """dereference until primitive type comes out"""
    # TODO: Not worrying about stack overflow for now
    if isinstance(var.type, ir.PointerType):
        a = builder.load(var)
        return recursive_dereferencer(a, builder)
    elif isinstance(var.type, ir.IntType):
        return var
    else:
        raise TypeError(f"Unsupported type for dereferencing: {var.type}")


def get_operand_value(operand, builder, local_sym_tab):
    """Extract the value from an operand, handling variables and constants."""
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            return recursive_dereferencer(local_sym_tab[operand.id].var, builder)
        raise ValueError(f"Undefined variable: {operand.id}")
    elif isinstance(operand, ast.Constant):
        if isinstance(operand.value, int):
            return ir.Constant(ir.IntType(64), operand.value)
        raise TypeError(f"Unsupported constant type: {type(operand.value)}")
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def handle_binary_op(rval, module, builder, var_name, local_sym_tab, map_sym_tab, func):
    logger.info(f"module {module}")
    op = rval.op

    left = get_operand_value(rval.left, builder, local_sym_tab)
    right = get_operand_value(rval.right, builder, local_sym_tab)
    logger.info(f"left is {left}, right is {right}, op is {op}")

    if isinstance(op, ast.Add):
        builder.store(builder.add(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.Sub):
        builder.store(builder.sub(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.Mult):
        builder.store(builder.mul(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.Div):
        builder.store(builder.sdiv(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.Mod):
        builder.store(builder.srem(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.LShift):
        builder.store(builder.shl(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.RShift):
        builder.store(builder.lshr(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.BitOr):
        builder.store(builder.or_(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.BitXor):
        builder.store(builder.xor(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.BitAnd):
        builder.store(builder.and_(left, right), local_sym_tab[var_name].var)
    elif isinstance(op, ast.FloorDiv):
        builder.store(builder.udiv(left, right), local_sym_tab[var_name].var)
    else:
        raise SyntaxError("Unsupported binary operation")
