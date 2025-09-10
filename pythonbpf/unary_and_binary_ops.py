import ast
from llvmlite import ir

def handle_binary_op(rval, module, builder, func, local_sym_tab, map_sym_tab):
    left = rval.left
    right = rval.right
    op = rval.op

    if isinstance(left, ast.Name):
        left = local_sym_tab[left.id]
    elif isinstance(left, ast.Constant):
        left = ir.Constant(ir.IntType(64), left.value)
    else:
        print("Unsupported left operand type")

    if isinstance(right, ast.Name):
        right = local_sym_tab[right.id]
    elif isinstance(right, ast.Constant):
        right = ir.Constant(ir.IntType(64), right.value)
    else:
        SyntaxError("Unsupported right operand type")

    if isinstance(op, ast.Add):
        result = builder.add(left, right)
    elif isinstance(op, ast.Sub):
        result = builder.sub(left, right)
    elif isinstance(op, ast.Mult):
        result = builder.mul(left, right)
    elif isinstance(op, ast.Div):
        result = builder.sdiv(left, right)
    else:
        result = "fuck type errors"
        SyntaxError("Unsupported binary operation")

    return result

def handle_unary_op(rval, module, builder, func, local_sym_tab, map_sym_tab):
    print("UNARY ASSIGNMENT DOES NOT WORK")
    return
    # TODO: heavy fixxing needed
    operand = rval.gay
    op = rval.op
    if isinstance(operand, ast.Name):
        operand = local_sym_tab[operand.id]
    elif isinstance(operand, ast.Constant):
        operand = ir.Constant(ir.IntType(64), operand.value)
    else:
        SyntaxError("Unsupported operand type")

    if isinstance(op, ast.UAdd):
        result = builder.add(ir.Constant(ir.IntType(64), 0), operand)
    elif isinstance(op, ast.USub):
        result = builder.sub(ir.Constant(ir.IntType(64), 0), operand)
    else:
        result = "all my homies hate type errors"
        SyntaxError("Unsupported unary operation")

    return result
