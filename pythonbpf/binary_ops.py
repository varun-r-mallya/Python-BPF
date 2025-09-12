import ast
from llvmlite import ir


def recursive_dereferencer(var, builder):
    """ dereference until primitive type comes out"""
    if var.type == ir.PointerType(ir.PointerType(ir.IntType(64))):
        a = builder.load(var)
        return recursive_dereferencer(a, builder)
    elif var.type == ir.PointerType(ir.IntType(64)):
        a = builder.load(var)
        return recursive_dereferencer(a, builder)
    elif var.type == ir.IntType(64):
        return var
    else:
        raise TypeError(f"Unsupported type for dereferencing: {var.type}")

def handle_binary_op(rval, module, builder, var_name, local_sym_tab, map_sym_tab, func):
    print(module)
    left = rval.left
    right = rval.right
    op = rval.op

    # Handle left operand
    if isinstance(left, ast.Name):
        if left.id in local_sym_tab:
            left = recursive_dereferencer(local_sym_tab[left.id], builder)
        else:
            raise SyntaxError(f"Undefined variable: {left.id}")
    elif isinstance(left, ast.Constant):
        left = ir.Constant(ir.IntType(64), left.value)
    else:
        raise SyntaxError("Unsupported left operand type")

    if isinstance(right, ast.Name):
        if right.id in local_sym_tab:
            right = recursive_dereferencer(local_sym_tab[right.id], builder)
        else:
            raise SyntaxError(f"Undefined variable: {right.id}")
    elif isinstance(right, ast.Constant):
        right = ir.Constant(ir.IntType(64), right.value)
    else:
        raise SyntaxError("Unsupported right operand type")

    print(f"left is {left}, right is {right}, op is {op}")

    if isinstance(op, ast.Add):
        builder.store(builder.add(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.Sub):
        builder.store(builder.sub(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.Mult):
        builder.store(builder.mul(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.Div):
        builder.store(builder.sdiv(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.Mod):
        builder.store(builder.srem(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.LShift):
        builder.store(builder.shl(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.RShift):
        builder.store(builder.lshr(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.BitOr):
        builder.store(builder.or_(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.BitXor):
        builder.store(builder.xor(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.BitAnd):
        builder.store(builder.and_(left, right),
                      local_sym_tab[var_name])
    elif isinstance(op, ast.FloorDiv):
        builder.store(builder.udiv(left, right),
                      local_sym_tab[var_name])
    else:
        raise SyntaxError("Unsupported binary operation")
