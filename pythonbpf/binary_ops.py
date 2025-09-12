import ast
from llvmlite import ir

def handle_binary_op(rval, module, builder, var_name, local_sym_tab, map_sym_tab):
    print(module)
    left = rval.left
    right = rval.right
    op = rval.op

    # Handle left operand
    if isinstance(left, ast.Name):
        if left.id in local_sym_tab:
            left = builder.load(local_sym_tab[left.id])
        else:
            raise SyntaxError(f"Undefined variable: {left.id}")
    elif isinstance(left, ast.Constant):
        left = ir.Constant(ir.IntType(64), left.value)
    else:
        raise SyntaxError("Unsupported left operand type")

    if isinstance(right, ast.Name):
        if right.id in local_sym_tab:
            right = builder.load(local_sym_tab[right.id])  # Dereference the pre-assigned value
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
    else:
        raise SyntaxError("Unsupported binary operation")
