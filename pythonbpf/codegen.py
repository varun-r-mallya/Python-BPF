import ast
from llvmlite import ir

def compile_to_ir(filename: str, output: str):
    with open(filename) as f:
        ast.parse(f.read(), filename)

    module = ir.Module(name="pythonbpf")
    func_ty = ir.FunctionType(ir.IntType(64), [], False)
    func = ir.Function(module, func_ty, name="trace_execve")

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    builder.ret(ir.IntType(64)(0))

    with open(output, "w") as f:
        f.write(str(module))

    return output
