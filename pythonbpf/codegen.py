import ast
from llvmlite import ir

def parser(source_code, filename):
    tree = ast.parse(source_code, filename)

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            print("Function:", node.name)
            for dec in node.decorator_list:
                print("  Decorator AST:", ast.dump(dec))

def compile_to_ir(filename: str, output: str):
    with open(filename) as f:
        parser(f.read(), filename)
    module = ir.Module(name=filename)
    module.data_layout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
    module.triple = "bpf"

    func_ty = ir.FunctionType(ir.IntType(64), [], False)
    func = ir.Function(module, func_ty, name="trace_execve")

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    builder.ret(ir.IntType(64)(0))

    with open(output, "w") as f:
        f.write(str(module))

    return output
