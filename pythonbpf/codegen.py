import ast
from llvmlite import ir
from .license_pass import license_processing

def processor(source_code, filename, module):
    tree = ast.parse(source_code, filename)
    license_processing(tree, module)

def compile_to_ir(filename: str, output: str):
    with open(filename) as f:
        source = f.read()

    module = ir.Module(name=filename)
    module.data_layout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
    module.triple = "bpf"

    processor(source, filename, module)

    with open(output, "w") as f:
        f.write(str(module))

    return output
