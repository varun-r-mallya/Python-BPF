import ast
from llvmlite import ir

def bpf_printk_emitter(call, module, builder, func):
    # Handle print statement
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            fmt_str = arg.value + "\n" + "\0"
            # Create a global variable for the format string
            fmt_gvar = ir.GlobalVariable(
                module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=f"{func.name}____fmt")
            fmt_gvar.global_constant = True
            fmt_gvar.initializer = ir.Constant(     # type: ignore
                ir.ArrayType(ir.IntType(8), len(fmt_str)),
                bytearray(fmt_str.encode("utf8"))
            )
            fmt_gvar.linkage = "internal"
            fmt_gvar.align = 1      # type: ignore

            # Cast the global variable to i8*
            fmt_ptr = builder.bitcast(
                fmt_gvar, ir.PointerType())

            # Call bpf_trace_printk (assumed to be at address 6)
            fn_type = ir.FunctionType(ir.IntType(
                64), [ir.PointerType(), ir.IntType(32)], var_arg=True)
            fn_ptr_type = ir.PointerType(fn_type)
            fn_addr = ir.Constant(ir.IntType(64), 6)
            fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

            # Call the function
            builder.call(fn_ptr, [fmt_ptr, ir.Constant(
                ir.IntType(32), len(fmt_str))], tail=True)