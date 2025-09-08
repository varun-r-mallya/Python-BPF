import ast
from llvmlite import ir


def bpf_ktime_get_ns_emitter(call, module, builder, func):
    pass


def bpf_printk_emitter(call, module, builder, func):
    if not hasattr(func, "_fmt_counter"):
        func._fmt_counter = 0

    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            fmt_str = arg.value + "\n" + "\0"
            fmt_name = f"{func.name}____fmt{func._fmt_counter}"
            func._fmt_counter += 1

            fmt_gvar = ir.GlobalVariable(
                module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=fmt_name)
            fmt_gvar.global_constant = True
            fmt_gvar.initializer = ir.Constant(     # type: ignore
                ir.ArrayType(ir.IntType(8), len(fmt_str)),
                bytearray(fmt_str.encode("utf8"))
            )
            fmt_gvar.linkage = "internal"
            fmt_gvar.align = 1      # type: ignore

            fmt_ptr = builder.bitcast(fmt_gvar, ir.PointerType())

            fn_type = ir.FunctionType(ir.IntType(
                64), [ir.PointerType(), ir.IntType(32)], var_arg=True)
            fn_ptr_type = ir.PointerType(fn_type)
            fn_addr = ir.Constant(ir.IntType(64), 6)
            fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

            builder.call(fn_ptr, [fmt_ptr, ir.Constant(
                ir.IntType(32), len(fmt_str))], tail=True)
