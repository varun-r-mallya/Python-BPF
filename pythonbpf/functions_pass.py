from llvmlite import ir
import ast


def emit_function(module: ir.Module, name: str):
    ret_type = ir.IntType(32)
    ptr_type = ir.PointerType()
    func_ty = ir.FunctionType(ret_type, [ptr_type])

    func = ir.Function(module, func_ty, name)

    param = func.args[0]
    param.add_attribute("nocapture")

    func.attributes.add("nounwind")
#    func.attributes.add("\"frame-pointer\"=\"all\"")
#    func.attributes.add("no-trapping-math", "true")
#    func.attributes.add("stack-protector-buffer-size", "8")

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    fmt_gvar = module.get_global("hello.____fmt")

    if fmt_gvar is None:
        # If you haven't created the format string global yet
        print("Warning: Format string global not found")
    else:
        # Cast integer 6 to function pointer type
        fn_type = ir.FunctionType(ir.IntType(
            64), [ptr_type, ir.IntType(32)], var_arg=True)
        fn_ptr_type = ir.PointerType(fn_type)
        fn_addr = ir.Constant(ir.IntType(64), 6)
        fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)
        # Call the function
        builder.call(fn_ptr, [fmt_gvar, ir.Constant(ir.IntType(32), 14)])

    builder.ret(ir.Constant(ret_type, 0))

    func.return_value.add_attribute("noundef")
    func.linkage = "dso_local"
    func.section = "kprobe/sys_clone"
    print("function emitted:", name)
    return func


def get_probe_string(func_node):
    """Extract the probe string from the decorator of the function node."""
    # TODO: right now we have the whole string in the section decorator
    # But later we can implement typed tuples for tracepoints and kprobes
    # For helper functions, we return "helper"

    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "section" and len(decorator.args) == 1:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    return "helper"


def process_func_body(module, builder, func_node, func):
    """Process the body of a bpf function"""
    # TODO: A lot.  We just have print -> bpf_trace_printk for now
    did_return = False

    for stmt in func_node.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if isinstance(call.func, ast.Name) and call.func.id == "print":
                # Handle print statement
                for arg in call.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        fmt_str = arg.value + "\n"
                        # Create a global variable for the format string
                        fmt_gvar = ir.GlobalVariable(
                            module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=f"{func.name}____fmt")
                        fmt_gvar.global_constant = True
                        fmt_gvar.initializer = ir.Constant(
                            ir.ArrayType(ir.IntType(8), len(fmt_str)),
                            bytearray(fmt_str.encode("utf8"))
                        )
                        fmt_gvar.linkage = "internal"
                        fmt_gvar.align = 1

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
        elif isinstance(stmt, ast.Return):
            if stmt.value is None:
                builder.ret(ir.Constant(ir.IntType(32), 0))
                did_return = True
            elif isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "c_int32" and len(stmt.value.args) == 1 and isinstance(stmt.value.args[0], ast.Constant) and isinstance(stmt.value.args[0].value, int):
                builder.ret(ir.Constant(ir.IntType(
                    32), stmt.value.args[0].value))
                did_return = True
            else:
                print("Unsupported return value")
    if not did_return:
        builder.ret(ir.Constant(ir.IntType(32), 0))


def process_bpf_chunk(func_node, module):
    """Process a single BPF chunk (function) and emit corresponding LLVM IR."""

    func_name = func_node.name

    # TODO: parse return type
    ret_type = ir.IntType(32)

    # TODO: parse parameters
    param_types = []
    if func_node.args.args:
        # Assume first arg to be ctx
        param_types.append(ir.PointerType())

    func_ty = ir.FunctionType(ret_type, param_types)
    func = ir.Function(module, func_ty, func_name)

    func.linkage = "dso_local"
    func.attributes.add("nounwind")

    if func_node.args.args:
        # Only look at the first argument for now
        param = func.args[0]
        param.add_attribute("nocapture")

    func.section = get_probe_string(func_node)

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)

    process_func_body(module, builder, func_node, func)

    print(func)
    print(module)
    return func


def func_proc(tree, module, chunks):
    for func_node in chunks:
        func_type = get_probe_string(func_node)
        print(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(func_node, module)


def functions_processing(tree, module):
    bpf_functions = []
    helper_functions = []
    for node in tree.body:
        section_name = ""
        if isinstance(node, ast.FunctionDef):
            if len(node.decorator_list) == 1:
                bpf_functions.append(node)
                node.end_lineno
            else:
                # IDK why this check is needed, but whatever
                if 'helper_functions' not in locals():
                    helper_functions.append(node)

    # TODO: implement helpers first

    for func in bpf_functions:
        dec = func.decorator_list[0]
        if (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Name)
            and dec.func.id == "section"
            and len(dec.args) == 1
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            section_name = dec.args[0].value
        else:
            print(f"ERROR: Invalid decorator for function {func.name}")
            continue

        # TODO: parse arguments and return type
        emit_function(module, func.name + "func")
