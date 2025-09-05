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
