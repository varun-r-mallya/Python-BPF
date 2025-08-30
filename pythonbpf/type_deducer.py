import ctypes
from llvmlite import ir

def ctypes_to_ir(ctype):
    if ctype is ctypes.c_int32:
        return ir.IntType(32)
    if ctype is ctypes.c_int64:
        return ir.IntType(64)
    if ctype is ctypes.c_uint8:
        return ir.IntType(8)
    if ctype is ctypes.c_double:
        return ir.DoubleType()
    if ctype is ctypes.c_float:
        return ir.FloatType()

    # pointers
    if hasattr(ctype, "_type_") and hasattr(ctype, "_length_"):
        # ctypes array
        return ir.ArrayType(ctypes_to_ir(ctype._type_), ctype._length_)

    # if hasattr(ctype, "_type_") and issubclass(ctype, ctypes._Pointer):
    #     return ir.PointerType(ctypes_to_ir(ctype._type_))

    # structs
    if issubclass(ctype, ctypes.Structure):
        fields = [ctypes_to_ir(f[1]) for f in ctype._fields_]
        return ir.LiteralStructType(fields)

    raise NotImplementedError(f"No mapping for {ctype}")
