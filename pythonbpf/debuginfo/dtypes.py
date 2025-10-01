import llvmlite.ir as ir


class DwarfBehaviorEnum:
    ERROR_IF_MISMATCH = ir.Constant(ir.IntType(32), 1)
    WARNING_IF_MISMATCH = ir.Constant(ir.IntType(32), 2)
    OVERRIDE_USE_LARGEST = ir.Constant(ir.IntType(32), 7)
