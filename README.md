# Python-BPF
This is an LLVM IR generator for eBPF program. We use `llvmlite` to generate LLVM IR code from pure Python code. This is then compiled to LLVM object files, which can be loaded into the kernel for execution.

## Development
Step 1. Run `make install` to install the required dependencies.  
Step 2. Run `make` to see the compilation output of the example.

## Authors
- [@r41k0u](https://github.com/r41k0u)
- [@varun-r-mallya](https://github.com/varun-r-mallya)
