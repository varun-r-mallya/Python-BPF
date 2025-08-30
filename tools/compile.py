#!/usr/bin/env python3
import argparse, subprocess, os
from pythonbpf import codegen

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="Python BPF program")
    args = parser.parse_args()

    ll_file = os.path.splitext(args.source)[0] + ".ll"
    o_file = os.path.splitext(args.source)[0] + ".o"

    print(f"[+] Compiling {args.source} → {ll_file}")
    codegen.compile_to_ir(args.source, ll_file)

    print("[+] Running llc -march=bpf")
    subprocess.run(["llc", "-march=bpf", "-filetype=obj", ll_file, "-o", o_file], check=True)

if __name__ == "__main__":
    main()
