#!/bin/bash

PIN_PATH="/sys/fs/bpf/bpf_prog"
FILE="$2"
case "$1" in
    check)
        echo "[*] Checking $FILE"
        echo $(sudo bpftool prog load -d "$FILE" "$PIN_PATH")
        sudo rm -f "$PIN_PATH"
        echo "[+] Verification succeeded"
        ;;
    run)
        echo "[*] Loading and running $FILE"
        sudo bpftool prog loadall "$FILE" "$PIN_PATH" autoattach
        echo "[+] Program loaded. Press Ctrl+C to stop"
        sudo cat /sys/kernel/debug/tracing/trace_pipe
        sudo rm -rf "$PIN_PATH"
        echo "[+] Stopped"
        ;;
    stop)
        echo "[*] Stopping program"
        sudo rm -f "$PIN_PATH"
        echo "[+] Stopped"
        ;;
    *)
        echo "Usage: $0 <check|run|stop> <file.o>"
        echo "Examples:"
        echo "  $0 check program.bpf.o"
        echo "  $0 run program.bpf.o"
        echo "  $0 stop"
        exit 1
        ;;
esac
