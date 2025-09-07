#!/bin/bash
sudo bpftool prog -d load $1 /sys/fs/bpf/tmp && sudo rm -f /sys/fs/bpf/tmp
