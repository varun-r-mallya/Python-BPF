#!/bin/bash
sudo bpftool prog -d load ./execve.o /sys/fs/bpf/tmp && sudo rm -f /sys/fs/bpf/tmp