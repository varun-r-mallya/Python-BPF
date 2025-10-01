// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

// Define the structure to be sent via ringbuf
struct event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    char comm[16];  // Process name
};

// Define the ringbuffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Tracepoint for execve system calls
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    struct event *e;
    __u64 pid_tgid;
    __u64 uid_gid;

    // Reserve space in the ringbuffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill the struct with data
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit the event to ringbuffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
