#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} rb SEC(".maps");

//struct msg {
//    u32 pid;
//    char comm[16];
//};

//SEC("tracepoint/syscalls/sys_enter_execve")
//int handle_execve(struct trace_event_raw_sys_enter *ctx)
//{
//    struct msg *m;
//    m = bpf_ringbuf_reserve(&rb, sizeof(*m), 0);
//    if (!m)
//        return 0;
//
//    m->pid = bpf_get_current_pid_tgid() >> 32;
//    bpf_get_current_comm(&m->comm, sizeof(m->comm));
//    bpf_ringbuf_submit(m, 0);
//    return 0;
//}

//char LICENSE[] SEC("license") = "GPL";
