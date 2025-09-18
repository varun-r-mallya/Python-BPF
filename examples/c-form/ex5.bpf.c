#define __TARGET_ARCH_arm64

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Map: key = struct request*, value = u64 timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct request *);
    __type(value, u64);
    __uint(max_entries, 1024);
} start SEC(".maps");

// Attach to kprobe for blk_start_request
SEC("kprobe/blk_start_request")
int BPF_KPROBE(trace_start, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &req, &ts, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
