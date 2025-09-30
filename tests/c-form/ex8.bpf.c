// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/blkdev.h>
#define __TARGET_ARCH_aarch64
#define u64 unsigned long long

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

SEC("kprobe/blk_start_request")
int BPF_KPROBE(trace_start_req, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &req, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(trace_start_mq, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &req, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/blk_account_io_completion")
int BPF_KPROBE(trace_completion, struct request *req)
{
    u64 *tsp, delta;

    tsp = bpf_map_lookup_elem(&start, &req);
    if (tsp) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_printk("%d %x %d\n", req->__data_len,
                  req->cmd_flags, delta / 1000);
        bpf_map_delete_elem(&start, &req);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
