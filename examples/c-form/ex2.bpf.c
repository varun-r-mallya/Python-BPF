#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#define u64 unsigned long long
#define u32 unsigned int

SEC("xdp")
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello, World!\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
