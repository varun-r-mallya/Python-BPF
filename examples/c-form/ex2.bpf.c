#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_clone")
int hello(struct pt_regs *ctx) {
    bpf_printk("Hello, World!");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
