#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#define u64 unsigned long long
#define u32 unsigned int

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} last SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(struct pt_regs *ctx) {
    bpf_printk("Hello, World!\n");
    u64 b;
    u64 a = 3 * b;
    bpf_printk("%d", a);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
