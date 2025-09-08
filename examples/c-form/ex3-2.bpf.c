#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define u64 unsigned long long

// Define the map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1);
} last SEC(".maps");

// Handler for syscall entry
SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
    bpf_printk("entered");
    bpf_printk("multi constant support");
    return 0;
}

// Handler for syscall exit
SEC("tracepoint/syscalls/sys_exit_execve")
long hello_again(void *ctx) {
    bpf_printk("exited");

    // Create a key for map lookup
    u64 key = 0;

    // Simple lookup without conditionals
    u64 *tsp = bpf_map_lookup_elem(&last, &key);

    // Get current timestamp
    u64 ts = bpf_ktime_get_ns();

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
