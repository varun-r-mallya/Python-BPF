// trace_delta.c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#define u64 unsigned long long
// Define the map structure
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u64);
    __type(value, u64);
} last SEC(".maps");

SEC("kprobe/YOUR_PROBE_POINT")  // Replace with actual probe point
int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // Attempt to read stored timestamp
    tsp = bpf_map_lookup_elem(&last, &key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // Output if time is less than 1 second
            bpf_printk("%d\n", delta / 1000000);
        }
        bpf_map_delete_elem(&last, &key);
    }

    // Update stored timestamp
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&last, &key, &ts, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
