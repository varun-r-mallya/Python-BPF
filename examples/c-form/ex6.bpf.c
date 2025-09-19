// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


#define TASK_COMM_LEN 16

// Define output data structure
struct data_t {
    __u32 pid;
    __u64 ts;
    char comm[TASK_COMM_LEN];
};

// Define a perf event output map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_clone")
int hello(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    // Get PID (lower 32 bits of the 64-bit value returned)
    data.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Get timestamp
    data.ts = bpf_ktime_get_ns();
    
    // Get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Submit data to userspace via perf event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &data, sizeof(data));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
