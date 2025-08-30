#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    bpf_printk("execve called\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
