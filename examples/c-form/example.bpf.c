#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

int trace_testing(void *ctx)
{
    bpf_printk("THISISACONSTANT");
    bpf_printk("THISISCONSTANT2");
    uint64_t a = 69;
    bpf_printk("%d", a);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    if(ctx){
        trace_testing(ctx);
    } else {
        bpf_printk("THISISANOTHERCONSTANT");
    }
    bpf_trace_printk("execve called\n", 15);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_randomname_exit(void *ctx)
{
    bpf_trace_printk("execve called to exit\n", 15);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
