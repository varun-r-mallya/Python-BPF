#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

void test_function() {
    bpf_printk("test_function called");
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    bpf_printk("execve called");
    bpf_printk("execve2 called");
    test_function();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
