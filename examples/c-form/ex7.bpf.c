// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_entry {
  short unsigned int type;
  unsigned char flags;
  unsigned char preempt_count;
  int pid;
};

struct trace_event_raw_sys_enter {
  struct trace_entry ent;
  long int id;
  long unsigned int args[6];
  char __data[0];
};

struct event {
  __u32 pid;
  __u32 uid;
  __u64 ts;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid_entry(struct trace_event_raw_sys_enter *ctx) {
  struct event data = {};

  // Extract UID from the syscall arguments
  data.uid = (unsigned int)ctx->args[0];
  data.ts = bpf_ktime_get_ns();
  data.pid = bpf_get_current_pid_tgid() >> 32;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
