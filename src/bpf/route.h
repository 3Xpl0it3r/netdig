
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "vmlinux.h"

// map[skb, tuple]
#include "data_types.h"
#include "maps.h"

struct do_route_args {
  struct sk_buff *skb;
  __be32 daadr;
  __be32 saddr;
};

/* struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(struct do_route_args));
  __uint(max_entries, 1024);
} map_route_buffer SEC(".maps"); */
BPF_HASH_MAP(buffer_do_route, u32, struct do_route_args, 1024)

SEC("kprobe/ip_route_input_noref")
int kprobe__ip_route_input_noref(struct pt_regs *ctx) {
  struct sk_buff *skb = PT_REGS_PARM1(ctx);
  __be32 daddr = PT_REGS_PARM2(ctx);
  __be32 saddr = PT_REGS_PARM3(ctx);

  struct do_route_args args = {
      .skb = skb,
      .saddr = saddr,
      .daadr = daddr,
  };

  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&buffer_do_route, &pid_tgid, &args, BPF_ANY);

  return BPF_OK;
}

SEC("kretprobe/ip_route_input_noref")
int kretprobe__ip_route_input_noref(struct pt_regs *ctx) {
  int rc = PT_REGS_RET(ctx);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct do_route_args *args = bpf_hashmap_pop(&buffer_do_route, &pid_tgid);
  if (!args) {
    return BPF_OK;
  }

  struct route_event_t event = {
      .ret_stus = rc,
      .daddr = args->daadr,
      .saddr = args->saddr,
  };

  bpf_perf_event_output(ctx, &perf_route_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

  return BPF_OK;
}
