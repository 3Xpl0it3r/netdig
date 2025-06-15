#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// map[skb, tuple]
#include "include/common_types.h"
#include "include/maps.h"

struct route_event_t {
  int ret_stus;
  __be32 daddr;
  __be32 saddr;
};

BPF_PERF_EVENT_ARRAY(perf_event_net_route_map, 4096)

struct do_route_args {
  struct sk_buff *skb;
  __be32 daadr;
  __be32 saddr;
};

BPF_HASH_MAP(buffer_do_route, u32, struct do_route_args, 1024)


SEC("kprobe/trace_router")
int kprobe__trace_router(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff*)PT_REGS_PARM1(ctx);
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

SEC("kretprobe/trace_router")
int kretprobe__trace_router(struct pt_regs *ctx) {
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

  bpf_perf_event_output(ctx, &perf_event_net_route_map, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

  return BPF_OK;
}
