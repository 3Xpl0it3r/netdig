#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// map[skb, tuple]
#include "data_types.h"
#include "maps.h"
#include "helper.h"

#include "netfilter.h"
#include "route.h"

BPF_HASH_MAP(skb_trace_event_cache, u64, struct generic_trace_event_t, 4096)

// ip_rcv
SEC("kprobe/ip_rcv_core")
int kprobe__ip_rcv_core(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  struct net_device *dev = (struct net_device *)PT_REGS_PARM2(ctx);
  u64 skb_addr = (u64)skb;

  struct generic_trace_event_t event = {};
  helper_memset(&event, 0, sizeof(event));
  event.trace_mask |= (1u << IP_RCV);
  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, &event, BPF_ANY);

  return BPF_OK;
}

// ip_rcv_finish
SEC("kprobe/ip_rcv_finish")
int kprobe__ip_rcv_finish(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;

  struct generic_trace_event_t *event =
      bpf_map_lookup_elem(&skb_trace_event_cache, &skb_addr);
  if (!event)
    return BPF_OK;

  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, event, BPF_EXIST);
  event->trace_mask |= (1U << IP_RCV_FINISH);

  return BPF_OK;
}

SEC("kprobe/ip_local_deliver")
int kprobe__ip_local_deliver(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;
  struct generic_trace_event_t *event =
      bpf_map_lookup_elem(&skb_trace_event_cache, &skb_addr);
  if (!event)
    return BPF_OK;

  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, event, BPF_EXIST);
  event->trace_mask |= (1U << IP_LOCAL_DELIVER);
  return BPF_OK;
}

SEC("kprobe/ip_local_deliver_finish")
int kprobe__ip_local_deliver_finish(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;
  struct generic_trace_event_t *event =
      bpf_map_lookup_elem(&skb_trace_event_cache, &skb_addr);
  if (!event)
    return BPF_OK;

  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, event, BPF_EXIST);
  event->trace_mask |= (1U << IP_LOCAL_DELIVER_FINISH);
  return BPF_OK;
}

SEC("kprobe/tcp_v4_rcv")
int kprobe__tcp_v4_rcv(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;
  struct generic_trace_event_t *event =
      bpf_map_lookup_elem(&skb_trace_event_cache, &skb_addr);
  if (!event)
    return BPF_OK;

  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, event, BPF_EXIST);
  event->trace_mask |= (1U << KFREE_SKB);
  return BPF_OK;
}

SEC("kretprobe/tcp_v4_rcv")
int kretprobe__tcp_v4_rcv(struct pt_regs *ctx) {
  int rc = (int)PT_REGS_RC(ctx);
  return BPF_OK;
}

SEC("kprobe/__kfree_skb")
int kprobe____kfree_skb(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;
  struct generic_trace_event_t *event =
      bpf_map_lookup_elem(&skb_trace_event_cache, &skb_addr);
  if (!event)
    return BPF_OK;

  bpf_map_update_elem(&skb_trace_event_cache, &skb_addr, event, BPF_EXIST);
  event->trace_mask |= (1U << KFREE_SKB);

  return BPF_OK;
}

char _license[] SEC("license") = "GPL";
