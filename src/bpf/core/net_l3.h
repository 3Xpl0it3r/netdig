#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// map[skb, tuple]
#include "include/common_types.h"
#include "include/maps.h"
#include "include/helper.h"
#include "include/cus_error.h"

// sk_buffer
struct net_l3_event_t {
  int errno;
  u64 probe_addr;
  u64 skb_addr;
  struct tuple_t tuple;
  struct net_ns_meta_t net_meta;
  struct process_info_t process_info;
};

BPF_HASH_MAP(net_l3_skb_trace_buffer, u64, u8, 4096);

BPF_PERF_EVENT_ARRAY(perf_event_net_l3_map, 4096)

static __always_inline void report_net_l3_event(struct pt_regs *ctx,
                                                struct sk_buff *skb) {
  /* int ifindex = BPF_CORE_READ(skb, dev, ifindex);
  bpf_printk("debug %d", ifindex); */
  struct net_device *dev;
  bpf_probe_read_kernel(&dev, sizeof(dev),
                        (void *)skb + offsetof(struct sk_buff, dev));
  if (dev != NULL) {
    int ifindex = 0;
    char name[16];
    bpf_probe_read_kernel(&ifindex, sizeof(ifindex),
                          (void *)dev + offsetof(struct net_device, ifindex));
    bpf_probe_read_kernel_str(name, sizeof(name),
                              (void *)dev + offsetof(struct net_device, name));
  }

  struct net_l3_event_t event = {};
  event.tuple = helper_get_tuple_from_skb(skb);
  event.probe_addr = helper_get_probe_addr(ctx);
  event.net_meta = helper_get_ns_metadata_from_skb(skb);
  event.skb_addr = (u64)skb;
  event.errno =
      (struct sk_buff *)PT_REGS_RET(ctx) == NULL ? L3_ERR_FAILED : L3_ERR_OK;
  event.process_info = helper_get_process_info();
  bpf_perf_event_output(ctx, &perf_event_net_l3_map, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));
}

SEC("kprobe/trace_l3_skb_start")
int kprobe__trace_l3_skb_srart(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  struct custom_config_t *cfg = get_config();
  if (!cfg)
    return BPF_OK;
  struct tuple_t tuple = helper_get_tuple_from_skb(skb);
  if (!helper_filter_tuple(&tuple, cfg))
    return BPF_OK;
  struct net_ns_meta_t meta = {};
  helper_memset(&meta, 0, sizeof(meta));
  u8 flag = 0;
  bpf_map_update_elem(&net_l3_skb_trace_buffer, &skb, &flag, BPF_ANY);
  struct net_l3_event_t event = {};
  event.tuple = tuple;
  event.skb_addr = (u64)skb;
  event.probe_addr = helper_get_probe_addr(ctx);
  event.net_meta = helper_get_ns_metadata_from_skb(skb);
  event.errno =
      (struct sk_buff *)PT_REGS_RET(ctx) == NULL ? L3_ERR_FAILED : L3_ERR_OK;
  event.process_info = helper_get_process_info();
  bpf_perf_event_output(ctx, &perf_event_net_l3_map, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));
  return BPF_OK;
}

// (int)(struct sk_buff *skb)
SEC("kprobe/trace_l3_skb_prog_0")
int kprobe__trace_l3_skb_prog_0(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  if (!bpf_map_lookup_elem(&net_l3_skb_trace_buffer, &skb))
    return BPF_OK;
  report_net_l3_event(ctx, skb);
  return BPF_OK;
}

SEC("kprobe/trace_l3_skb_end")
int kprobe__trace_l3_skb_end(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u64 skb_addr = (u64)skb;
  if (!bpf_hashmap_pop(&net_l3_skb_trace_buffer, &skb_addr))
    return BPF_OK;
  report_net_l3_event(ctx, skb);
  return BPF_OK;
}
