#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "common_types.h"
#include "helper.h"
#include "maps.h"


struct net_nat_event_t {
  u8 manip_type;
  __be16 origin_port;
  __be16 target_port;
  u32 origin_addr;
  u32 target_addr;
  u32 rc;
  struct process_info_t proc;
  struct net_ns_meta_t ns_meta;
};

BPF_PERF_EVENT_ARRAY(perf_nfnat_events, 4096)


struct args_nf_nat {
  struct sk_buff *skb;
  struct tuple_t origin;
  u32 maniptype;
};

BPF_HASH_MAP(buffer_nft_nat_args, u32, struct args_nf_nat, 1024)

SEC("kprobe/nf_nat_ipv4_manip_pkt")
int kprobe__nf_nat_ipv4_manip_pkt(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u32 maniptype = PT_REGS_PARM4(ctx);
  u32 skb_addr = (u32)skb;

  struct custom_config_t *config = get_config();
  if (config == NULL || !config->hook_nf_nat)
    return BPF_OK;

  struct tuple_t origin_tuple = helper_get_tuple_from_skb(skb);

  if (!helper_filter_tuple(&origin_tuple, config))
    return BPF_OK;

  // prepare argument
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct args_nf_nat args = {};
  helper_memset(&args, 0, sizeof(args));
  args.skb = skb;
  args.maniptype = maniptype;
  args.origin = helper_get_tuple_from_skb(skb);

  bpf_map_update_elem(&buffer_nft_nat_args, &pid_tgid, &args, BPF_ANY);
  return BPF_OK;
}

SEC("kretprobe/nf_nat_ipv4_manip_pkt")
int kretprobe__nf_nat_ipv4_manip_pkt(struct pt_regs *ctx) {
  bool ret_stus = PT_REGS_RET(ctx);
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct args_nf_nat *args = bpf_hashmap_pop(&buffer_nft_nat_args, &pid_tgid);
  if (!args || !ret_stus) {
    return BPF_OK;
  }

  struct sk_buff *skb = args->skb;
  u64 skb_addr = (u64)skb;
  struct net_nat_event_t event = {};
  helper_memset(&event, 0, sizeof(event));

  struct tuple_t tuple = helper_get_tuple_from_skb(skb);

  if (0 == args->maniptype) { // do_src_nat
    event.origin_addr = args->origin.s_addr;
    event.origin_port = args->origin.s_port;
    event.target_addr = tuple.s_addr;
    event.target_port = tuple.s_port;

  } else { // do_dst_nat
    event.origin_port = args->origin.d_port;
    event.origin_addr = args->origin.d_addr;
    event.target_addr = tuple.d_addr;
    event.target_port = tuple.d_port;
  }

  event.rc = ret_stus;
  event.manip_type = args->maniptype;

  bpf_perf_event_output(ctx, &perf_nfnat_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

  return BPF_OK;
}

