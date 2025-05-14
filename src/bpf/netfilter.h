#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "vmlinux.h"

#include "data_types.h"
#include "helper.h"
#include "maps.h"

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5 /* Deprecated, for userspace nf_queue compatibility. */
#define NF_MAX_VERDICT NF_STOP

#define NF_NAT_TYPE_SRC 0
#define NF_NAT_TYPE_DST 1

// nft_pktinfo 在vmlinux里面没有暴露出来
struct nft_pktinfo {
  struct sk_buff *skb;
  const struct nf_hook_state *state;
  u8 flags;
  u8 tprot;
  u16 fragoff;
  u16 thoff;
  u16 inneroff;
};

// nft_tables 在vmlinux.h 里面没有暴露出这个结构体
struct nft_table {
  struct list_head list;
  struct rhltable chains_ht;
  struct list_head chains;
  struct list_head sets;
  struct list_head objects;
  struct list_head flowtables;
  u64 hgenerator;
  u64 handle;
  u32 use;
  u16 family : 6, flags : 8, genmask : 2;
  u32 nlpid;
  char *name;
  u16 udlen;
  u8 *udata;
  u8 validate_state;
};

// nft_rule_blob 在vmlinux.h 里面没有暴露出这个结构体
struct _dymmy_nft_rule {};

// nft_chain 在vmlinux.h 里面没有暴露出这个结构体
struct nft_chain {
  struct _dymmy_nft_rule *rules_gen_0;
  struct _dymmy_nft_rule *rules_gen_1;
  struct list_head rules;
  struct list_head list;
  struct rhlist_head rhlhead;
  struct nft_table *table;
  u64 handle;
  u32 use;
  u8 flags : 5, bound : 1, genmask : 2;
  char *name;
  u16 udlen;
  u8 *udata;

  /* Only used during control plane commit phase: */
  struct _dymmy_nft_rule *rules_next;
};

struct args_do_nft_chain {
  struct sk_buff *skb;
  struct nft_pktinfo *pkt;
  struct nft_chain *chain;
};
BPF_HASH_MAP(buffer_do_nft_chain_args, u32, struct args_do_nft_chain, 1024)

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

  struct tuple_t origin_tuple = {};
  helper_memset(&origin_tuple, 0, sizeof(origin_tuple));
  helper_skb_extract_5tuple(skb, &origin_tuple);

  if (!helper_filter_tuple(&origin_tuple, config))
    return BPF_OK;

  // prepare argument
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct args_nf_nat args = {};
  helper_memset(&args, 0, sizeof(args));
  args.skb = skb;
  args.maniptype = maniptype;
  helper_skb_extract_5tuple(skb, &args.origin);

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

  struct sk_uff *skb = args->skb;
  u64 skb_addr = (u64)skb;
  struct nf_nat_event_t event = {};
  helper_memset(&event, 0, sizeof(event));

  struct tuple_t tuple = {};
  helper_memset(&tuple, 0, sizeof(tuple));
  helper_skb_extract_5tuple(skb, &tuple);

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

// nftables
SEC("kprobe/nft_do_chain")
int kprobe__nft_do_chain(struct pt_regs *ctx) {
  struct nft_chain *chain = (struct nft_chain *)PT_REGS_PARM2(ctx);
  struct nft_pktinfo *pkt = (struct nft_pktinfo *)PT_REGS_PARM1(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sk_buff *skb = NULL;

  bpf_probe_read_kernel(&skb, sizeof(skb),
                        (void *)pkt + offsetof(struct nft_pktinfo, skb));
  struct args_do_nft_chain args = {
      .skb = skb,
      .pkt = pkt,
      .chain = chain,
  };

  struct tuple_t tuple = {};
  helper_memset(&tuple, 0, sizeof(tuple));
  helper_skb_extract_5tuple(skb, &tuple);

  struct custom_config_t *cfg = get_config();
  if (!cfg || !cfg->hook_nf_filter || !helper_filter_tuple(&tuple, cfg))
    return BPF_OK;
  bpf_map_update_elem(&buffer_do_nft_chain_args, &pid_tgid, &args, BPF_ANY);

  return BPF_OK;
}

SEC("kretprobe/nft_do_chain")
int kretprobe__nft_do_chain(struct pt_regs *ctx) {
  struct args_do_nft_chain *args;
  struct nft_trace_t *trace;
  struct nft_table *table;
  struct nf_hook_state *state;
  struct net *net;
  struct sk_buff *skb;

  u32 verdict_code;
  char *name;
  u64 pid_tgid;

  verdict_code = PT_REGS_RC(ctx);

  pid_tgid = bpf_get_current_pid_tgid();
  args = bpf_hashmap_pop(&buffer_do_nft_chain_args, &pid_tgid);
  if (!args)
    return BPF_OK;

  struct tuple_t tuple = {};
  helper_memset(&tuple, 0, sizeof(tuple));
  helper_skb_extract_5tuple(args->skb, &tuple);

  struct nf_filter_event_t event = {};
  helper_memset(&event, 0, sizeof(event));
  event.verdict = verdict_code;
  event.proc.pid = pid_tgid >> 32;
  event.tuple = tuple;

  bpf_get_current_comm(event.proc.comm, sizeof(event.proc.comm));

  // get table name
  bpf_probe_read_kernel(&table, sizeof(table),
                        (void *)args->chain +
                            offsetof(struct nft_chain, table));
  bpf_probe_read_kernel(&name, sizeof(name),
                        (void *)table + offsetof(struct nft_table, name));
  bpf_probe_read_kernel_str(&event.table_name, sizeof(event.table_name), name);

  // get chain name
  bpf_probe_read_kernel(&name, sizeof(name),
                        (void *)args->chain + offsetof(struct nft_chain, name));
  bpf_probe_read_kernel_str(&event.chain_name, sizeof(event.chain_name), name);

  bpf_probe_read_kernel(&state, sizeof(state),
                        (void *)args->pkt +
                            offsetof(struct nft_pktinfo, state));
  bpf_probe_read_kernel(&net, sizeof(net),
                        (void *)state + offsetof(struct nf_hook_state, net));

  // get network namespace id
  bpf_probe_read_kernel(&event.ns_meta.ns_id, sizeof(event.ns_meta.ns_id),
                        (void *)net + offsetof(struct net, ns) +
                            offsetof(struct ns_common, inum));

  // get device_name
  bpf_probe_read_kernel(&name, sizeof(name),
                        (void *)net + offsetof(struct net, loopback_dev) +
                            offsetof(struct net_device, name));
  bpf_probe_read_kernel_str(&event.ns_meta.device_name,
                            sizeof(event.ns_meta.device_name), name);

  bpf_perf_event_output(ctx, &perf_netfilter_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

  return BPF_OK;
}
