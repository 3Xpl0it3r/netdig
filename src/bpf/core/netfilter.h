#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "include/common_types.h"
#include "include/helper.h"
#include "include/maps.h"

// netfilter metadata
struct net_netfilter_event_t {
  u8 nf_hook_ops_type; // 0 ==  only print logo; 1 == xtables, 2 == Nftables  3
                       // == common
  u8 hook;
  u16 num_hook_entries;
  char table_name[XT_TABLE_MAXNAMELEN];
  char chain_name[XT_TABLE_MAXNAMELEN];
  u32 verdict;
  u32 delay;
  char in[IFNAMSIZ];
  char out[IFNAMSIZ];
  struct tuple_t tuple;
  struct net_ns_meta_t ns_meta;
  struct process_info_t proc;
};

BPF_PERF_EVENT_ARRAY(perf_event_net_netfilter_map, 4096)

struct netfilter_nft_trace_args {
  struct sk_buff *skb;
  struct nft_pktinfo *pkt;
  struct nft_chain *chain;
};

BPF_HASH_MAP(netfilter_nft_trace_buffer, u32, struct netfilter_nft_trace_args,
             1024)
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

// nftables
SEC("kprobe/nft_do_chain")
int kprobe__nft_do_chain(struct pt_regs *ctx) {
  struct nft_chain *chain = (struct nft_chain *)PT_REGS_PARM2(ctx);
  struct nft_pktinfo *pkt = (struct nft_pktinfo *)PT_REGS_PARM1(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sk_buff *skb = NULL;

  bpf_probe_read_kernel(&skb, sizeof(skb),
                        (void *)pkt + offsetof(struct nft_pktinfo, skb));
  struct netfilter_nft_trace_args args = {
      .skb = skb,
      .pkt = pkt,
      .chain = chain,
  };

  struct tuple_t tuple = helper_get_tuple_from_skb(skb);

  struct custom_config_t *cfg = get_config();
  if (!cfg || !cfg->hook_nf_filter || !helper_filter_tuple(&tuple, cfg))
    return BPF_OK;
  bpf_map_update_elem(&netfilter_nft_trace_buffer, &pid_tgid, &args, BPF_ANY);

  return BPF_OK;
}

SEC("kretprobe/nft_do_chain")
int kretprobe__nft_do_chain(struct pt_regs *ctx) {
  struct netfilter_nft_trace_args *args;
  struct nft_trace_t *trace;
  struct nft_table *table;
  struct net *net;

  u32 verdict_code;
  char *name;
  u64 pid_tgid;

  verdict_code = PT_REGS_RC(ctx);

  pid_tgid = bpf_get_current_pid_tgid();
  args = bpf_hashmap_pop(&netfilter_nft_trace_buffer, &pid_tgid);
  if (!args || !args->skb)
    return BPF_OK;

  struct tuple_t tuple = helper_get_tuple_from_skb(args->skb);

  struct net_netfilter_event_t event = {};
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

  struct net_ns_meta_t ns_meta = helper_get_ns_metadata_from_skb(args->skb);
  event.ns_meta = ns_meta;

  bpf_perf_event_output(ctx, &perf_event_net_netfilter_map, BPF_F_CURRENT_CPU,
                        &event, sizeof(event));

  return BPF_OK;
}
