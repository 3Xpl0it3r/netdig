#include "vmlinux.h"
#include "constants.h"

#ifndef __DATA_TYPES_H_
#define __DATA_TYPES_H_

struct tuple_t;
struct skb_meta_t;
struct net_netfilter_event_t;
union addr;

enum net_flow_directive {
  NET_DIRECTIVE_IN,
  NET_DIRECTIVE_OUT,
};

enum nf_verdict_t {
  NF_DROP,   // 0
  NF_ACCEPT, // 1
  NF_STOLEN, // 2
  NF_QUEUE,  // 3
  NF_REPEAT, // 4
  NF_STOP,
};

enum trace_code_t {
  start = 0,
  IP_RCV_IN,
  NF_INET_PRE_ROUTING_IN,

  end
};

struct proc_meta_t {
  int pid;
  char comm[TASK_COMM_LEN];
};

struct net_ns_meta_t {
  char device_name[IFNAMSIZ];
  int ifindex;
  unsigned int ns_id;
};

// skb_tuple_t 五元组 # todo 暂时只处理v4情况
struct tuple_t {
  u8 l4_protocol;
  u16 l3_protocol;
  __be16 s_port;
  __be16 d_port;
  u32 s_addr;
  u32 d_addr;
};

// sk_buffer
struct net_l3_event_t {
  int errno;
  u64 probe_addr;
  u64 skb_addr;
  struct tuple_t tuple;
  struct net_ns_meta_t net_meta;
};

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
  struct proc_meta_t proc;
};

struct net_nat_event_t {
  u8 manip_type;
  __be16 origin_port;
  __be16 target_port;
  u32 origin_addr;
  u32 target_addr;
  u32 rc;
  struct proc_meta_t proc;
  struct net_ns_meta_t ns_meta;
};

struct route_event_t {
  int ret_stus;
  __be32 daddr;
  __be32 saddr;
};

// user_opts用户态程序传进来参数
struct custom_config_t {
  u32 addr;    // 根据原地址过滤
  __be16 port; // 原端口过滤
  bool hook_nf_nat;
  bool hook_nf_filter;
  bool hook_net_l3;
};

#endif // end __DATA_TYPES_H_
