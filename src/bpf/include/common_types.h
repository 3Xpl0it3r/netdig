#include "vmlinux.h"
#include "constants.h"

#ifndef __DATA_TYPES_H_
#define __DATA_TYPES_H_


struct process_info_t {
  u32 pid;
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

// user_opts用户态程序传进来参数
struct custom_config_t {
  u32 addr;    // 根据原地址过滤
  __be16 port; // 原端口过滤
  bool hook_nf_nat;
  bool hook_nf_filter;
  bool hook_net_l3;
};

#endif // end __DATA_TYPES_H_
