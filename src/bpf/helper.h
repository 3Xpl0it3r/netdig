#ifndef __USER_HELEPER_FUNC_H_
#define __USER_HELEPER_FUNC_H_

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "vmlinux.h"

#include "data_types.h"

// this code is copied from
// https://stackoverflow.com/questions/71212540/how-do-i-print-ip-addresses-with-bpf-trace-printk,
// author is : Maciek Leks
#define BE32_TO_IPV4(ip_value) ({ be32_to_ipv4((ip_value), (char[32]){}); })
static char *be32_to_ipv4(__be32 ip_value, char *ip_buffer) {
  __u64 ip_data[4];

  ip_data[3] = ((__u64)(ip_value >> 24) & 0xFF);
  ip_data[2] = ((__u64)(ip_value >> 16) & 0xFF);
  ip_data[1] = ((__u64)(ip_value >> 8) & 0xFF);
  ip_data[0] = ((__u64)ip_value & 0xFF);

  bpf_snprintf(ip_buffer, 16, "%d.%d.%d.%d", ip_data, 4 * sizeof(__u64));
  return ip_buffer;
}

// 执行基于五元组过滤
// 如果config->should_filter为false ，则不做任何过滤，hook所有的流量
// 如果config->should_filter为true, 则基于五元组做过滤
// 如果config->should_filter为true,
// 但是源&目的地址为0,源&目的端口为0,则hook所有流量 返回true
// 意味着可以追踪该hook点, 返回false 则直接退出,不追踪该hook点
static __always_inline bool
helper_filter_tuple(struct tuple_t *tuple, struct custom_config_t *config) {

  if (config->addr != 0 && config->addr != tuple->s_addr &&
      config->addr != tuple->d_addr)
    return false;

  if (config->port != 0 && config->port != tuple->s_port &&
      config->port != tuple->d_port)
    return false;

  return true;
}

static __always_inline void helper_memcpy(void *dst, const void *src,
                                          unsigned long size) {
  __builtin_memcpy(dst, src, size);
}

static __always_inline void helper_memset(void *dst, int data,
                                          unsigned long size) {
  __builtin_memset(dst, 0, size);
}

// 从skb里面提取五元组信息
static __always_inline bool helper_skb_extract_5tuple(struct sk_buff *skb,
                                                      struct tuple_t *tuple) {

  void *skb_head = {0};
  bpf_probe_read_kernel(&skb_head, sizeof(skb_head),
                        (void *)skb + offsetof(struct sk_buff, head));

  // load offset of headers
  u16 network_header = 0;
  u16 transport_header = 0;
  bpf_probe_read_kernel(&network_header, sizeof(network_header),
                        (void *)skb + offsetof(struct sk_buff, network_header));
  bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
                        (void *)skb +
                            offsetof(struct sk_buff, transport_header));

  struct iphdr *iphdr = (struct iphdr *)(skb_head + network_header);
  u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(iphdr, version);

  if (ip_vsn == 4) {
    struct iphdr *iphdr = (struct iphdr *)(skb_head + network_header);
    bpf_probe_read_kernel(&tuple->s_addr, sizeof(tuple->s_addr),
                          (void *)iphdr + offsetof(struct iphdr, saddr));
    bpf_probe_read_kernel(&tuple->d_addr, sizeof(tuple->d_addr),
                          (void *)iphdr + offsetof(struct iphdr, daddr));
    tuple->l3_protocol = ETH_P_IP;
    bpf_probe_read_kernel(&tuple->l4_protocol, 1,
                          (void *)iphdr + offsetof(struct iphdr, protocol));
  } else if (ip_vsn == 6) {
    struct ipv6hdr *ip6hdr = (struct ipv6hdr *)(skb_head + network_header);
    tuple->l3_protocol = ETH_P_IPV6;
    // todo
  } else {
    // other protocol ,but not tcp nor udp
    return false;
  }

  if (IPPROTO_TCP == tuple->l4_protocol) {
    struct tcphdr *tcphdr = (struct tcphdr *)(skb_head + transport_header);
    bpf_probe_read_kernel(&tuple->s_port, sizeof(tuple->s_port),
                          (void *)tcphdr + offsetof(struct tcphdr, source));
    bpf_probe_read_kernel(&tuple->d_port, sizeof(tuple->d_port),
                          (void *)tcphdr + offsetof(struct tcphdr, dest));

  } else if (IPPROTO_UDP == tuple->l4_protocol) {
    struct udphdr *udphdr = (struct udphdr *)(skb_head + transport_header);
    bpf_probe_read_kernel(&tuple->d_port, sizeof(tuple->d_port),
                          (void *)udphdr + offsetof(struct tcphdr, dest));
    bpf_probe_read_kernel(&tuple->d_port, sizeof(tuple->d_port),
                          (void *)udphdr + offsetof(struct tcphdr, dest));
  } else {
    return false;
  }
  return true;
}

#endif
