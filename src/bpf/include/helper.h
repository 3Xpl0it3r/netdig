#ifndef __USER_HELEPER_FUNC_H_
#define __USER_HELEPER_FUNC_H_

#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "common_types.h"

extern int LINUX_KERNEL_VERSION __kconfig;

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
static __always_inline struct tuple_t
helper_get_tuple_from_skb(struct sk_buff *skb) {

  struct tuple_t tuple = {};
  helper_memset(&tuple, 0, sizeof(tuple));

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
  // u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(iphdr, version);
  u16 tmp_data; // tos(8bit) version(高四位 4bit), ihl(低四位 4bit)
  bpf_probe_read_kernel(&tmp_data, 2, (void *)iphdr);
  u8 ip_vsn = (tmp_data & 0x00F0) >> 4;

  if (ip_vsn == 4) {
    struct iphdr *iphdr = (struct iphdr *)(skb_head + network_header);
    bpf_probe_read_kernel(&tuple.s_addr, sizeof(tuple.s_addr),
                          (void *)iphdr + offsetof(struct iphdr, saddr));
    bpf_probe_read_kernel(&tuple.d_addr, sizeof(tuple.d_addr),
                          (void *)iphdr + offsetof(struct iphdr, daddr));
    tuple.l3_protocol = ETH_P_IP;
    bpf_probe_read_kernel(&tuple.l4_protocol, 1,
                          (void *)iphdr + offsetof(struct iphdr, protocol));
  } else if (ip_vsn == 6) {
    struct ipv6hdr *ip6hdr = (struct ipv6hdr *)(skb_head + network_header);
    tuple.l3_protocol = ETH_P_IPV6;
    // todo
  } else {
    // other protocol ,but not tcp nor udp
    goto end;
  }

  if (IPPROTO_TCP == tuple.l4_protocol) {
    struct tcphdr *tcphdr = (struct tcphdr *)(skb_head + transport_header);
    bpf_probe_read_kernel(&tuple.s_port, sizeof(tuple.s_port),
                          (void *)tcphdr + offsetof(struct tcphdr, source));
    bpf_probe_read_kernel(&tuple.d_port, sizeof(tuple.d_port),
                          (void *)tcphdr + offsetof(struct tcphdr, dest));
  } else if (IPPROTO_UDP == tuple.l4_protocol) {
    struct udphdr *udphdr = (struct udphdr *)(skb_head + transport_header);
    bpf_probe_read_kernel(&tuple.d_port, sizeof(tuple.d_port),
                          (void *)udphdr + offsetof(struct tcphdr, dest));
    bpf_probe_read_kernel(&tuple.d_port, sizeof(tuple.d_port),
                          (void *)udphdr + offsetof(struct tcphdr, dest));
  }
end:
  return tuple;
}

static __always_inline struct net_ns_meta_t
helper_get_ns_metadata_from_skb(struct sk_buff *skb) {
  struct net_ns_meta_t meta = {};
  helper_memset(&meta, 0, sizeof(meta));
  struct net_device *device;
  struct sock *sk;

  if (0 == bpf_probe_read_kernel(&device, sizeof(device),
                                 (void *)skb + offsetof(struct sk_buff, dev))) {
    bpf_probe_read_kernel_str(meta.device_name, sizeof(meta.device_name),
                              (void *)device +
                                  offsetof(struct net_device, name));
    bpf_probe_read_kernel(&meta.ifindex, sizeof(meta.ifindex),
                          (void *)device +
                              offsetof(struct net_device, ifindex));
  }

  if (0 != bpf_probe_read_kernel(&sk, sizeof(sk),
                                 (void *)skb + offsetof(struct sk_buff, sk)))
    goto end;

  struct net *possible_net; // this is struct possible_net

  if (0 != bpf_probe_read_kernel(&possible_net, sizeof(possible_net),
                                 (void *)device +
                                     offsetof(struct net_device, nd_net)))
    goto end;

  bpf_probe_read_kernel(&meta.ns_id, sizeof(meta.ns_id),
                        (void *)possible_net + offsetof(struct net, ns) +
                            offsetof(struct ns_common, inum));

end:

  return meta;
}

static __always_inline u64 helper_get_probe_addr(struct pt_regs *ctx) {
  if (LINUX_KERNEL_VERSION > KERNEL_VERSION(5, 15, 0))
    return bpf_get_func_ip(ctx);
  else {
    // x86架构上,通过pt_regs_ip获取到的probe其始地址要不从`/proc/kmallsyms`里面的probe地址多一个字节,因此在这个地方需要减去一个字节
    // 在其他CPU架构上会不会有这种情况暂时还不清楚
    return PT_REGS_IP(ctx) - 1;
  }
}

#endif
