## Usage
```bash
l0calh0st@lima-ubuntu22:/Users/l0calh0st/Git/Rust/netdig$ sudo ./target/debug/netdig --help
A tool using eBPF to trace and diagnose container network issues

Usage: netdig [OPTIONS]

Options:
      --addr <ADDR>  
      --port <PORT>  
      --nat          
      --netfilter    
      --skb_trace    
  -h, --help         Print help
  -V, --version      Print version
l0calh0st@lima-ubuntu22:/Users/l0calh0st/Git/Rust/netdig$
```

## Trace Layer 3
```bash
l0calh0st@lima-ubuntu22:/Users/l0calh0st/Git/Rust/netdig$ sudo ./target/debug/netdig --addr 172.17.0.2
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  ip_rcv_core   |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |ip_local_deliver|
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |   tcp_v4_rcv   |
|0xffff9f09c30b8500| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
|0xffff9f09c30b8500| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff9f09c30b8500| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff9f09c30b8500| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff9f09c30b8900|     0      |        :(00)|  172.17.0.2:80    ->  172.17.0.1:37914 |  __kfree_skb   |
|0xffff9f09c57b80e0|     0      |        :(00)|  172.17.0.1:37914 ->  172.17.0.2:80    |  nf_hook_slow  |
|0xffff9f09c57b80e0| 4026531840 | docker0:(03)|  172.17.0.1:37914 ->  172.17.0.2:80    |  nf_hook_slow  |
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  ip_rcv_core   |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |ip_local_deliver|
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f09c30b8900| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |   tcp_v4_rcv   |
|0xffff9f09c30b8900|     0      |        :(00)|  172.17.0.2:80    ->  172.17.0.1:37914 |  __kfree_skb   |
|0xffff9f0ac08bcee0|     0      |        :(00)|  172.17.0.2:80    ->  172.17.0.1:37914 |  __kfree_skb   |
|0xffff9f0ac08bcee0|     0      |        :(00)|  172.17.0.2:80    ->  172.17.0.1:37914 |  __kfree_skb   |
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff9f09c57b80e0| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff9f09c57b80e0|     0      |        :(00)|  172.17.0.1:37914 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  ip_rcv_core   |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |ip_local_deliver|
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |   tcp_v4_rcv   |
|0xffff9f09c3183100| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
|0xffff9f09c3183100| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff9f09c3183100| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff9f09c3183100|     0      |        :(00)|  172.17.0.1:37914 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  ip_rcv_core   |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |ip_local_deliver|
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |  nf_hook_slow  |
|0xffff9f0ac08bcee0| 4026531840 | docker0:(03)|  172.17.0.2:80    ->  172.17.0.1:37914 |   tcp_v4_rcv   |
|0xffff9f09c3183100| /pod_nginx |    eth0:(02)|  172.17.0.1:37914 ->  172.17.0.2:80    |  ip_rcv_core   |
```
## Trace Netfitler

## Trace Layer 4

## Trace Http Protocol

## Other Protocol Tracing
