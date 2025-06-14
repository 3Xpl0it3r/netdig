## 安装

#### rust环境安装
```bash
# 安装rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装libbpf-cargo
cargo install libbpf-cargo
```

#### 操作系统版本
&emsp;Linux 内核 5.4 或更高版本（支持 BTF）都支持, 低于5.4以下内核参考下面操作系统支持列表

#### 操作系统支持
|操作系统名称|操作系统版本|内核版本|是否信创|
|----|----|----|----|
|BigCloud Enterprise Linux|21.10 (LTS-SP2)|4.19.90-2107.6.0.0100.oe1.bclinux.x86_64|是|
|Rocky Linux|8.10 (Green Obsidian)|4.18.0-553.el8_10.x86_64|否|

#### 编译安装

```bash
git clone https://github.com/3Xpl0it3r/netdig.git
cd netdig
cargo build --release 

# 编译完会在target/release/目录下生成netdig文件
```

## 使用
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

|0xffff8f2e52d8fee8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e52d8fee8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e52d8fee8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e52e4b700| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e52e4b700| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e52e4b700| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e52e4b700| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e52e4b700| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e52e4b700|     0      |        :(00)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  __kfree_skb   |
|0xffff8f2e52e4b900|  /webpod   |    eth0:(06)|  9   |ksoftirqd/0 |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e52e4b900|  /webpod   |    eth0:(06)|  9   |ksoftirqd/0 |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e52e4b900|  /webpod   |    eth0:(06)|  9   |ksoftirqd/0 |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e52e4b900|     0      |        :(00)|  9   |ksoftirqd/0 |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e52e4b200| 4026531992 | docker0:(03)|  9   |ksoftirqd/0 |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e52e4b200| 4026531992 | docker0:(03)|  9   |ksoftirqd/0 |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e52e4b200| 4026531992 | docker0:(03)|  9   |ksoftirqd/0 |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e52e4b200| 4026531992 | docker0:(03)|  9   |ksoftirqd/0 |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e52e4b200| 4026531992 | docker0:(03)|  9   |ksoftirqd/0 |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e97314f00| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e97314f00| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e97314f00| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e97314f00| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e97314f00| 4026531992 | docker0:(03)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e97314f00|     0      |        :(00)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  __kfree_skb   |
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e52e4b200|     0      |        :(00)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  __kfree_skb   |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e97314f00|     0      |        :(00)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e9a90e2e8|     0      |        :(00)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  __kfree_skb   |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90e2e8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e97314f00|     0      |        :(00)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e9a90e2e8|     0      |        :(00)|71071 |    curl    |  172.17.0.2:80    ->  172.17.0.1:57268 |  __kfree_skb   |
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e9a90e2e8|  /webpod   |    eth0:(06)|71071 |    curl    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e9a90e2e8|     0      |        :(00)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e9a90eee8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |     ip_rcv     |
|0xffff8f2e9a90eee8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90eee8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |ip_local_deliver|
|0xffff8f2e9a90eee8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |  nf_hook_slow  |
|0xffff8f2e9a90eee8| 4026531992 | docker0:(03)|70989 |   nginx    |  172.17.0.2:80    ->  172.17.0.1:57268 |   tcp_v4_rcv   |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |     ip_rcv     |
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |ip_local_deliver|
|0xffff8f2e97314f00|  /webpod   |    eth0:(06)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |   tcp_v4_rcv   |
|0xffff8f2e97314f00|     0      |        :(00)|70989 |   nginx    |  172.17.0.1:57268 ->  172.17.0.2:80    |  __kfree_skb   |
|0xffff8f2e9a90eee8|     0      |        :(00)|70999 |    sshd    |192.168.1.16:22    -> 192.168.1.9:59614 |  nf_hook_slow  |
|0xffff8f2e9a90eee8| 4026531992 |  enp0s3:(02)|70999 |    sshd    |192.168.1.16:22    -> 192.168.1.9:59614 |  nf_hook_slow  |
|0xffff8f2e9a90eee8|     0      |        :(00)|66196 |    sshd    |192.168.1.16:22    -> 192.168.1.9:51144 |  nf_hook_slow  |
|0xffff8f2e9a90eee8| 4026531992 |  enp0s3:(02)|66196 |    sshd    |192.168.1.16:22    -> 192.168.1.9:51144 |  nf_hook_slow  |
```
## Trace Netfitler

## Trace Layer 4

## Trace Http Protocol

## Other Protocol Tracing
