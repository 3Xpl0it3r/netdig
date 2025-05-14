use std::cell::LazyCell;
use std::collections::HashMap;
use std::fs;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use std::{fmt, slice, u8};

use anyhow::{anyhow, Result};
use chrono::offset::MappedLocalTime;
use chrono::prelude::*;

use bollard::Docker;
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, PerfBufferBuilder};
use libc::{c_char, htonl, htons, ntohl, ntohs};
use plain::Plain;

mod netdig {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netdig.skel.rs"
    ));
}

use netdig::*;
use tokio::runtime::Runtime;

#[derive(clap::Parser)]
#[command(name = "netdig")]
#[command(bin_name = "netdig")]
#[command(version="v0.0.1(2025-05-14)", about="A tool using eBPF to trace and diagnose container network issues", long_about = None)]
struct Cli {
    #[arg(long)]
    addr: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long = "nat", group = "hook")]
    hook_ns_nat: bool,
    #[arg(long = "netfilter", group = "hook")]
    hook_ns_filter: bool,
}

impl Into<Configuration> for Cli {
    fn into(self) -> Configuration {
        let mut cfg = Configuration::default();
        if self.addr.is_some() {
            let addr = Ipv4Addr::from_str(self.addr.as_ref().unwrap())
                .unwrap()
                .to_bits();
            cfg.addr = htonl(addr);
        }
        if self.port.is_some() {
            cfg.port = htons(self.port.unwrap());
        }
        cfg.hook_nf_nat = self.hook_ns_nat;
        cfg.hook_nf_filter = self.hook_ns_filter;
        cfg
    }
}

// configure that will pass to ebpf
#[repr(C)]
#[derive(Default)]
struct Configuration {
    addr: u32,
    port: u16,
    hook_nf_nat: bool,
    hook_nf_filter: bool,
}

impl Configuration {
    #[inline]
    fn set_port(&mut self, port: u16) {
        self.port = htons(port)
    }
    #[inline]
    fn get_port(&self) -> u16 {
        ntohs(self.port)
    }
    #[inline]
    fn set_v4_addr(&mut self, ip_str: &str) -> Result<()> {
        let s_addr: u32 = Ipv4Addr::from_str(ip_str)?.into();
        self.addr = s_addr.to_be();
        Ok(())
    }
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        let bptr = self as *const _ as *const u8;
        let bsize = std::mem::size_of_val(self);
        unsafe { slice::from_raw_parts(bptr, bsize) }
    }
}

// Some constants about cri paths
const DEFAULT_CRI_RUNTIME_ENDPOINTS: [&'static str; 3] = [
    "unix:///run/containerd/containerd.sock",
    "unix:///run/crio/crio.sock",
    "unix:///var/run/cri-dockerd.sock",
];
const DEFAULT_DOCKER_ENDPOINT: &'static str = "unix:///var/run/docker.sock";

// Store the id of network namespace <-> container name mapping
static CONTAINER_NETNS_CACHE: LazyLock<HashMap<u64, String>> =
    LazyLock::new(|| init_container_ns());
fn init_container_ns() -> HashMap<u64, String> {
    let mut ns_cache = HashMap::<u64, String>::new();

    ns_cache.insert(0, "root_ns".to_owned());
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
         let docker = Docker::connect_with_local_defaults().unwrap(); 
         let containers:Vec<String> = docker.list_containers::<String>(None).await.unwrap().iter().filter_map(|c|{
             c.state.as_ref().map(|sts| {
                 if sts.eq("running") == true {
                     c.id.as_ref().cloned()
                 }else {
                     None
                 }
             })
         }).map(|c|c.unwrap()).collect();
         
         for c in containers.iter(){
             let cs = docker.inspect_container(c, None).await.unwrap();
             let name=cs.name.clone().unwrap();
             let sanboxkey = cs.network_settings.as_ref().unwrap().sandbox_key.as_ref().unwrap().to_owned();
             let ns_id = fs::metadata(sanboxkey.as_str()).unwrap().ino();
             ns_cache.insert(ns_id, name);
         }

    });
    ns_cache
}

enum NfHookOpType {
    NfHookOpUndefined = 0,
    NfHookOpNfTables,
}

enum TraceMask {
  IpRcv = 0, // 0
  IpRcvFinish = 1,
  IpLocalDeliver = 2,
  IpLocalDeliverFinish = 3,
  TcpV4Rcv = 4,
  // NETFILTER
  IpForward = 5,
  IpForwardFinish = 6,

  TcpTransmitSkb = 7,
  IpQueueXmit = 8,
  IpRouteOutputPorts = 9, // 路由
  IpLocalOut = 10,
  IpLocalOutFinish = 11,

  IpOutput = 12,
  IpFinishOutput = 13,

  NeighOutput = 14,
  DevQueueXmit = 15,

  KfreeSkb = 16,

}


// Some constants
const XT_TABLE_MAXNAMELEN: usize = 32;
const IFNAMESIZ: usize = 16;
const TASK_COMM_LEN: usize = 16;

fn nf_hook_name(hook: u8) -> &'static str {
    match hook {
        0 => "NF_INET_PRE_ROUTING",
        1 => "NF_INET_LOCAL_IN",
        2 => "NF_INET_FORWARD",
        3 => "NF_INET_LOCAL_OUT",
        4 => "NF_INET_POST_ROUTING",
        5 => "NF_INET_NUMHOOKS",
        6 => "NF_INET_INGRESS",
        _ => "UN_KNOWN",
    }
}

fn nf_hook_verdict(ret_code: u32) -> &'static str {
    match ret_code {
        0 => "NF_DROP",
        1 => "NF_ACCEPT",
        2 => "NF_STOLEN",
        3 => "NF_QUEUE",
        4 => "NF_REPEAT",
        5 => "NF_STOP",
        6 => "NF_MAX_VERDICT",
        _ => "UN_KNOWN",
    }
}

#[repr(C)]
struct ProcInfo {
    pid: i32,
    comm: [u8; TASK_COMM_LEN],
}

// Tuple struct represent 5 tuple
#[repr(C)]
struct Tuple {
    l4_protocol: u8,
    l3_protocol: u16,
    s_port: u16,
    d_port: u16,
    s_addr: u32,
    d_addr: u32,
}

// fmt::Display[#TODO] (should add some comments)
impl fmt::Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}->{}:{}",
            Ipv4Addr::from(ntohl(self.s_addr)),
            ntohs(self.s_port),
            Ipv4Addr::from(ntohl(self.d_addr)),
            ntohs(self.d_port)
        )
    }
}

#[repr(C)]
struct NetNsInfo {
    device_name: [u8; IFNAMESIZ],
    ns_id: u32,
}

// Netfilter nat event
#[repr(C)]
struct NfNatEvent {
    manip_type: u8,
    origin_port: u16,
    target_port: u16,
    origin_addr: u32,
    target_addr: u32,
    rc: u32,
}

impl NfNatEvent {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const NfNatEvent) };
    }
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Self = Self::load(data);
        println!("{}", event);
    }
}

impl fmt::Display for NfNatEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let manip_type = if self.manip_type == 0 { "SNAT" } else { "DNAT" };
        let ret_stus = if self.rc == 0 { "PASS" } else { "REJECT" };
        if self.target_addr != self.origin_addr {
            return write!(
                f,
                "{:4}\t{}:{} -> {}:{}\t\t{}",
                manip_type,
                Ipv4Addr::from(ntohl(self.origin_addr)),
                ntohs(self.origin_port),
                Ipv4Addr::from(ntohl(self.target_addr)),
                ntohs(self.target_port),
                ret_stus,
            );
        }
        Ok(())
    }
}

#[repr(C)]
struct NetFilterEvent {
    nf_hook_ops_type: u8,
    hook: u8,
    num_hook_entries: u16,
    table_name: [u8; XT_TABLE_MAXNAMELEN],
    chain_name: [u8; XT_TABLE_MAXNAMELEN],
    verdict: u32,
    delay: u32,
    in_dev: [u8; IFNAMESIZ],
    out_dev: [u8; IFNAMESIZ],
    tuple: Tuple,
    ns_info: NetNsInfo,
    proc_info: ProcInfo,
}
impl fmt::Display for NetFilterEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ds = Utc
            .with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
            .unwrap()
            .to_string();
        let ns_str = match CONTAINER_NETNS_CACHE.get(&(self.ns_info.ns_id as u64)) {
            Some(ns) => ns.to_string(),
            None => format!("{}(root)", self.ns_info.ns_id),
        };
        write!(f,
            "{} {:<16} {}      {:<8}    {}      {} {:<32} {:<32} {}",
            chrono::offset::Local::now().format("%H:%M:%S%.3f"),
            ns_str,
            String::from_utf8_lossy(self.ns_info.device_name.as_slice()),
            self.proc_info.pid.to_string(),
            String::from_utf8_lossy(self.proc_info.comm.as_slice()),
            self.tuple,
            String::from_utf8_lossy(self.table_name.as_slice()),
            String::from_utf8_lossy(self.chain_name.as_slice()),
            nf_hook_verdict(self.verdict))
    }
}

impl NetFilterEvent {
    fn print_header() {
        println!("{:^12} {:^16} {:^8} {:^8} {:^8} {:^32} {:^8} {:^8} {:^8}", 
            "TIME", "NET_NS_NAME", "IF_NAME", "PID", "COMM", "PKT_INFO", "TABLE", "CHAIN", "VERDICT");
    }
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const NetFilterEvent) };
    }
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Self = Self::load(data);
        println!("{}", event);
    }
}

#[repr(C)]
struct RouteEvent {
    rc: u32,
    daddr: u32,
    saddr: u32,
}

impl RouteEvent {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const RouteEvent) };
    }
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Self = Self::load(data);
        println!("{}", event);
    }
}

impl fmt::Display for RouteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rec = if self.rc ==0 {"Pass"} else {"NoRoue"};
            write!(
                f,
                "{} --> {}  {}",
                Ipv4Addr::from(ntohl(self.saddr)),
                Ipv4Addr::from(ntohl(self.daddr)),
                rec,
            )
        } 
}

fn ebpf_attach_netfilter(skel: &mut NetdigSkel)->Result<()>{
    skel.links.kprobe__nft_do_chain = skel.progs.kprobe__nft_do_chain.attach()?.into();
    skel.links.kretprobe__nft_do_chain = skel.progs.kretprobe__nft_do_chain.attach()?.into();
    Ok(())
}

fn ebpf_attach_nf_nat(skel: &mut NetdigSkel)->Result<()>{
    skel.links.kprobe__nf_nat_ipv4_manip_pkt = skel.progs.kprobe__nf_nat_ipv4_manip_pkt.attach()?.into();
    skel.links.kretprobe__nf_nat_ipv4_manip_pkt = skel.progs.kretprobe__nf_nat_ipv4_manip_pkt.attach()?.into();
    Ok(())
}

fn ebpf_attach_route(skel: &mut NetdigSkel)->Result<()>{
    skel.links.kprobe__ip_route_input_noref = skel.progs.kprobe__ip_route_input_noref.attach()?.into();
    skel.links.kretprobe__ip_route_input_noref = skel.progs.kretprobe__ip_route_input_noref.attach()?.into();
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let cfg: Configuration = cli.into();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        println!("remove limit on locked memory failed, ret is {}", ret);
    }

    let mut skel_builder = NetdigSkelBuilder::default();
    // set constants
    let mut open_project = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_project).unwrap();
    // load ebpf code into kernel
    let mut skel = open_skel.load().unwrap();

    // config
    let key = 0u32;
    skel.maps.custom_config_map.update(
        &key.to_ne_bytes(),
        cfg.as_bytes(),
        libbpf_rs::MapFlags::ANY,
    ).unwrap();


    if true == cfg.hook_nf_filter {
        ebpf_attach_netfilter(&mut skel).unwrap();

        let perf = PerfBufferBuilder::new(&skel.maps.perf_netfilter_events)
            .sample_cb(NetFilterEvent::handler)
            .build()
            .unwrap();

        NetFilterEvent::print_header();
        loop {
            perf.poll(Duration::from_millis(100)).unwrap();
        }
    }

}
