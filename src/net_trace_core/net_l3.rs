use anyhow::{anyhow, Result};
use std::ffi::CStr;
use std::fmt;

use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::netdig::NetdigSkel;
use crate::utils;
use crate::{comm_types, container_utils, os_utils};

const KPROBES_SKB_RECORD: [&str; 1] = ["ip_rcv_core"];
// (int)(struct sk_buff *, .....)
const KPROBES_SKB_PROG_TYPE_0: [&str; 4] = [
    "ip_rcv_finish",
    "ip_local_deliver",
    "tcp_v4_rcv",
    "nf_hook_slow",
];
const KPROBES_SKB_RELEASE: [&str; 2] = ["__kfree_skb", "__kfree_skb_defer"];

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[repr(C)]
struct NetL3Event {
    errno: i32,
    probe_addr: u64,
    skb_addr: u64,
    tuple: comm_types::Tuple,
    net_ns_info: comm_types::NetNsInfo,
}

impl NetL3Event {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
}

impl NetL3Event {
    fn display(self) {
        println!(
            "|{:#10x}|{:^12}|{:>8}:({:<02})|{}|{:^16}|",
            self.skb_addr,
            container_utils::get_container_name_by_nsid(&(self.net_ns_info.ns_id as u64)),
            utils::cstr_to_string(&self.net_ns_info.device_name),
            self.net_ns_info.ifindex,
            self.tuple,
            os_utils::get_kallsyms_by_func_addr(&self.probe_addr),
        )
    }
}

#[inline]
fn handler(_cpu: i32, data: &[u8]) {
    let event: NetL3Event = NetL3Event::load(data);
    event.display();
}

#[inline]
pub fn get_perf_buffer<'a>(skel: &'a NetdigSkel) -> Result<PerfBuffer<'a>> {
    Ok(PerfBufferBuilder::new(&skel.maps.perf_net_l3_events)
        .sample_cb(handler)
        .build()?)
}

#[inline]
pub fn ebpf_attach(skel: &mut NetdigSkel) -> Result<Vec<Option<libbpf_rs::Link>>> {
    let mut l3_links = Vec::<Option<libbpf_rs::Link>>::new();
    for kprobe in KPROBES_SKB_RECORD {
        if os_utils::kprobe_is_available(kprobe) {
            l3_links.push(
                skel.progs
                    .kprobe__trace_l3_skb_srart
                    .attach_kprobe(false, kprobe)?
                    .into(),
            );
        }
    }
    // (int)(struct sk_buff *)
    for kprobe in KPROBES_SKB_PROG_TYPE_0 {
        if os_utils::kprobe_is_available(kprobe) {
            l3_links.push(
                skel.progs
                    .kprobe__trace_l3_skb_prog_0
                    .attach_kprobe(false, kprobe)?
                    .into(),
            );
        }
    }
    for kprobe in KPROBES_SKB_RELEASE {
        if os_utils::kprobe_is_available(kprobe) {
            l3_links.push(
                skel.progs
                    .kprobe__trace_l3_skb_end
                    .attach_kprobe(false, kprobe)?
                    .into(),
            );
        }
    }

    Ok(l3_links)
}
