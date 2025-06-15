use std::time::Duration;

use anyhow::Result;
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::comm_types;
use crate::container_utils;
use crate::netdig::NetdigSkel;
use crate::os_utils;
use crate::trace::Tracer;
use crate::utils;


#[cfg(kernel_le_4_19)]
const KPROBES_SKB_RECORD: [&str; 1] = ["ip_rcv"];

#[cfg(kernel_gt_4_19)]
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
struct Event {
    errno: i32,
    probe_addr: u64,
    skb_addr: u64,
    tuple: comm_types::Tuple,
    net_ns_info: comm_types::NetNsInfo,
    process_info: comm_types::ProcessInfo,
}

impl Event {
    #[inline]
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
    #[inline]
    fn display(self) {
        // skbaddr netns ifidx  pid prog tuple  function
        println!(
            "|{:#10x}|{:^12}|{:>8}:({:<02})|{:^6}|{:^12}|{}|{:^16}|",
            self.skb_addr,
            container_utils::get_container_name_by_nsid(&(self.net_ns_info.ns_id as u64)),
            utils::cstr_to_string(&self.net_ns_info.device_name),
            self.net_ns_info.ifindex,
            self.process_info.pid,
            utils::cstr_to_string(&self.process_info.comm),
            self.tuple,
            os_utils::get_kallsyms_by_func_addr(&self.probe_addr),
        )
    }
    #[inline]
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Event = Event::load(data);
        event.display();
    }
}


pub struct NetL3Tracer<'pb> {
    _links: Vec<Option<libbpf_rs::Link>>,
    perf_buffer: Option<PerfBuffer<'pb>>,
}

impl<'pb> Tracer for NetL3Tracer<'pb> {
    fn new() -> Self {
        Self {
            _links: Vec::new(),
            perf_buffer: None,
        }
    }
    fn poll(&self, duration: Duration) -> Result<()> {
        self.perf_buffer.as_ref().unwrap().poll(duration).unwrap();
        Ok(())
    }
    fn attach_map(&mut self, skel: &NetdigSkel) -> Result<()> {
        let perf_buffer = PerfBufferBuilder::new(&skel.maps.perf_event_net_l3_map)
            .sample_cb(Event::handler)
            .build()?;
        self.perf_buffer = Some(perf_buffer);
        Ok(())
    }

    #[inline]
    fn attach_probe(
        &mut self,
        skel: &mut NetdigSkel,
        kernel_probes: os_utils::KernelProbes,
    ) -> Result<()> {
        for kprobe in KPROBES_SKB_RECORD {
            if kernel_probes.kprobe_is_available(kprobe) {
                self._links.push(
                    skel.progs
                        .kprobe__trace_l3_skb_srart
                        .attach_kprobe(false, kprobe)?
                        .into(),
                );
            }
        }
        // (int)(struct sk_buff *)
        for kprobe in KPROBES_SKB_PROG_TYPE_0 {
            if kernel_probes.kprobe_is_available(kprobe) {
                self._links.push(
                    skel.progs
                        .kprobe__trace_l3_skb_prog_0
                        .attach_kprobe(false, kprobe)?
                        .into(),
                );
            }
        }
        for kprobe in KPROBES_SKB_RELEASE {
            if kernel_probes.kprobe_is_available(kprobe) {
                self._links.push(
                    skel.progs
                        .kprobe__trace_l3_skb_end
                        .attach_kprobe(false, kprobe)?
                        .into(),
                );
            }
        }
        Ok(())
    }
}
