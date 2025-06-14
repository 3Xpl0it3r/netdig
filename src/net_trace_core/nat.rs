use std::net::Ipv4Addr;

use anyhow::Result;
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};
use libc::{ntohl, ntohs};

use crate::netdig::NetdigSkel;
use crate::os_utils;

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[repr(C)]
struct NetNatEvent {
    manip_type: u8,
    origin_port: u16,
    target_port: u16,
    origin_addr: u32,
    target_addr: u32,
    rc: u32,
}
impl NetNatEvent {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
}

impl NetNatEvent {
    fn display(self) {
        let manip_type = if self.manip_type == 0 { "SNAT" } else { "DNAT" };
        let ret_stus = if self.rc == 0 { "PASS" } else { "REJECT" };
        if self.target_addr != self.origin_addr {
            println!(
                "{:4}\t{}:{} -> {}:{}\t\t{}",
                manip_type,
                Ipv4Addr::from(ntohl(self.origin_addr)),
                ntohs(self.origin_port),
                Ipv4Addr::from(ntohl(self.target_addr)),
                ntohs(self.target_port),
                ret_stus,
            );
        }
    }
}

fn handler(_cpu: i32, data: &[u8]) {
    let event: NetNatEvent = NetNatEvent::load(data);
    event.display();
}
pub fn get_perf_buffer<'a>(skel: &'a NetdigSkel) -> Result<PerfBuffer<'a>> {
    Ok(PerfBufferBuilder::new(&skel.maps.perf_nfnat_events)
        .sample_cb(handler)
        .build()?)
}
#[inline]
pub fn ebpf_attach(
    skel: &mut NetdigSkel,
    kernel_probes: os_utils::AllAvailableKernelProbes,
) -> Result<Vec<Option<libbpf_rs::Link>>> {
    let mut links = Vec::<Option<libbpf_rs::Link>>::new();
    if kernel_probes.kprobe_is_available("nf_nat_ipv4_manip_pkt") {
        links.push(skel.progs.kprobe__nf_nat_ipv4_manip_pkt.attach()?.into());
        links.push(skel.progs.kretprobe__nf_nat_ipv4_manip_pkt.attach()?.into());
    }

    Ok(links)
}
