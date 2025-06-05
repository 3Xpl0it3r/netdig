use std::vec;

use anyhow::{anyhow, Result};
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::netdig::NetdigSkel;
use crate::os_utils;

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[repr(C)]
struct NetRouteEvent {
    rc: u32,
    daddr: u32,
    saddr: u32,
}

impl NetRouteEvent {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
}

impl NetRouteEvent {
    #[inline]
    fn display(self) {
        let rec = if self.rc == 0 { "Pass" } else { "NoRoue" };
        println!(
            "{} --> {}  {}",
            std::net::Ipv4Addr::from(libc::ntohl(self.saddr)),
            std::net::Ipv4Addr::from(libc::ntohl(self.daddr)),
            rec,
        )
    }
}
#[inline]
fn handler(_cpu: i32, data: &[u8]) {
    let event: NetRouteEvent = NetRouteEvent::load(data);
    event.display();
}

#[inline]
pub fn get_perf_buffer<'a>(skel: &'a NetdigSkel) -> Result<PerfBuffer<'a>> {
    Ok(PerfBufferBuilder::new(&skel.maps.perf_route_events)
        .sample_cb(handler)
        .build()?)
}

#[inline]
pub fn ebpf_attach(skel: &mut NetdigSkel) -> Result<Vec<Option<libbpf_rs::Link>>> {
    let kprobes = ["ip_route_input_noref"];
    let mut links = Vec::new();
    for kprobe in kprobes {
        if os_utils::kprobe_is_available(kprobe) {
            links.push(
                skel.progs
                    .kprobe__trace_router
                    .attach_kprobe(false, kprobe)?
                    .into(),
            );
            links.push(
                skel.progs
                    .kretprobe__trace_router
                    .attach_kprobe(true, kprobe)?
                    .into(),
            );
        }
    }
    Ok(links)
}
