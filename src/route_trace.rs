use anyhow::{anyhow, Result};
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::netdig::NetdigSkel;

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
fn ebpf_attach_route(skel: &mut NetdigSkel) -> Result<()> {
    skel.links.kprobe__ip_route_input_noref =
        skel.progs.kprobe__ip_route_input_noref.attach()?.into();
    skel.links.kretprobe__ip_route_input_noref =
        skel.progs.kretprobe__ip_route_input_noref.attach()?.into();
    Ok(())
}
