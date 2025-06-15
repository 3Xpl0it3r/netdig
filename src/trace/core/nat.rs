use std::net::Ipv4Addr;

use anyhow::Result;
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};
use libc::{ntohl, ntohs};

use crate::netdig::NetdigSkel;
use crate::os_utils;
use crate::trace::Tracer;

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[repr(C)]
struct Event {
    manip_type: u8,
    origin_port: u16,
    target_port: u16,
    origin_addr: u32,
    target_addr: u32,
    rc: u32,
}

impl Event {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
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
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Event = Event::load(data);
        event.display();
    }
}

pub struct NetNatTracer<'pb> {
    _links: Vec<Option<libbpf_rs::Link>>,
    perf_buffer: Option<PerfBuffer<'pb>>,
}

// Tracer[#TODO] (should add some comments)
impl<'pb> Tracer for NetNatTracer<'pb> {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self {
            _links: Vec::new(),
            perf_buffer: None,
        }
    }

    fn attach_map(&mut self, skel: &NetdigSkel) -> Result<()> {
        let perf_buffer = PerfBufferBuilder::new(&skel.maps.perf_event_net_nat_map)
            .sample_cb(Event::handler)
            .build()?;
        self.perf_buffer = Some(perf_buffer);
        Ok(())
    }

    fn attach_probe(
        &mut self,
        skel: &mut NetdigSkel,
        kernel_probes: os_utils::KernelProbes,
    ) -> Result<()> {
        if kernel_probes.kprobe_is_available("nf_nat_ipv4_manip_pkt") {
            self._links
                .push(skel.progs.kprobe__nf_nat_ipv4_manip_pkt.attach()?.into());
            self._links
                .push(skel.progs.kretprobe__nf_nat_ipv4_manip_pkt.attach()?.into());
        }
        Ok(())
    }

    fn poll(&self, duration: std::time::Duration) -> Result<()> {
        self.perf_buffer.as_ref().unwrap().poll(duration).unwrap();
        Ok(())
    }
}
