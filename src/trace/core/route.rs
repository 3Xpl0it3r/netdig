use anyhow::Result;
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::netdig::NetdigSkel;
use crate::os_utils;
use crate::trace::Tracer;

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[repr(C)]
struct Event {
    rc: u32,
    daddr: u32,
    saddr: u32,
}

impl Event {
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
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
    #[inline]
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Event = Event::load(data);
        event.display();
    }
}

pub struct NetRoute<'pb> {
    _links: Vec<Option<libbpf_rs::Link>>,
    perf_buffer: Option<PerfBuffer<'pb>>,
}

// Tracer[#TODO] (should add some comments)
impl<'pb> Tracer for NetRoute<'pb> {
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
        let perf_buffer = PerfBufferBuilder::new(&skel.maps.perf_event_net_route_map)
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
        let kprobes = ["ip_route_input_noref"];
        for kprobe in kprobes {
            if kernel_probes.kprobe_is_available(kprobe) {
                self._links.push(
                    skel.progs
                        .kprobe__trace_router
                        .attach_kprobe(false, kprobe)?
                        .into(),
                );
                self._links.push(
                    skel.progs
                        .kretprobe__trace_router
                        .attach_kprobe(true, kprobe)?
                        .into(),
                );
            }
        }
        Ok(())
    }

    fn poll(&self, duration: std::time::Duration) -> Result<()> {
        self.perf_buffer.as_ref().unwrap().poll(duration).unwrap();
        Ok(())
    }
}
