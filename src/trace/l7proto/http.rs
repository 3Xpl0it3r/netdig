// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::comm_types;
use crate::container_utils;
use crate::netdig::NetdigSkel;
use crate::os_utils;
use crate::trace::Tracer;
use crate::utils;

#[repr(C)]
struct Event {
    method: u8,
    protocol: u16,
    url: [u8; 16],
    delay: u64,
    s_addr: u32,
    s_port: u16,
}

impl Event {
    #[inline]
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
    #[inline]
    fn display(self) {
        // skbaddr netns ifidx  pid prog tuple  function
        println!("hello world")
    }
    #[inline]
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Event = Event::load(data);
        event.display();
    }
}


pub struct HttpTracer<'pb> {
    _links: Vec<Option<libbpf_rs::Link>>,
    perf_buffer: Option<PerfBuffer<'pb>>,
}

impl<'pb> Tracer for HttpTracer<'pb> {
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
        let perf_buffer = PerfBufferBuilder::new(&skel.maps.perf_event_l7_http_map)
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
        Ok(())
    }
}
