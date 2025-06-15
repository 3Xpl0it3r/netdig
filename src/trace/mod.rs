// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
use std::default;
use std::time::Duration;

use anyhow::Result;

use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use crate::netdig::NetdigSkel;
use crate::os_utils::KernelProbes;

mod core;
use core::{NetL3Tracer,NetNatTracer, NetNetfilterTracer, NetRoute};

mod l7proto;
use l7proto::HttpTracer;

pub enum TracerKind {
    CoreTraceNetL3,
    CoreTraceNat,
    CoreTraceRoute,
    CoreTraceNetfilter,

    L7TraceHttp,
}

pub trait Tracer {
    fn new() -> Self
    where
        Self: Sized;
    fn attach_map(&mut self, skel: &NetdigSkel) -> Result<()>;
    fn attach_probe(&mut self, skel: &mut NetdigSkel, kernel_probes: KernelProbes) -> Result<()>;
    fn poll(&self, duration: Duration) -> Result<()>;
}

pub fn build_tracker(trace_kind: TracerKind) -> Box<dyn Tracer> {
    match trace_kind  {
        TracerKind::CoreTraceNetL3 =>Box::new(NetL3Tracer::new()) ,
        TracerKind::CoreTraceNat => Box::new(NetNatTracer::new()),
        TracerKind::CoreTraceRoute => Box::new(NetRoute::new()),
        TracerKind::CoreTraceNetfilter => Box::new(NetNetfilterTracer::new()),

        TracerKind::L7TraceHttp => Box::new(HttpTracer::new()),
    }
}
