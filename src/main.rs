use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::mem::MaybeUninit;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::offset::MappedLocalTime;
use chrono::prelude::*;
use tokio::runtime::Runtime;

use bollard::Docker;
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, PerfBuffer, PerfBufferBuilder};
use libc::{c_char, htonl, htons, ntohl, ntohs};
use plain::Plain;

mod netdig {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netdig.skel.rs"
    ));
}

use netdig::*;

pub(crate) mod comm_types;
pub(crate) mod config;
pub(crate) mod constants;
pub(crate) mod container_utils;
pub(crate) mod os_utils;
pub(crate) mod utils;

pub(crate) mod net_trace_core;
pub(crate) mod net_trace_l7;

fn main() {
    let cli = config::Cli::parse();
    let cfg: config::Configuration = cli.into();

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
    skel.maps
        .custom_config_map
        .update(&key.to_ne_bytes(), cfg.as_bytes(), libbpf_rs::MapFlags::ANY)
        .unwrap();

    if true == cfg.trace_net_l3 {
        let _links = net_trace_core::ebpf_attach_l3(&mut skel);
        let perf = net_trace_core::get_l3_perf_buffer(&skel).unwrap();
        loop {
            perf.poll(Duration::from_millis(100)).unwrap();
        }
    } else if true == cfg.trace_nf_filter {
        let _links = net_trace_core::ebpf_attach_netfilter(&mut skel);
        let perf = net_trace_core::get_netfiler_perf_buffer(&skel).unwrap();
        loop {
            perf.poll(Duration::from_millis(100)).unwrap();
        }
    }
}
