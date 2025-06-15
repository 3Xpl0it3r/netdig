use std::ffi::CString;
use std::mem::{self, MaybeUninit};
use std::time;

use clap::Parser;
use libbpf_rs::{
    libbpf_sys,
    skel::{OpenSkel, SkelBuilder},
    MapCore,
};

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

pub(crate) mod trace;

fn build_custom_btf_open_opt(btf_custom_path: &str) -> libbpf_sys::bpf_object_open_opts {
    let _path = CString::new(btf_custom_path).unwrap();
    let cus_btf_fd: *const ::std::os::raw::c_char = _path.into_raw();

    let mut opts = libbpf_sys::bpf_object_open_opts {
        sz: mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    opts.btf_custom_path = cus_btf_fd;
    opts
}

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

    let skel_builder = NetdigSkelBuilder::default();
    // set constants
    let mut open_project = MaybeUninit::uninit();

    let open_skel = if os_utils::os_support_btf() {
        skel_builder.open(&mut open_project).unwrap()
    } else {
        // bpf/btfhub_archive/<os_id>/<version_id>/<arch>/<kernel_version.btf>
        let os_release = os_utils::OsRelease::default();
        let btf_custom_path = format!(
            "src/bpf/btfhub_archive/{}/{}/{}/{}.btf",
            os_release.id, os_release.version_id, os_release.arch, os_release.kernel_version
        );
        skel_builder
            .open_opts(
                build_custom_btf_open_opt(&btf_custom_path),
                &mut open_project,
            )
            .unwrap()
    };
    // load ebpf code into kernel
    let mut skel = open_skel.load().unwrap();

    // config
    let key = 0u32;
    skel.maps
        .custom_config_map
        .update(&key.to_ne_bytes(), cfg.as_bytes(), libbpf_rs::MapFlags::ANY)
        .unwrap();

    let kernel_probes = os_utils::KernelProbes::default();

    let mut tracer = trace::build_tracker(cfg.as_trace_kind());
    // 关联perf event maps
    tracer.attach_map(&skel).unwrap();
    // 关联kprobes
    tracer.attach_probe(&mut skel, kernel_probes).unwrap();
    loop {
        tracer.poll(time::Duration::from_millis(100));
    }
}
