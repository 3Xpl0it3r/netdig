use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/netdig.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("netdig.skel.rs");

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            PathBuf::from("src/bpf/headers").as_os_str(),
            OsStr::new("-I"),
            PathBuf::from("src/bpf/libbpf/src").as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}
