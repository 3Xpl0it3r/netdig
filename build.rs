use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/netdig.bpf.c";

fn create_or_replace_symlink(original_path: &Path, link_path: &Path) -> std::io::Result<()> {
    if link_path.exists() {
        fs::remove_file(link_path)?;
    }

    std::os::unix::fs::symlink(original_path, link_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to create symlink from {:?} to {:?}: {}",
                original_path, link_path, e
            ),
        )
    })
}

fn os_support_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

fn os_kernel_version() -> Option<(u32, u32, u32)> {
    let content = fs::read_to_string("/proc/version").unwrap();
    let version_str = content.split_whitespace().nth(2).unwrap();
    let version_part = version_str.split('-').next()?;
    let mut parts = version_part
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok());
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next().unwrap_or(0); // 如果没有 patch 版本，默认为 0
    Some((major, minor, patch))
}

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("netdig.skel.rs");

    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    let (major_version, minor_version, path_version) =
        os_kernel_version().expect("cannot get kernel version");

    let mut skeleton_builder = SkeletonBuilder::new();
    skeleton_builder.source(SRC);
    let mut build_args = vec![
        OsStr::new("-I").to_owned(),
        PathBuf::from("src/bpf/libbpf/src").as_os_str().to_owned(),
        OsStr::new("-I").to_owned(),
        PathBuf::from("src/bpf/include").as_os_str().to_owned(),
    ];

    if os_support_btf() {
        build_args.append(&mut vec![
            OsStr::new("-I").to_owned(),
            vmlinux::include_path_root()
                .join(&arch)
                .as_os_str()
                .to_owned(),
        ]);
    } else {
        create_or_replace_symlink(
            &manifest_path
                .join("src/bpf/vmlinux")
                .join(arch)
                .join(format!(
                    "vmlinux-{}.{}.{}.h",
                    major_version, minor_version, path_version
                )),
            &PathBuf::from("src/bpf/vmlinux/vmlinux.h"),
        )
        .expect("cannot create slink");
        build_args.append(&mut vec![
            OsStr::new("-DLINUX_KERNEL_VERSION=50400").to_owned(),
            OsStr::new("-I").to_owned(),
            PathBuf::from("src/bpf/vmlinux").as_os_str().to_owned(),
        ]);
    }

    skeleton_builder
        .clang_args(build_args)
        .build_and_generate(out)
        .unwrap();

    let kernel_version_flag = if major_version <= 4 && minor_version <= 19 {
        "kernel_le_4_19"
    } else {
        "kernel_gt_4_19"
    };

    println!("cargo::rustc-check-cfg=cfg(kernel_gt_4_19)");
    println!("cargo::rustc-check-cfg=cfg(kernel_le_4_19)");


    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rustc-cfg={}", kernel_version_flag);
}
