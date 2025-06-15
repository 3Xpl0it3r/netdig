use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::LazyLock;

//
use anyhow::Result;

pub static KALLSYMS: LazyLock<HashMap<u64, String>> = LazyLock::new(|| load_kallsyms());

#[inline]
fn load_kallsyms() -> HashMap<u64, String> {
    let mut symbol_map = HashMap::<u64, String>::new();
    // if load failed, then panic directory , don't need propagate error
    let file = File::open("/proc/kallsyms").unwrap();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                symbol_map.insert(addr, parts[2].to_string());
            }
        }
    }
    symbol_map
}

pub fn os_support_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

pub fn get_kallsyms_by_func_addr(addr: &u64) -> String {
    match KALLSYMS.get(addr) {
        Some(syms) => syms.to_string(),
        None => format!("{}", addr),
    }
}

pub struct KernelProbes {
    kprobes: HashMap<String, bool>,
    tracepoints: HashMap<String, bool>,
}

// Default[#TODO] (should add some comments)
impl Default for KernelProbes {
    fn default() -> Self {
        let kprobes = get_all_kprobes().unwrap_or(HashMap::new());
        let tracepoints = get_all_tracepoints().unwrap_or(HashMap::new());
        KernelProbes {
            kprobes,
            tracepoints,
        }
    }
}

impl KernelProbes {
    #[inline]
    pub fn kprobe_is_available(&self, kprobe: &str) -> bool {
        match self.kprobes.get(kprobe) {
            Some(_) => true,
            None => {
                println!("kprobe {} is not supported in current os", kprobe);
                false
            }
        }
    }
    #[inline]
    pub fn tp_is_available(&self, tp: &str) -> bool {
        match self.tracepoints.get(tp) {
            Some(_) => true,
            None => {
                println!("tracepoint {} is not supported in current os", tp);
                false
            }
        }
    }
}

#[inline]
fn get_all_kprobes() -> Result<HashMap<String, bool>> {
    let path = Path::new("/sys/kernel/debug/tracing/available_filter_functions");
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut functions = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let func_name = line.trim().to_string();

        if !func_name.is_empty() {
            functions.insert(func_name, true);
        }
    }
    Ok(functions)
}

#[inline]
fn get_all_tracepoints() -> Result<HashMap<String, bool>> {
    let path = Path::new("/sys/kernel/debug/tracing/available_events");
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut trace_map: HashMap<String, bool> = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        let tracepoint = line.trim();
        // 跳过空行和不符合格式的行
        if !tracepoint.is_empty() && tracepoint.contains(':') {
            trace_map.insert(tracepoint.to_string(), true);
        }
    }
    Ok(trace_map)
}

pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub kernel_version: String,
    pub arch: String,
}

// Default[#TODO] (should add some comments)
impl Default for OsRelease {
    fn default() -> Self {
        let os_release = get_os_release().unwrap_or(HashMap::new());
        let (kernel_version, arch) =
            get_kernel_info().unwrap_or(("UnknownVersion".to_string(), "UnKnownArch".to_string()));
        OsRelease {
            id: os_release
                .get("ID")
                .cloned()
                .unwrap_or("UnKnown OS".to_string()),
            version_id: os_release
                .get("VERSION_ID")
                .cloned()
                .unwrap_or("Unknown Os Version".to_string()),
            kernel_version,
            arch,
        }
    }
}

#[inline]
fn get_os_release() -> Result<HashMap<String, String>> {
    let path = Path::new("/etc/os-release");
    let content = fs::read_to_string(path)?;

    let mut os_info = HashMap::new();

    for line in content.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"');
            os_info.insert(key.to_string(), value.to_string());
        }
    }

    Ok(os_info)
}

#[inline]
fn get_kernel_info() -> Option<(String, String)> {
    let content = fs::read_to_string("/proc/version").ok()?;

    let full_version = content.split_whitespace().nth(2)?.to_string();

    // 从版本字符串中提取CPU架构（最后一个以'.'分割的部分）
    let arch = full_version.split('.').last()?.to_string();

    Some((full_version, arch))
}
