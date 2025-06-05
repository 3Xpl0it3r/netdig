use std::cell::{LazyCell, RefCell};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};

//
use std::thread;
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

pub fn get_kallsyms_by_func_addr(addr: &u64) -> String {
    match KALLSYMS.get(addr) {
        Some(syms) => syms.to_string(),
        None => format!("{}", addr),
    }
}

// /sys/kernel/debug/tracing/available_filter_functions
pub fn kprobe_is_available(kprobe: &str) -> bool {
    true
}

// sudo cat /sys/kernel/debug/tracing/available_events
pub fn tracepoint_is_available(tp: &str) -> bool {
    true
}
