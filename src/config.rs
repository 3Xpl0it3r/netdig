use libc::{htonl, htons};
use std::net::{self, Ipv4Addr};
use std::slice;
use std::str::FromStr;

use anyhow::{anyhow, Result};

// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.
#[derive(clap::Parser)]
#[command(name = "netdig")]
#[command(bin_name = "netdig")]
#[command(version="v0.0.1(2025-05-14)", about="A tool using eBPF to trace and diagnose container network issues", long_about = None)]
pub(crate) struct Cli {
    #[arg(long)]
    addr: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long = "nat", group = "hook")]
    hook_net_nat: bool,
    #[arg(long = "netfilter", group = "hook")]
    hook_netfilter: bool,
    #[arg(long = "skb_trace", group = "hook")]
    hook_net_l3: bool,
}

impl Into<Configuration> for Cli {
    fn into(self) -> Configuration {
        let mut cfg = Configuration::default();
        if self.addr.is_some() {
            let addr = Ipv4Addr::from_str(self.addr.as_ref().unwrap())
                .unwrap()
                .to_bits();
            cfg.addr = htonl(addr);
        }
        if self.port.is_some() {
            cfg.port = htons(self.port.unwrap());
        }
        cfg.hook_nf_nat = self.hook_net_nat;
        cfg.hook_nf_filter = self.hook_netfilter;
        if !self.hook_net_nat && !self.hook_netfilter {
            cfg.hook_net_l3 = true;
        }
        cfg
    }
}

// configure that will pass to ebpf
#[repr(C)]
#[derive(Default)]
pub(crate) struct Configuration {
    pub addr: u32,
    pub port: u16,
    pub hook_nf_nat: bool,
    pub hook_nf_filter: bool,
    pub hook_net_l3: bool,
}

impl Configuration {
    #[inline]
    pub fn set_port(&mut self, port: u16) {
        self.port = libc::htons(port)
    }
    #[inline]
    pub fn get_port(&self) -> u16 {
        libc::ntohs(self.port)
    }
    #[inline]
    pub fn set_v4_addr(&mut self, ip_str: &str) -> Result<()> {
        let s_addr: u32 = net::Ipv4Addr::from_str(ip_str)?.into();
        self.addr = s_addr.to_be();
        Ok(())
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let bptr = self as *const _ as *const u8;
        let bsize = std::mem::size_of_val(self);
        unsafe { slice::from_raw_parts(bptr, bsize) }
    }
}
