// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.

use std::ffi::CStr;
use std::net::Ipv4Addr;

use libc::ntohl;

#[inline]
pub fn cstr_to_string(data: &[u8]) -> String {
    match CStr::from_bytes_until_nul(data) {
        Ok(device_name) => device_name.to_string_lossy().to_string(),
        Err(_) => "".to_string(),
    }
}

#[inline]
pub fn u32_to_ipaddr_v4(addr: u32) -> String {
    Ipv4Addr::from(ntohl(addr)).to_string()
}
