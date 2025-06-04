// Copyright 2025 netdig Project Authors. Licensed under Apache-2.0.

use std::ffi::CStr;

#[inline]
pub fn cstr_to_string(data: &[u8]) -> String {
    match unsafe { CStr::from_bytes_until_nul(data) } {
        Ok(device_name) => device_name.to_string_lossy().to_string(),
        Err(_) => "".to_string(),
    }
}
