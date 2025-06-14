use std::fmt;
use std::net::Ipv4Addr;

use libc::{ntohl, ntohs};

use crate::constants;


// 进程相关信息
#[repr(C)]
pub struct ProcessInfo {
    pub pid: i32,
    pub comm: [u8; crate::constants::TASK_COMM_LEN],
}

// Tuple struct represent 5 tuple
#[repr(C)]
pub struct Tuple {
    pub l4_protocol: u8,
    pub l3_protocol: u16,
    pub s_port: u16,
    pub d_port: u16,
    pub s_addr: u32,
    pub d_addr: u32,
}

// fmt::Display[#TODO] (should add some comments)
impl fmt::Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>12}:{:<6}->{:>12}:{:<6}",
            Ipv4Addr::from(ntohl(self.s_addr)),
            ntohs(self.s_port),
            Ipv4Addr::from(ntohl(self.d_addr)),
            ntohs(self.d_port)
        )
    }
}

// 网络namespace相关的信息
#[repr(C)]
pub struct NetNsInfo {
    pub device_name: [u8; constants::IFNAMESIZ],
    pub ifindex: i32,
    pub ns_id: u32,
}
