use libbpf_rs::{PerfBuffer, PerfBufferBuilder};

use anyhow::Result;

use crate::container_utils;
use crate::netdig::NetdigSkel;
use crate::trace::Tracer;
use crate::{comm_types, utils};
use crate::{constants, os_utils};

const NF_HOOK_VERDICT: [&str; 8] = [
    "NF_DROP",
    "NF_ACCEPT",
    "NF_STOLEN",
    "NF_QUEUE",
    "NF_REPEAT",
    "NF_STOP",
    "NF_MAX_VERDICT",
    "UN_KNOWN",
];
// Netfilter nat event

#[repr(C)]
struct Event {
    nf_hook_ops_type: u8,
    hook: u8,
    num_hook_entries: u16,
    table_name: [u8; constants::XT_TABLE_MAXNAMELEN],
    chain_name: [u8; constants::XT_TABLE_MAXNAMELEN],
    verdict: u32,
    delay: u32,
    in_dev: [u8; constants::IFNAMESIZ],
    out_dev: [u8; constants::IFNAMESIZ],
    tuple: comm_types::Tuple,
    ns_info: comm_types::NetNsInfo,
    proc_info: comm_types::ProcessInfo,
}

impl Event {
    #[inline]
    fn display(self) {
        println!(
            "|{:^8}|{:<16}|{}|{:<8}|{}|{}|{:<32}|{:<32}|{}|",
            chrono::offset::Local::now().format("%H:%M:%S%.3f"),
            container_utils::get_container_name_by_nsid(&(self.ns_info.ns_id as u64)),
            utils::cstr_to_string(&self.ns_info.device_name),
            self.proc_info.pid.to_string(),
            String::from_utf8_lossy(self.proc_info.comm.as_slice()),
            self.tuple,
            utils::cstr_to_string(&self.table_name),
            utils::cstr_to_string(&self.chain_name),
            NF_HOOK_VERDICT[self.verdict as usize]
        )
    }
}

/* "TIME", "NET_NS_NAME", "IF_NAME", "PID", "COMM", "PKT_INFO", "TABLE", "CHAIN", "VERDICT" */

impl Event {
    #[inline]
    fn load(data: &[u8]) -> Self {
        return unsafe { std::ptr::read(data.as_ptr() as *const Self) };
    }
    #[inline]
    fn handler(_cpu: i32, data: &[u8]) {
        let event: Event = Event::load(data);
        event.display();
    }
}

pub struct NetNetfilterTracer<'pb> {
    _links: Vec<Option<libbpf_rs::Link>>,
    perf_buffer: Option<PerfBuffer<'pb>>,
}

// Tracer[#TODO] (should add some comments)
impl<'pb> Tracer for NetNetfilterTracer<'pb> {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self {
            _links: Vec::new(),
            perf_buffer: None,
        }
    }

    fn attach_map(&mut self, skel: &NetdigSkel) -> Result<()> {
        let perf_buffer = PerfBufferBuilder::new(&skel.maps.perf_event_net_netfilter_map)
            .sample_cb(Event::handler)
            .build()?;
        self.perf_buffer = Some(perf_buffer);
        Ok(())
    }

    fn attach_probe(
        &mut self,
        skel: &mut NetdigSkel,
        kernel_probes: os_utils::KernelProbes,
    ) -> Result<()> {
        if kernel_probes.kprobe_is_available("nft_do_chain") {
            self._links
                .push(skel.progs.kprobe__nft_do_chain.attach()?.into());
        }
        Ok(())
    }

    fn poll(&self, duration: std::time::Duration) -> Result<()> {
        self.perf_buffer.as_ref().unwrap().poll(duration).unwrap();
        Ok(())
    }
}
