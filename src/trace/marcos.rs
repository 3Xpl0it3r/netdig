macro_rules! new_tracer {
    ($tracer_name:ident, $map_name:ident) => {
        pub struct $tracer_name<'pb> {
            _links: Vec<Option<libbpf_rs::Link>>,
            perf_buffer: Option<PerfBuffer<'pb>>,
        }

        impl<'pb> Tracer for $tracer_name<'pb> {
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
                let perf_buffer = PerfBufferBuilder::new(&skel.maps.$map_name)
                    .sample_cb(Event::handler)
                    .build()?;
                self.perf_buffer = Some(perf_buffer);
                Ok(())
            }
            fn attach_probe(&mut self, skel: &mut NetdigSkel, kernel_probes: KernelProbes) -> Result<()>{
                todo!()
            }

            fn poll(&self, duration: std::time::Duration) -> Result<()> {
                self.perf_buffer.as_ref().unwrap().poll(duration).unwrap();
                Ok(())
            }
        }
    };
}


pub(crate) use new_tracer;
