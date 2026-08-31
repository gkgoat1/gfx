//! `std`-gated host adapters (plan §9). These are conveniences for hosts and
//! integration tests — the sans-IO core never requires them.

use alloc::vec::Vec;

extern crate std;
use gfx_core::{Error, Event, Parser};

/// Feed all bytes from a reader into the parser (core stays `no_std`; this
/// adapter lives on the facade).
pub fn feed_all(parser: &mut Parser, mut reader: impl std::io::Read) -> Result<(), Error> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            return Ok(());
        }
        parser.feed(&buf[..n]);
    }
}

fn io_error(e: std::io::Error) -> Error {
    let _ = e;
    Error::Internal("host i/o error (see host logs)")
}

/// Stream → stream in one call: parse `input`, push it through `pipeline`,
/// and serialize. Buffers in, buffers out — still sans-IO (plan §9).
pub fn rewrite(input: &[u8], pipeline: &mut gfx_core::Pipeline) -> Result<Vec<u8>, Error> {
    use gfx_core::Transform;
    let mut parser = Parser::new(gfx_core::ParseOptions::default());
    parser.feed(input);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event()? {
        pipeline.apply(ev, &mut events)?;
    }
    let mut final_events = Vec::new();
    parser.finish(&mut final_events)?;
    for ev in final_events {
        pipeline.apply(ev, &mut events)?;
    }
    pipeline.finish(&mut events)?;
    let mut writer = gfx_core::Writer::new();
    for ev in &events {
        writer.write(ev)?;
    }
    Ok(writer.take())
}
