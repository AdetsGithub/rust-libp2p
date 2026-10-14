#![no_main]

//! Fuzz target for the **Yamux** frame-header codec and stateful connection.
//!
//! Arms (via `Arbitrary`):
//!   - **Header** — raw 12-byte (and short) inputs for `fuzz_header_codec`
//!   - **Connection raw** — blob wire into `fuzz_connection` / `_ex`
//!   - **Closing-biased** — SYN/FIN/RST + tiny WU; graceful `poll_close`
//!   - **Credit-exhaust / RST** — multi-stream SYN, RST edges, tiny/zero WU;
//!     driver soaks local send credit to `poll_write` Pending
//!   - **Connection structured** — type-correct header+body sequences
//!
//! Dict: `dicts/yamux.dict`. Seeds: `seeds/yamux_frame_header/`.
//!
//! Invariants: header lossless HARD; connection terminates HARD; watch RSS/OOM.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};

const MAX_FRAMES: usize = 12;
const MAX_DATA_BODY: usize = 256;

/// Yamux flag bits (spec).
const FLAG_SYN: u16 = 0x0001;
const FLAG_ACK: u16 = 0x0002;
const FLAG_FIN: u16 = 0x0004;
const FLAG_RST: u16 = 0x0008;

/// Build a Yamux frame with type-correct body length.
fn encode_yamux_frame(tag: u8, flags: u16, stream_id: u32, length: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + body.len());
    v.push(0); // version
    v.push(tag);
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(&length.to_be_bytes());
    v.extend_from_slice(body);
    v
}

#[derive(Debug)]
enum Case {
    Header {
        bytes: Vec<u8>,
    },
    Connection {
        server: bool,
        loopback: bool,
        graceful_close: bool,
        wire: Vec<u8>,
    },
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Weights (sum = 10): Header 1 | Raw 1 | Closing 2 | Credit/RST 3 | Structured 3
        Ok(match u.int_in_range(0u8..=9)? {
            0 => {
                let len = u.int_in_range(0..=24)?;
                Case::Header {
                    bytes: u.bytes(len)?.to_vec(),
                }
            }
            1 => {
                let len = u.int_in_range(0..=1024)?;
                Case::Connection {
                    server: u.arbitrary()?,
                    loopback: u.ratio(1, 4)?,
                    graceful_close: !u.ratio(1, 8)?,
                    wire: u.bytes(len)?.to_vec(),
                }
            }
            2 | 3 => {
                // Closing-biased: stay Active for local `poll_close` (closing.rs).
                let mut wire = Vec::new();
                let body_len = u.int_in_range(0..=64)?;
                let body = u.bytes(body_len)?.to_vec();
                wire.extend_from_slice(&encode_yamux_frame(
                    0,
                    FLAG_SYN,
                    1,
                    body_len as u32,
                    &body,
                ));
                match u.int_in_range(0u8..=2)? {
                    0 => wire.extend_from_slice(&encode_yamux_frame(0, FLAG_FIN, 1, 0, &[])),
                    1 => wire.extend_from_slice(&encode_yamux_frame(0, FLAG_RST, 1, 0, &[])),
                    _ => {}
                }
                if u.ratio(1, 2)? {
                    wire.extend_from_slice(&encode_yamux_frame(1, 0, 1, 1, &[]));
                }
                Case::Connection {
                    server: true,
                    loopback: u.ratio(1, 2)?,
                    graceful_close: true,
                    wire,
                }
            }
            4 | 5 | 6 => {
                // Credit-exhaust + RST edges (stream.rs / flow_control).
                let mut wire = Vec::new();
                let n_streams = u.int_in_range(1u32..=3)?;
                for i in 0..n_streams {
                    let sid = 1 + i * 2; // odd client ids for server accept
                    let body_len = u.int_in_range(0..=128)?;
                    let body = u.bytes(body_len)?.to_vec();
                    wire.extend_from_slice(&encode_yamux_frame(
                        0,
                        FLAG_SYN,
                        sid,
                        body_len as u32,
                        &body,
                    ));
                    // Extra Data to fill recv path before RST / WU.
                    if u.ratio(1, 2)? {
                        let dlen = u.int_in_range(1..=64)?;
                        let dbody = u.bytes(dlen)?.to_vec();
                        wire.extend_from_slice(&encode_yamux_frame(
                            0,
                            0,
                            sid,
                            dlen as u32,
                            &dbody,
                        ));
                    }
                    // RST edge variants.
                    match u.int_in_range(0u8..=4)? {
                        0 => {
                            // RST after SYN Data
                            wire.extend_from_slice(&encode_yamux_frame(0, FLAG_RST, sid, 0, &[]));
                        }
                        1 => {
                            // FIN then RST
                            wire.extend_from_slice(&encode_yamux_frame(0, FLAG_FIN, sid, 0, &[]));
                            wire.extend_from_slice(&encode_yamux_frame(0, FLAG_RST, sid, 0, &[]));
                        }
                        2 => {
                            // RST with ACK
                            wire.extend_from_slice(&encode_yamux_frame(
                                0,
                                FLAG_RST | FLAG_ACK,
                                sid,
                                0,
                                &[],
                            ));
                        }
                        3 => {
                            // Tiny WindowUpdate only (local soak exhausts send credit)
                            wire.extend_from_slice(&encode_yamux_frame(1, 0, sid, 1, &[]));
                        }
                        _ => {
                            // No terminal flag — driver credit-soak on held stream
                        }
                    }
                }
                // Orphan RST on never-opened stream id.
                if u.ratio(2, 3)? {
                    let orphan = 1 + n_streams * 2 + 10;
                    wire.extend_from_slice(&encode_yamux_frame(0, FLAG_RST, orphan, 0, &[]));
                }
                // Huge WindowUpdate → InvalidWindowUpdate / wrap edge.
                if u.ratio(1, 5)? {
                    let sid = 1u32;
                    wire.extend_from_slice(&encode_yamux_frame(1, 0, sid, u32::MAX / 2, &[]));
                }
                Case::Connection {
                    // Prefer server so odd SYN accepts; client empty+soak also via driver.
                    server: !u.ratio(1, 4)?,
                    // Avoid loopback during credit soak (loopback can grant WU via echo).
                    loopback: u.ratio(1, 6)?,
                    graceful_close: true,
                    wire,
                }
            }
            _ => {
                // Structured type-correct frames.
                let n = u.int_in_range(1..=MAX_FRAMES)?;
                let mut wire = Vec::new();
                let mut next_id = 1u32;
                for i in 0..n {
                    let tag = u.int_in_range(0u8..=3)?;
                    let (flags, stream_id, length, body) = match tag {
                        0 => {
                            let body_len = u.int_in_range(0..=MAX_DATA_BODY)?;
                            let body = u.bytes(body_len)?.to_vec();
                            let mut flags = 0u16;
                            if i == 0 {
                                flags |= FLAG_SYN;
                            }
                            match u.int_in_range(0u8..=5)? {
                                0 | 1 => flags |= FLAG_FIN,
                                2 | 3 => flags |= FLAG_RST, // bias RST
                                4 => flags |= FLAG_FIN | FLAG_ACK,
                                _ => {}
                            }
                            let sid = next_id;
                            next_id = next_id.saturating_add(2);
                            (flags, sid, body_len as u32, body)
                        }
                        1 => {
                            let credit = match u.int_in_range(0u8..=4)? {
                                0 => 0u32, // zero credit edge
                                1 => 1,
                                2 => 64,
                                3 => 256,
                                _ => u.int_in_range(1u32..=65_536)?,
                            };
                            let mut flags = 0u16;
                            if u.ratio(1, 6)? {
                                flags |= FLAG_SYN;
                            }
                            (flags, next_id.saturating_sub(2).max(1), credit, Vec::new())
                        }
                        2 => {
                            let flags = if u.arbitrary()? { FLAG_SYN } else { FLAG_ACK };
                            let id = u.arbitrary::<u32>()?;
                            (flags, 0u32, id, Vec::new())
                        }
                        _ => {
                            let code = u.int_in_range(0u32..=2)?;
                            (0u16, 0u32, code, Vec::new())
                        }
                    };
                    wire.extend_from_slice(&encode_yamux_frame(
                        tag, flags, stream_id, length, &body,
                    ));
                }
                Case::Connection {
                    server: u.arbitrary()?,
                    loopback: u.ratio(1, 3)?,
                    graceful_close: !u.ratio(1, 6)?,
                    wire,
                }
            }
        })
    }
}

fuzz_target!(|data: &[u8]| {
    // Prefer structured `Case` when entropy parses; otherwise treat the whole
    // blob as Yamux wire with graceful close (so raw seeds hit closing.rs).
    let mut u = Unstructured::new(data);
    let case = Case::arbitrary(&mut u).unwrap_or(Case::Connection {
        server: true,
        loopback: false,
        graceful_close: true,
        wire: data.to_vec(),
    });
    match case {
        Case::Header { bytes } => {
            yamux::fuzz_header_codec(&bytes);
            if !bytes.is_empty() && bytes.len() <= 12 {
                yamux::fuzz_connection(&bytes, true);
            }
        }
        Case::Connection {
            server,
            loopback,
            graceful_close,
            wire,
        } => {
            yamux::fuzz_header_codec(&wire);
            yamux::fuzz_connection_ex(&wire, server, loopback, graceful_close);
        }
    }
});
