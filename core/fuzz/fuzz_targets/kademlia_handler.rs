#![no_main]

//! ConnectionHandler mock-stream fuzzer for `libp2p-kad`.
//!
//! Feeds length-delimited DHT request frames into [`fuzz_handler_io`] and
//! optionally enqueues an outbound FindNode for the request/response path.
//! Dedicated arms drive DialUpgradeError::Timeout and idle FuturesTupleSet
//! TimedOut so `HandlerQueryErr::Io(TimedOut)` is reachable.
//! [`WriteFault`] stresses request/response encode under backpressure.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_kad::{
    MAX_MSG_BYTES, OutboundDrive, StructuredInboundKind, WriteFault, encode_structured_wire,
    fuzz_handler_io,
};

#[derive(Debug)]
struct Case {
    chunks: Vec<Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    enqueue_outbound_find_node: bool,
    outbound: OutboundDrive,
    write: WriteFault,
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bias ~½ toward DialUpgrade / idle TimedOut arms (sum weights 12).
        let outbound = match u.int_in_range(0u8..=11)? {
            0 | 1 => OutboundDrive::DialUpgradeTimeout,
            2 => OutboundDrive::SubstreamIdleTimeout,
            3 => OutboundDrive::DialUpgradeNegotiationFailed,
            4 => OutboundDrive::DialUpgradeApply,
            5 => OutboundDrive::DialUpgradeIo,
            _ => OutboundDrive::MockResponse,
        };

        let mode = u.int_in_range(0u8..=3)?;
        let (chunks, chunk_cap) = match mode {
            0 => {
                let n = u.int_in_range(1usize..=4)?;
                let mut chunks = Vec::with_capacity(n);
                for _ in 0..n {
                    let kind = match u.int_in_range(0u8..=3)? {
                        0 => StructuredInboundKind::FindNode,
                        1 => StructuredInboundKind::GetProviders,
                        2 => StructuredInboundKind::GetValue,
                        _ => StructuredInboundKind::PutValue,
                    };
                    chunks.push(encode_structured_wire(kind, u.arbitrary()?, None));
                }
                (chunks, u.int_in_range(1usize..=16)?)
            }
            1 => (
                vec![encode_structured_wire(
                    StructuredInboundKind::FindNode,
                    0,
                    None,
                )],
                1,
            ),
            2 => {
                let len = u.int_in_range(0usize..=MAX_MSG_BYTES.min(512))?;
                (vec![u.bytes(len)?.to_vec()], u.int_in_range(1usize..=64)?)
            }
            _ => {
                let n = u.int_in_range(0usize..=8)?;
                let mut chunks = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = u.int_in_range(0usize..=64)?;
                    chunks.push(u.bytes(len)?.to_vec());
                }
                (chunks, u.int_in_range(1usize..=8)?)
            }
        };
        let reset_every = if u.ratio(1, 8)? {
            u.int_in_range(1usize..=8)?
        } else {
            0
        };
        // Bias: partial OR stall (combined tiny+stall can starve noop_waker drain).
        let write = if u.ratio(1, 2)? {
            match u.int_in_range(0u8..=2)? {
                0 => WriteFault {
                    write_cap: u.int_in_range(1usize..=8)?,
                    stall_every: 0,
                    err_every: 0,
                },
                1 => WriteFault {
                    write_cap: 0,
                    stall_every: u.int_in_range(1usize..=4)?,
                    err_every: 0,
                },
                _ => WriteFault {
                    write_cap: u.int_in_range(4usize..=16)?,
                    stall_every: u.int_in_range(2usize..=6)?,
                    err_every: if u.ratio(1, 8)? {
                        u.int_in_range(4usize..=16)?
                    } else {
                        0
                    },
                },
            }
        } else {
            WriteFault::NONE
        };
        Ok(Case {
            chunks,
            chunk_cap,
            reset_every,
            // Timeout / write-stress arms force enqueue inside fuzz_handler_io.
            enqueue_outbound_find_node: write.is_stressed() || u.ratio(1, 2)?,
            outbound,
            write,
        })
    }
}

fuzz_target!(|case: Case| {
    let _ = fuzz_handler_io(
        case.chunks,
        case.chunk_cap,
        case.reset_every,
        case.enqueue_outbound_find_node,
        case.outbound,
        case.write,
    );
});
