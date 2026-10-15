#![no_main]

//! ConnectionHandler mock-stream fuzzer for `libp2p-gossipsub`.
//!
//! Feeds length-delimited wire chunks (optionally fragmented) into
//! [`fuzz_handler_io`] and optionally enqueues a Subscribe for the encode path.
//! Dedicated [`HandlerFault`] arms drive DialUpgradeError, MaxSubstreamAttempts,
//! and MessageDropped (timed-out Publish).

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_gossipsub::{
    HandlerFault, MAX_RPC_BYTES, StructuredRpcKind, WriteFault, encode_structured_wire,
    fuzz_handler_io,
};

#[derive(Debug)]
struct Case {
    chunks: Vec<Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    enqueue_subscribe: bool,
    fault: HandlerFault,
    write: WriteFault,
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bias ~⅜ toward structured ConnectionEvent / MessageDropped faults.
        let fault = match u.int_in_range(0u8..=7)? {
            0 => HandlerFault::DialUpgradeTimeout,
            1 => HandlerFault::DialUpgradeNegotiationFailed,
            2 => HandlerFault::DialUpgradeIo,
            3 => HandlerFault::MaxSubstreamAttemptsInbound,
            4 => HandlerFault::MaxSubstreamAttemptsOutbound,
            5 => HandlerFault::MessageDroppedTimedOut,
            _ => HandlerFault::None,
        };

        let mode = u.int_in_range(0u8..=3)?;
        let (chunks, chunk_cap) = match mode {
            // Structured full frames, small chunk_cap → partial reads.
            0 => {
                let n = u.int_in_range(1usize..=4)?;
                let mut chunks = Vec::with_capacity(n);
                for _ in 0..n {
                    let kind = match u.int_in_range(0u8..=6)? {
                        0 => StructuredRpcKind::Subscribe,
                        1 => StructuredRpcKind::Graft,
                        2 => StructuredRpcKind::IHave,
                        3 => StructuredRpcKind::Prune,
                        4 => StructuredRpcKind::PruneWithPx,
                        5 => StructuredRpcKind::Publish,
                        _ => StructuredRpcKind::PublishBadSig,
                    };
                    chunks.push(encode_structured_wire(
                        kind,
                        u.arbitrary()?,
                        u.arbitrary()?,
                    ));
                }
                let cap = u.int_in_range(1usize..=16)?;
                (chunks, cap)
            }
            // One structured frame split into 1-byte chunks in the driver via cap=1.
            1 => {
                let kind = StructuredRpcKind::Subscribe;
                (vec![encode_structured_wire(kind, 0, 0)], 1)
            }
            // Raw fuzz bytes as a single chunk.
            2 => {
                let len = u.int_in_range(0usize..=MAX_RPC_BYTES.min(512))?;
                (vec![u.bytes(len)?.to_vec()], u.int_in_range(1usize..=64)?)
            }
            // Multiple tiny raw fragments.
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
                    flush_stall_every: 0,
                    drop_every: 0,
                },
                1 => WriteFault {
                    write_cap: 0,
                    stall_every: u.int_in_range(1usize..=4)?,
                    err_every: 0,
                    flush_stall_every: 0,
                    drop_every: 0,
                },
                _ => WriteFault {
                    write_cap: u.int_in_range(4usize..=16)?,
                    stall_every: u.int_in_range(2usize..=6)?,
                    err_every: if u.ratio(1, 8)? {
                        u.int_in_range(4usize..=16)?
                    } else {
                        0
                    },
                    flush_stall_every: 0,
                    drop_every: 0,
                },
            }
        } else {
            WriteFault::NONE
        };
        Ok(Case {
            chunks,
            chunk_cap,
            reset_every,
            // Prefer enqueue when write-stressed so outbound encode runs.
            enqueue_subscribe: write.is_stressed() || u.ratio(1, 2)?,
            fault,
            write,
        })
    }
}

fuzz_target!(|case: Case| {
    let _ = fuzz_handler_io(
        case.chunks,
        case.chunk_cap,
        case.reset_every,
        case.enqueue_subscribe,
        case.fault,
        case.write,
    );
});
