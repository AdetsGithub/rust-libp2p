#![no_main]

//! ConnectionHandler mock-stream fuzzer for `libp2p-identify`.
//!
//! Feeds length-delimited Identify protobuf frames into [`fuzz_handler_io`]
//! across outbound-identify / inbound-push / encode roles, plus DialUpgradeError.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_identify::{
    MAX_MSG_BYTES, OutboundDrive, StreamRole, StructuredIdentifyKind, encode_structured_wire,
    fuzz_handler_io,
};

#[derive(Debug)]
struct Case {
    chunks: Vec<Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    role: StreamRole,
    outbound: OutboundDrive,
    trigger_push: bool,
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let outbound = match u.int_in_range(0u8..=7)? {
            0 | 1 => OutboundDrive::DialUpgradeTimeout,
            2 => OutboundDrive::DialUpgradeNegotiationFailed,
            _ => OutboundDrive::MockNegotiated,
        };
        let role = match u.int_in_range(0u8..=5)? {
            0 | 1 | 2 => StreamRole::OutboundIdentify, // bias parse path
            3 => StreamRole::InboundPush,
            4 => StreamRole::InboundIdentify,
            _ => StreamRole::OutboundPush,
        };

        let mode = u.int_in_range(0u8..=3)?;
        let (chunks, chunk_cap) = match mode {
            0 => {
                let n = u.int_in_range(1usize..=3)?;
                let mut chunks = Vec::with_capacity(n);
                for _ in 0..n {
                    let kind = match u.int_in_range(0u8..=4)? {
                        0 => StructuredIdentifyKind::MatchingPeer,
                        1 => StructuredIdentifyKind::MismatchedPeer,
                        2 => StructuredIdentifyKind::LargeLists,
                        3 => StructuredIdentifyKind::PushPartial,
                        _ => StructuredIdentifyKind::WithSignedRecord,
                    };
                    chunks.push(encode_structured_wire(kind, u.arbitrary()?));
                }
                (chunks, u.int_in_range(1usize..=16)?)
            }
            1 => (
                vec![encode_structured_wire(
                    StructuredIdentifyKind::MatchingPeer,
                    0,
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
        Ok(Case {
            chunks,
            chunk_cap,
            reset_every,
            role,
            outbound,
            trigger_push: u.ratio(1, 4)?,
        })
    }
}

fuzz_target!(|case: Case| {
    let _ = fuzz_handler_io(
        case.chunks,
        case.chunk_cap,
        case.reset_every,
        case.role,
        case.outbound,
        case.trigger_push,
    );
});
