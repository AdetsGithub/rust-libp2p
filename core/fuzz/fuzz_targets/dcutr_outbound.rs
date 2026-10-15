#![no_main]

//! Fuzzer for the DCUtR **dialer-side** hole-punch (`protocol/outbound.rs`),
//! which was previously 0%-covered: the behaviour harness only drives the
//! relayed inbound/outbound *events* and the `dummy` direct handler, never the
//! `relayed::Handler` listener-side upgrade that runs `outbound::handshake`.
//!
//! Arms:
//!   - Well-formed CONNECT response → `OutboundConnectNegotiated` (success)
//!   - SYNC response (wrong type) / empty addrs / raw garbage / EOF →
//!     `OutboundConnectFailed` with the corresponding `outbound::Error`
//!   - Write faults (`write_cap`/`stall`) stress the CONNECT/SYNC encode.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_core::Multiaddr;
use libp2p_dcutr::{StructuredHolePunchKind, WriteFault, encode_structured_holepunch_wire, fuzz_outbound_holepunch};

#[derive(Debug)]
struct Case {
    response_wire: Vec<u8>,
    candidates: Vec<Multiaddr>,
    write: WriteFault,
}

fn candidate(slot: u8) -> Multiaddr {
    format!("/ip4/203.0.113.{}/tcp/{}", 1 + slot % 200, 9100 + slot as u16)
        .parse()
        .expect("candidate multiaddr")
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bias: ~½ valid CONNECT response, rest split across malformed arms.
        let response_wire = match u.int_in_range(0u8..=7)? {
            0..=3 => encode_structured_holepunch_wire(StructuredHolePunchKind::Connect, u.arbitrary()?),
            4 => encode_structured_holepunch_wire(StructuredHolePunchKind::Sync, u.arbitrary()?),
            5 => encode_structured_holepunch_wire(StructuredHolePunchKind::EmptyAddrs, u.arbitrary()?),
            6 => encode_structured_holepunch_wire(StructuredHolePunchKind::ManyAddrs, u.arbitrary()?),
            _ => {
                let len = u.int_in_range(0usize..=64)?;
                u.bytes(len)?.to_vec()
            }
        };

        let n = u.int_in_range(0usize..=8)?;
        let mut candidates = Vec::with_capacity(n);
        for i in 0..n {
            candidates.push(candidate(i as u8));
        }

        let write = if u.ratio(1, 2)? {
            WriteFault {
                write_cap: u.int_in_range(1usize..=8)?,
                stall_every: u.int_in_range(1usize..=4)?,
                err_every: 0,
                flush_stall_every: 0,
            }
        } else {
            WriteFault::NONE
        };

        Ok(Case {
            response_wire,
            candidates,
            write,
        })
    }
}

fuzz_target!(|case: Case| {
    let _ = fuzz_outbound_holepunch(case.response_wire, case.candidates, case.write);
});
