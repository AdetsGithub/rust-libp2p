#![no_main]

//! Action-sequence fuzzer for `libp2p-request-response::Behaviour`.
//!
//! Targets QueryId-style attribution (Kad `query_slot` / `mismatch`):
//! concurrent outbound ring walks, ghost responses, stale timeouts vs late
//! responses, inbound/outbound races.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_request_response::{
    FuzzAction, MAX_ACTIONS, MAX_MSG_BYTES, PEER_POOL, fuzz_behaviour,
};

#[derive(Debug)]
struct ActionSeq(Vec<FuzzAction>);

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.int_in_range(10..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        Ok(ActionSeq(actions))
    }
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: two peers, concurrent SendRequest ×2, then mismatch + older-slot.
    if step == 0 {
        return Ok(FuzzAction::Connect {
            peer_slot: 0,
            outbound: true,
        });
    }
    if step == 1 {
        return Ok(FuzzAction::Connect {
            peer_slot: 1,
            outbound: false,
        });
    }
    if step == 2 {
        return Ok(FuzzAction::SendRequest {
            peer_slot: 0,
            data: capped_bytes(u, 64)?,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::SendRequest {
            peer_slot: 0,
            data: capped_bytes(u, 64)?,
        });
    }
    if step == 4 {
        return Ok(FuzzAction::InjectResponse {
            peer_slot: 0,
            request_slot: 0,
            mismatch: true,
            data: capped_bytes(u, 64)?,
        });
    }
    if step == 5 {
        return Ok(FuzzAction::InjectResponse {
            peer_slot: 0,
            request_slot: 1,
            mismatch: false,
            data: capped_bytes(u, 64)?,
        });
    }
    if step == 6 {
        return Ok(FuzzAction::InjectRequest {
            peer_slot: 1,
            inbound_slot: 0,
            data: capped_bytes(u, 64)?,
        });
    }
    if step == 7 {
        return Ok(FuzzAction::InjectInboundTimeout {
            peer_slot: 1,
            request_slot: 0,
            mismatch: u.ratio(1, 3)?,
        });
    }

    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    // Weights (sum = 20): InjectResponse(+mismatch) 4 | Timeout 3 | SendRequest 3
    //   InjectRequest 2 | StreamFailed 2 | SendResponse 1 | Omission 1
    //   Blackhole 1 | Connect 1 | Disconnect 1 | rest 1
    Ok(match u.int_in_range(0u8..=19)? {
        0..=3 => FuzzAction::InjectResponse {
            peer_slot,
            request_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 3)?,
            data: capped_bytes(u, 256)?,
        },
        4..=5 => FuzzAction::InjectOutboundTimeout {
            peer_slot,
            request_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 4)?,
        },
        6 => FuzzAction::InjectInboundTimeout {
            peer_slot,
            request_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 4)?,
        },
        7..=9 => FuzzAction::SendRequest {
            peer_slot,
            data: capped_bytes(u, 256)?,
        },
        10..=11 => FuzzAction::InjectRequest {
            peer_slot,
            inbound_slot: u.arbitrary()?,
            data: capped_bytes(u, 256)?,
        },
        12..=13 => FuzzAction::InjectOutboundStreamFailed {
            peer_slot,
            request_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 4)?,
        },
        14 => FuzzAction::SendResponse {
            peer_slot,
            inbound_slot: u.arbitrary()?,
            data: capped_bytes(u, 256)?,
        },
        15 => FuzzAction::InjectResponseOmission {
            peer_slot,
            inbound_slot: u.arbitrary()?,
        },
        16 => FuzzAction::BlackholeResponse {
            peer_slot,
            inbound_slot: u.arbitrary()?,
        },
        17 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 2)?,
        },
        18 => FuzzAction::Disconnect { peer_slot },
        _ => FuzzAction::SendRequest {
            peer_slot,
            data: capped_bytes(u, 256)?,
        },
    })
}

fn capped_bytes(u: &mut Unstructured<'_>, max: usize) -> arbitrary::Result<Vec<u8>> {
    let cap = max.min(MAX_MSG_BYTES);
    let len = u.int_in_range(0usize..=cap)?;
    Ok(u.bytes(len)?.to_vec())
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
