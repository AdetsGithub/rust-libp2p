#![no_main]

//! Action-sequence fuzzer for AutoNAT v2 **server** Behaviour.
//!
//! FOCUS: dial-request → dial-back command flood vs soft clamp, DialFailure /
//! dial-back success races, status-event emission.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_autonat::{
    V2ServerFuzzAction as FuzzAction, V2_SERVER_MAX_ACTIONS as MAX_ACTIONS,
    V2_SERVER_PEER_POOL as PEER_POOL, fuzz_behaviour_v2_server as fuzz_behaviour,
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
    if step == 0 {
        return Ok(FuzzAction::Connect {
            peer_slot: 0,
            outbound: false,
        });
    }
    if step == 1 {
        return Ok(FuzzAction::InjectDialRequest {
            peer_slot: 0,
            addr_count: 2,
        });
    }
    if step == 2 {
        return Ok(FuzzAction::InjectDialBackResult {
            peer_slot: 0,
            success: u.ratio(1, 2)?,
            dial_slot: 0,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::InjectStatusEvent {
            peer_slot: 0,
            success: u.ratio(2, 3)?,
            addr_slot: 1,
        });
    }

    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    // Weights (sum = 16): DialRequest 3 | DialBackResult 3 | Flood 2 | Timeout 2
    //   Status 2 | Connect 2 | Disconnect 1 | rest 1
    Ok(match u.int_in_range(0u8..=15)? {
        0..=2 => FuzzAction::InjectDialRequest {
            peer_slot,
            addr_count: u.arbitrary()?,
        },
        3..=5 => FuzzAction::InjectDialBackResult {
            peer_slot,
            success: u.ratio(1, 2)?,
            dial_slot: u.arbitrary()?,
        },
        6..=7 => FuzzAction::FloodDialRequests {
            peer_slot,
            count: u.arbitrary()?,
        },
        8..=9 => FuzzAction::AdvanceTimeout {
            all: u.ratio(1, 2)?,
        },
        10..=11 => FuzzAction::InjectStatusEvent {
            peer_slot,
            success: u.ratio(1, 2)?,
            addr_slot: u.arbitrary()?,
        },
        12..=13 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 4)?, // bias inbound (dial-request path)
        },
        14 => FuzzAction::Disconnect { peer_slot },
        _ => FuzzAction::AdvanceTimeout { all: true },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
