#![no_main]

//! Action-sequence fuzzer for `libp2p-autonat` v1 [`Behaviour`].
//!
//! FOCUS: dial-back probe clock, confidence flips, inbound DialRequest
//! throttle, Kad-style outbound request_slot / mismatch attribution.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_autonat::{FuzzAction, MAX_ACTIONS, PEER_POOL, fuzz_behaviour};

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
    // Setup: connect server → add_server → candidate → probe → dial-back.
    if step == 0 {
        return Ok(FuzzAction::Connect {
            peer_slot: 0,
            outbound: true,
        });
    }
    if step == 1 {
        return Ok(FuzzAction::AddServer {
            peer_slot: 0,
            with_addr: true,
        });
    }
    if step == 2 {
        return Ok(FuzzAction::NewExternalCandidate { slot: 1 });
    }
    if step == 3 {
        return Ok(FuzzAction::AdvanceProbeClock);
    }
    if step == 4 {
        return Ok(FuzzAction::InjectDialBack {
            peer_slot: 0,
            request_slot: 0,
            mismatch: false,
            success: u.ratio(2, 3)?,
            addr_slot: 1,
        });
    }
    if step == 5 {
        return Ok(FuzzAction::Connect {
            peer_slot: 1,
            outbound: false,
        });
    }
    if step == 6 {
        return Ok(FuzzAction::InjectInboundDialRequest {
            peer_slot: 1,
            addr_count: 2,
        });
    }

    // Weights (sum = 20):
    //   InjectDialBack 4 | AdvanceProbeClock 3 | FloodAdvance 2 | Connect 2
    //   InboundDial 2 | Candidate 2 | AddServer 1 | DialFailure 1
    //   Disconnect 1 | ProbeAddress 1 | rest 1
    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    Ok(match u.int_in_range(0u8..=19)? {
        0..=3 => FuzzAction::InjectDialBack {
            peer_slot,
            request_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 4)?,
            success: u.ratio(1, 2)?,
            addr_slot: u.arbitrary()?,
        },
        4..=6 => FuzzAction::AdvanceProbeClock,
        7..=8 => FuzzAction::FloodAdvanceProbe {
            count: u.arbitrary()?,
        },
        9..=10 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 2)?,
        },
        11..=12 => FuzzAction::InjectInboundDialRequest {
            peer_slot,
            addr_count: u.arbitrary()?,
        },
        13..=14 => FuzzAction::NewExternalCandidate {
            slot: u.arbitrary()?,
        },
        15 => FuzzAction::AddServer {
            peer_slot,
            with_addr: u.ratio(1, 2)?,
        },
        16 => FuzzAction::DialFailure { peer_slot },
        17 => FuzzAction::Disconnect { peer_slot },
        18 => FuzzAction::ProbeAddress {
            slot: u.arbitrary()?,
        },
        _ => FuzzAction::NewListenAddr {
            slot: u.arbitrary()?,
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
