#![no_main]

//! Action-sequence fuzzer for AutoNAT v2 **client** Behaviour.
//!
//! FOCUS: candidate flood vs max_candidates, dial-back nonce attribution,
//! TestOutcome success/failure races with probe clock.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_autonat::{
    V2FuzzAction as FuzzAction, V2_MAX_ACTIONS as MAX_ACTIONS, V2_PEER_POOL as PEER_POOL,
    fuzz_behaviour_v2 as fuzz_behaviour,
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
        return Ok(FuzzAction::InjectPeerHasServerSupport { peer_slot: 0 });
    }
    if step == 3 {
        return Ok(FuzzAction::NewExternalCandidate { slot: 0 });
    }
    if step == 4 {
        return Ok(FuzzAction::AdvanceProbeClock);
    }
    if step == 5 {
        return Ok(FuzzAction::InjectDialBackNonce {
            peer_slot: 1,
            mismatch: false,
            nonce_slot: 0,
        });
    }
    if step == 6 {
        return Ok(FuzzAction::InjectTestOutcome {
            peer_slot: 0,
            success: u.ratio(2, 3)?,
            nonce_slot: 0,
            mismatch: false,
        });
    }

    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    // Weights (sum = 16): DialBack 3 | TestOutcome 3 | Advance 2 | Candidate 2
    //   Flood 2 | Support 1 | Connect 1 | Disconnect 1 | rest 1
    Ok(match u.int_in_range(0u8..=15)? {
        0..=2 => FuzzAction::InjectDialBackNonce {
            peer_slot,
            mismatch: u.ratio(1, 4)?,
            nonce_slot: u.arbitrary()?,
        },
        3..=5 => FuzzAction::InjectTestOutcome {
            peer_slot,
            success: u.ratio(1, 2)?,
            nonce_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 4)?,
        },
        6..=7 => FuzzAction::AdvanceProbeClock,
        8..=9 => FuzzAction::NewExternalCandidate {
            slot: u.arbitrary()?,
        },
        10..=11 => FuzzAction::FloodCandidates {
            count: u.arbitrary()?,
        },
        12 => FuzzAction::InjectPeerHasServerSupport { peer_slot },
        13 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 2)?,
        },
        14 => FuzzAction::Disconnect { peer_slot },
        _ => FuzzAction::NewExternalCandidate {
            slot: u.arbitrary()?,
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
