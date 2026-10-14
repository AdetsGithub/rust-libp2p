#![no_main]

//! Action-sequence fuzzer for `libp2p-dcutr::Behaviour`.
//!
//! FOCUS: concurrent upgrade attempts, hole-punch wire inject, dial-failure
//! floods vs attempt budget, teardown races.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_dcutr::{
    FuzzAction, MAX_ACTIONS, StructuredHolePunchKind, fuzz_behaviour,
};

#[derive(Debug)]
struct ActionSeq(Vec<FuzzAction>);

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Setup occupies steps 0..=8 (hole-punch / attempt-exceed / teardown).
        let n = u.int_in_range(12..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        Ok(ActionSeq(actions))
    }
}

fn pick_holepunch(u: &mut Unstructured<'_>) -> arbitrary::Result<StructuredHolePunchKind> {
    // Bias protocol-violation / Sync / ManyAddrs (deny / replace-stream arms).
    Ok(match u.int_in_range(0u8..=7)? {
        0 | 1 => StructuredHolePunchKind::Connect,
        2 | 3 => StructuredHolePunchKind::Sync,
        4 | 5 => StructuredHolePunchKind::EmptyAddrs,
        _ => StructuredHolePunchKind::ManyAddrs,
    })
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: relayed peer → hole-punch under WriteFault → flood past attempt
    // budget → concurrent teardown → outbound fail.
    if step == 0 {
        return Ok(FuzzAction::NewExternalAddrCandidate { slot: 0 });
    }
    if step == 1 {
        return Ok(FuzzAction::ConnectRelayed {
            peer_slot: 1,
            relay_slot: 0,
            outbound: true,
        });
    }
    if step == 2 {
        // Even-length wire → WriteFault::stressed in inject_inbound_holepunch.
        return Ok(FuzzAction::InjectHolePunchWire {
            peer_slot: 1,
            kind: StructuredHolePunchKind::Connect,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::InjectHolePunchWire {
            peer_slot: 1,
            kind: StructuredHolePunchKind::EmptyAddrs,
        });
    }
    if step == 4 {
        return Ok(FuzzAction::InjectInboundConnectNegotiated {
            peer_slot: 1,
            addr_slot: 2,
        });
    }
    // count=7 → exceeds MAX_NUMBER_OF_UPGRADE_ATTEMPTS (AttemptsExceeded).
    if step == 5 {
        return Ok(FuzzAction::FloodDialFailure {
            peer_slot: 1,
            count: 7,
        });
    }
    if step == 6 {
        return Ok(FuzzAction::ConcurrentUpgradeTeardown {
            peer_slot: 1,
            addr_slot: 2,
        });
    }
    if step == 7 {
        return Ok(FuzzAction::InjectOutboundConnectFailed { peer_slot: 1 });
    }
    if step == 8 {
        return Ok(FuzzAction::ConnectDirect {
            peer_slot: 2,
            outbound: true,
        });
    }

    // Weights (sum = 28) — deny / teardown / WriteFault-holepunch dense:
    //   HolePunchWire 6 | FloodDialFailure 5 | ConcurrentUpgradeTeardown 5
    //   OutboundFailed 3 | ConnectRelayed 3 | InjectInbound 2 | DialFailure 2
    //   ConnectDirect 1 | Disconnect 1
    Ok(match u.int_in_range(0u8..=27)? {
        0..=5 => FuzzAction::InjectHolePunchWire {
            peer_slot: 1, // keep on relayed peer from setup
            kind: pick_holepunch(u)?,
        },
        6..=10 => FuzzAction::FloodDialFailure {
            peer_slot: 1,
            count: u.int_in_range(4..=7)?,
        },
        11..=15 => FuzzAction::ConcurrentUpgradeTeardown {
            peer_slot: 1,
            addr_slot: u.arbitrary()?,
        },
        16..=18 => FuzzAction::InjectOutboundConnectFailed { peer_slot: 1 },
        19..=21 => FuzzAction::ConnectRelayed {
            peer_slot: u.arbitrary()?,
            relay_slot: u.arbitrary()?,
            outbound: u.arbitrary()?,
        },
        22..=23 => FuzzAction::InjectInboundConnectNegotiated {
            peer_slot: u.arbitrary()?,
            addr_slot: u.arbitrary()?,
        },
        24..=25 => FuzzAction::DialFailure {
            peer_slot: 1,
            relayed_conn: true,
        },
        26 => FuzzAction::ConnectDirect {
            peer_slot: u.arbitrary()?,
            outbound: u.arbitrary()?,
        },
        _ => FuzzAction::Disconnect {
            peer_slot: u.arbitrary()?,
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
