#![no_main]

//! Action-sequence fuzzer for `libp2p-identify::Behaviour`.
//!
//! Weights + structured Identify wire target cold branches: large listen_addrs /
//! protocols lists, peer-id mismatch discard, signedPeerRecord, push merge,
//! NewListenAddr → AddressesChanged/push, and DialUpgradeError.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_identify::{
    FuzzAction, FuzzSeed, MAX_ACTIONS, MAX_MSG_BYTES, PEER_POOL, StructuredIdentifyKind,
    encode_structured_wire, fuzz_behaviour_seeded,
};

#[derive(Debug)]
struct ActionSeq {
    seed: FuzzSeed,
    actions: Vec<FuzzAction>,
}

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Min 7 so setup reaches AdvanceInterval (step 6).
        let n = u.int_in_range(7..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        // Seed: ~½ start with live pre-connected handlers (skip Connect preamble).
        let live_peers = if u.ratio(1, 2)? {
            u.int_in_range(0u8..=PEER_POOL as u8)?
        } else {
            0
        };
        Ok(ActionSeq {
            seed: FuzzSeed { live_peers },
            actions,
        })
    }
}

fn pick_kind(u: &mut Unstructured<'_>) -> arbitrary::Result<StructuredIdentifyKind> {
    Ok(match u.int_in_range(0u8..=6)? {
        0 | 1 => StructuredIdentifyKind::MatchingPeer,
        2 => StructuredIdentifyKind::MismatchedPeer,
        3 | 4 => StructuredIdentifyKind::LargeLists, // bias DoS lists
        5 => StructuredIdentifyKind::PushPartial,
        _ => StructuredIdentifyKind::WithSignedRecord,
    })
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: connect a few peers, then identify + large lists + listen addr.
    if step < 2 {
        return Ok(FuzzAction::Connect {
            peer_slot: (step as u8) % PEER_POOL as u8,
            outbound: step % 2 == 0,
        });
    }
    if step == 2 {
        return Ok(FuzzAction::InjectOutboundIdentify {
            peer_slot: 0,
            kind: StructuredIdentifyKind::MatchingPeer,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::InjectStructured {
            peer_slot: 0,
            kind: StructuredIdentifyKind::LargeLists,
        });
    }
    if step == 4 {
        return Ok(FuzzAction::NewListenAddr { port: 4001 });
    }
    if step == 5 {
        return Ok(FuzzAction::Push { peer_slot: 0 });
    }
    if step == 6 {
        // Periodic identify after mesh is warm.
        return Ok(FuzzAction::AdvanceInterval { peer_slot: 0 });
    }

    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    // Weights sum 18: keep LargeLists/Mismatch warm; AdvanceInterval 2/18.
    Ok(match u.int_in_range(0u8..=17)? {
        0 | 1 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 2)?,
        },
        2 => FuzzAction::Disconnect { peer_slot },
        3 => FuzzAction::Push { peer_slot },
        4 | 5 => FuzzAction::InjectOutboundIdentify {
            peer_slot,
            kind: pick_kind(u)?,
        },
        6 | 7 => FuzzAction::InjectStructured {
            peer_slot,
            kind: pick_kind(u)?,
        },
        8 => {
            let len = u.int_in_range(0usize..=MAX_MSG_BYTES.min(256))?;
            FuzzAction::InjectWire {
                peer_slot,
                wire_bytes: u.bytes(len)?.to_vec(),
            }
        }
        9 => FuzzAction::InjectWire {
            peer_slot,
            wire_bytes: encode_structured_wire(pick_kind(u)?, peer_slot),
        },
        10 => FuzzAction::FailOutboundUpgrade {
            peer_slot,
            timeout: u.ratio(2, 3)?,
        },
        11 => FuzzAction::NewListenAddr {
            port: u.int_in_range(1u16..=65535)?,
        },
        12 => FuzzAction::ExternalAddrConfirmed { peer_slot },
        13 => FuzzAction::AddressesChanged {
            peer_slot,
            n_addrs: u.int_in_range(1u8..=32)?,
        },
        14 | 15 => FuzzAction::AdvanceInterval { peer_slot },
        _ => FuzzAction::InjectStructured {
            peer_slot,
            kind: StructuredIdentifyKind::LargeLists,
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour_seeded(seq.seed, seq.actions);
});
