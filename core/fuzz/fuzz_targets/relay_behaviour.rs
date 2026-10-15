#![no_main]

//! Action-sequence fuzzer for `libp2p-relay::Behaviour`.
//!
//! FOCUS weights: reservation/circuit DoS floods, concurrent hop teardown,
//! ghost [`CircuitId`] closes, structured hop/stop wire.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_relay::{
    FuzzAction, MAX_ACTIONS, MAX_MSG_BYTES, PEER_POOL, StructuredHopKind, StructuredStopKind,
    encode_structured_hop_wire, encode_structured_stop_wire, fuzz_behaviour_rate_limited,
};

#[derive(Debug)]
struct ActionSeq(Vec<FuzzAction>);

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Setup occupies steps 0..=12 (deny floods + WriteFault hop/stop).
        let n = u.int_in_range(15..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        Ok(ActionSeq(actions))
    }
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: enable → multi-conn peer0 + peers 1..2 → fill caps → deny floods.
    // Caps: max_reservations=2 / per_peer=1 / max_circuits=2 / per_peer=1.
    if step == 0 {
        return Ok(FuzzAction::ConfirmExternalAddr { slot: 0 });
    }
    if step == 1 {
        return Ok(FuzzAction::SetStatusEnable);
    }
    // Two conns on peer 0 so per-peer Active can exceed max_reservations_per_peer.
    if step == 2 {
        return Ok(FuzzAction::Connect {
            peer_slot: 0,
            outbound: true,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::Connect {
            peer_slot: 0,
            outbound: false,
        });
    }
    if step == 4 {
        return Ok(FuzzAction::Connect {
            peer_slot: 1,
            outbound: false,
        });
    }
    if step == 5 {
        return Ok(FuzzAction::Connect {
            peer_slot: 2,
            outbound: true,
        });
    }
    // Fill global max_reservations (=2).
    if step == 6 {
        return Ok(FuzzAction::InjectReservationReq { peer_slot: 0 });
    }
    if step == 7 {
        return Ok(FuzzAction::InjectReservationReq { peer_slot: 1 });
    }
    // Global full → DenyReservationReq; rotate conns for per-peer arm.
    if step == 8 {
        return Ok(FuzzAction::FloodReservations {
            peer_slot: 2,
            count: 7,
        });
    }
    // Exceed circuit caps → CircuitReqDenied.
    if step == 9 {
        return Ok(FuzzAction::FloodCircuits {
            src_slot: 0,
            dst_slot: 1,
            count: 7,
        });
    }
    if step == 10 {
        return Ok(FuzzAction::ConcurrentTeardown {
            src_slot: 0,
            dst_slot: 1,
        });
    }
    // Hop wire under WriteFault (even peer_slot) + MalformedPeer deny arm.
    if step == 11 {
        return Ok(FuzzAction::InjectHopWire {
            peer_slot: 0, // even → WriteFault stressed
            wire: encode_structured_hop_wire(StructuredHopKind::MalformedPeer, 0),
        });
    }
    if step == 12 {
        return Ok(FuzzAction::InjectStopWire {
            peer_slot: 0,
            wire: encode_structured_stop_wire(StructuredStopKind::Connect { src_slot: 1 }),
        });
    }

    // Coverage-biased weights (sum = 32) — deny / teardown / WriteFault-hop dense:
    //   FloodReservations 5 | FloodCircuits 5 | ConcurrentTeardown 4
    //   InjectCircuitClosed 3 | Disable 2 | HopWire(even+malformed) 4
    //   StopWire 3 | Connect 2 | TimedOut 1 | Disconnect 1 | rest 2
    Ok(match u.int_in_range(0u8..=31)? {
        0..=4 => FuzzAction::FloodReservations {
            peer_slot: u.arbitrary()?,
            count: u.int_in_range(4..=7)?,
        },
        5..=9 => FuzzAction::FloodCircuits {
            src_slot: u.arbitrary()?,
            dst_slot: u.arbitrary()?,
            count: u.int_in_range(4..=7)?,
        },
        10..=13 => FuzzAction::ConcurrentTeardown {
            src_slot: u.arbitrary()?,
            dst_slot: u.arbitrary()?,
        },
        14..=16 => FuzzAction::InjectCircuitClosed {
            peer_slot: u.arbitrary()?,
            dst_slot: u.arbitrary()?,
            circuit_slot: u.arbitrary()?,
            mismatch: u.ratio(1, 2)?,
        },
        17..=18 => FuzzAction::SetStatusDisable,
        19..=22 => {
            // Bias even peer_slot so hop_write_fault stresses encode/flush.
            let peer_slot = (u.arbitrary::<u8>()? % (PEER_POOL as u8 / 2)) * 2;
            let kind = match u.int_in_range(0u8..=3)? {
                0 => StructuredHopKind::Reserve,
                1 => StructuredHopKind::Connect {
                    dst_slot: u.arbitrary()?,
                },
                2 => StructuredHopKind::MalformedPeer, // deny / bad peer
                _ => StructuredHopKind::StatusOk,
            };
            FuzzAction::InjectHopWire {
                peer_slot,
                wire: encode_structured_hop_wire(kind, u.arbitrary()?),
            }
        }
        23..=25 => {
            let kind = if u.ratio(2, 3)? {
                StructuredStopKind::Connect {
                    src_slot: u.arbitrary()?,
                }
            } else {
                StructuredStopKind::Status
            };
            FuzzAction::InjectStopWire {
                peer_slot: (u.arbitrary::<u8>()? % (PEER_POOL as u8 / 2)) * 2,
                wire: encode_structured_stop_wire(kind),
            }
        }
        26..=27 => FuzzAction::Connect {
            peer_slot: u.arbitrary()?,
            outbound: u.arbitrary()?,
        },
        28 => FuzzAction::InjectReservationTimedOut {
            peer_slot: u.arbitrary()?,
        },
        29 => FuzzAction::Disconnect {
            peer_slot: u.arbitrary()?,
        },
        30 => FuzzAction::SetStatusEnable,
        _ => {
            let len = u.int_in_range(0..=MAX_MSG_BYTES.min(256))?;
            FuzzAction::InjectHopWire {
                peer_slot: 0,
                wire: u.bytes(len)?.to_vec(),
            }
        }
    })
}

fuzz_target!(|seq: ActionSeq| {
    // Tight rate limiter (limit=2, 1h interval) so reservation/circuit floods
    // deterministically trip the `rate_limiter.rs` token-bucket deny arms.
    let limit = std::num::NonZeroU32::new(2).unwrap();
    fuzz_behaviour_rate_limited(seq.0, limit);
});
