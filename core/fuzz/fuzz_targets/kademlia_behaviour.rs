#![no_main]

//! Action-sequence fuzzer for `libp2p-kad::Behaviour`.
//!
//! Weights target: inbound structured/wire DHT RPCs, outbound response inject
//! (incl. empty GetRecord / incomplete providers), `put_record_to` QuorumFailed,
//! GetRecord NotFound (empty RT + empty res), disjoint closest-peers paths, and
//! periodic `jobs.rs` via AdvanceJobs.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_kad::{
    FuzzAction, MAX_ACTIONS, MAX_DATA_BYTES, MAX_MSG_BYTES, PEER_POOL, StructuredInboundKind,
    StructuredResponseKind, encode_structured_wire, fuzz_behaviour,
};

#[derive(Debug)]
struct ActionSeq(Vec<FuzzAction>);

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.int_in_range(8..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n + 4);
        // Empty-RT NotFound: GetRecord before any ProtocolConfirmed.
        actions.push(FuzzAction::GetRecord {
            key_slot: u.arbitrary()?,
        });
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        Ok(ActionSeq(actions))
    }
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: Connect then ProtocolConfirmed on several dialer slots (need ≥2
    // RT peers so disjoint closest paths have seeds).
    if step < 6 {
        let slot = (step as u8 / 2) % PEER_POOL as u8;
        return Ok(if step % 2 == 0 {
            FuzzAction::Connect {
                peer_slot: slot,
                outbound: true,
            }
        } else {
            FuzzAction::ProtocolConfirmed { peer_slot: slot }
        });
    }
    // After mesh: GetClosestPeers to enter ClosestDisjointPeersIter.
    if step == 6 {
        return Ok(FuzzAction::GetClosestPeers {
            key_slot: u.arbitrary()?,
        });
    }
    if step == 7 {
        return Ok(FuzzAction::InjectResponse {
            peer_slot: 0,
            kind: StructuredResponseKind::FindNodeRes,
            closer_slot: 1 + (u.arbitrary::<u8>()? % (PEER_POOL as u8 - 1).max(1)),
            query_slot: 0,
            mismatch: false,
        });
    }
    // NotFound via empty record responses on a live GetRecord.
    if step == 8 {
        return Ok(FuzzAction::GetRecord {
            key_slot: 0xFE,
        });
    }
    if step == 9 {
        return Ok(FuzzAction::InjectResponse {
            peer_slot: 0,
            kind: StructuredResponseKind::GetRecordEmpty,
            closer_slot: 0,
            query_slot: 0,
            mismatch: false,
        });
    }

    // Coverage-biased weights (sum = 50):
    //   InjectResponse 8 (GetRecordEmpty/FindNodeRes; query_slot/mismatch bias)
    //   InjectWire 6 | GetRecord 5 | GetClosestPeers 5 | PutRecordTo 3
    //   GetProviders 3 | AdvanceJobs 2 | AdvanceQueryClock 3 | PutRecord 2
    //   StartProviding 2 | Connect 2 | ProtocolConfirmed 2 | InjectStructured 2
    //   AddAddress 2 | raw wire/inbound 1+1 | Bootstrap 1 | Disconnect 1
    Ok(match u.int_in_range(0u8..=49)? {
        0..=7 => {
            let kind = match u.int_in_range(0u8..=7)? {
                0 | 1 => StructuredResponseKind::GetRecordEmpty, // NotFound density
                2 | 3 => StructuredResponseKind::FindNodeRes,    // disjoint progress
                4 => StructuredResponseKind::GetProvidersRes,
                5 => StructuredResponseKind::GetRecordRes,
                6 => StructuredResponseKind::PutRecordRes,
                _ => StructuredResponseKind::QueryError,
            };
            FuzzAction::InjectResponse {
                peer_slot: u.arbitrary()?,
                kind,
                closer_slot: u.arbitrary()?,
                // 0 = newest; bias older slots + ghost ids for QueryId confusion.
                query_slot: if u.ratio(3, 4)? { 0 } else { u.arbitrary()? },
                mismatch: u.ratio(1, 8)?,
            }
        }
        8..=13 => {
            let kind = match u.int_in_range(0u8..=5)? {
                0 | 1 => StructuredInboundKind::FindNode, // feeds disjoint closer sets
                2 => StructuredInboundKind::GetProviders,
                3 => StructuredInboundKind::GetValue,
                4 => StructuredInboundKind::PutValue,
                _ => StructuredInboundKind::AddProvider,
            };
            FuzzAction::InjectWire {
                peer_slot: u.arbitrary()?,
                wire_bytes: encode_structured_wire(kind, u.arbitrary()?, None),
            }
        }
        14..=18 => FuzzAction::GetRecord {
            key_slot: u.arbitrary()?,
        },
        19..=23 => FuzzAction::GetClosestPeers {
            key_slot: u.arbitrary()?,
        },
        24..=26 => {
            let len = u.int_in_range(0..=MAX_DATA_BYTES.min(64))?;
            let value = u.bytes(len)?.to_vec();
            FuzzAction::PutRecordTo {
                key_slot: u.arbitrary()?,
                value,
                quorum_all: true,
                peer_count: 1 + (u.arbitrary::<u8>()? % 3),
            }
        }
        27..=29 => FuzzAction::GetProviders {
            key_slot: u.arbitrary()?,
        },
        30..=31 => FuzzAction::AdvanceJobs,
        32..=34 => {
            // Bias toward values ≥ 60_000 so Timeout fires under 60s fuzz timeout.
            let ms = if u.ratio(3, 4)? {
                60_000 + u.int_in_range(0u16..=1000)?
            } else {
                u.arbitrary()?
            };
            FuzzAction::AdvanceQueryClock { ms }
        }
        35..=36 => {
            let len = u.int_in_range(0..=MAX_DATA_BYTES.min(64))?;
            let value = u.bytes(len)?.to_vec();
            FuzzAction::PutRecord {
                key_slot: u.arbitrary()?,
                value,
                quorum_all: u.arbitrary()?,
            }
        }
        37..=38 => FuzzAction::StartProviding {
            key_slot: u.arbitrary()?,
        },
        39..=40 => FuzzAction::Connect {
            peer_slot: u.arbitrary()?,
            outbound: u.arbitrary()?,
        },
        41..=42 => FuzzAction::ProtocolConfirmed {
            peer_slot: u.arbitrary()?,
        },
        43..=44 => {
            let kind = match u.int_in_range(0u8..=4)? {
                0 => StructuredInboundKind::GetProviders,
                1 => StructuredInboundKind::FindNode,
                2 => StructuredInboundKind::GetValue,
                3 => StructuredInboundKind::PutValue,
                _ => StructuredInboundKind::AddProvider,
            };
            FuzzAction::InjectStructured {
                peer_slot: u.arbitrary()?,
                kind,
                key_slot: u.arbitrary()?,
            }
        }
        45..=46 => FuzzAction::AddAddress {
            peer_slot: u.arbitrary()?,
        },
        47 => {
            let len = u.int_in_range(0..=MAX_MSG_BYTES.min(128))?;
            FuzzAction::InjectWire {
                peer_slot: u.arbitrary()?,
                wire_bytes: u.bytes(len)?.to_vec(),
            }
        }
        48 => {
            let len = u.int_in_range(0..=MAX_MSG_BYTES.min(128))?;
            FuzzAction::InjectInbound {
                peer_slot: u.arbitrary()?,
                msg_bytes: u.bytes(len)?.to_vec(),
            }
        }
        _ => {
            if u.ratio(1, 2)? {
                FuzzAction::Bootstrap
            } else {
                FuzzAction::Disconnect {
                    peer_slot: u.arbitrary()?,
                }
            }
        }
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour(seq.0);
});
