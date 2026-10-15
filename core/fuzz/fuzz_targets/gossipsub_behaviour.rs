#![no_main]

//! Action-sequence fuzzer for `libp2p-gossipsub::Behaviour`.
//!
//! Weights + structured control RPCs target cold branches found by llvm-cov:
//! `handle_ihave` / `handle_graft` / `handle_prune` / `handle_iwant`, peer
//! scoring, `PublishError::MessageTooLarge`, the length-delimited
//! `GossipsubCodec` path (InjectWire), and `reject_message(msg_id)` via
//! blacklist / self-origin / IHAVE-promise sequences.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_gossipsub::{
    FuzzAction, FuzzSeed, MAX_ACTIONS, MAX_RPC_BYTES, MAX_TRANSMIT_SIZE, PEER_POOL,
    RejectMsgIdReason, ScheduleOp, StructuredRpcKind, encode_batch_rpc, encode_structured_rpc,
    encode_structured_wire, fuzz_behaviour_seeded,
};

#[derive(Debug)]
struct ActionSeq {
    seed: FuzzSeed,
    actions: Vec<FuzzAction>,
}

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Min 8 so Subscribe→Graft→Publish×2 setup always lands before free actions.
        let n = u.int_in_range(8..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        // Seed: ~½ pre-mesh explicit peers, ~⅓ pre-publish (warm mcache).
        let seed = FuzzSeed {
            explicit_peers: if u.ratio(1, 2)? {
                u.int_in_range(0u8..=PEER_POOL as u8)?
            } else {
                0
            },
            pre_publish: if u.ratio(1, 3)? {
                u.int_in_range(0u8..=8)?
            } else {
                0
            },
        };
        Ok(ActionSeq { seed, actions })
    }
}

fn pick_structured_kind(u: &mut Unstructured<'_>) -> arbitrary::Result<StructuredRpcKind> {
    // Keep PublishSelfOrigin / PublishFromPeer out of random wire — those need
    // correlated PeerIds and are driven by RejectMsgId.
    Ok(match u.int_in_range(0u8..=10)? {
        0 => StructuredRpcKind::IHave,
        1 => StructuredRpcKind::IHave, // bias IHAVE floods
        2 => StructuredRpcKind::IWant,
        3 => StructuredRpcKind::Graft,
        4 => StructuredRpcKind::Prune, // empty PX
        5 | 6 => StructuredRpcKind::PruneWithPx, // bias peer-exchange
        7 => StructuredRpcKind::IDontWant,
        8 => StructuredRpcKind::Subscribe,
        9 => StructuredRpcKind::Publish,
        _ => StructuredRpcKind::PublishBadSig,
    })
}

fn pick_reject_reason(u: &mut Unstructured<'_>) -> arbitrary::Result<RejectMsgIdReason> {
    Ok(match u.int_in_range(0u8..=2)? {
        0 => RejectMsgIdReason::BlackListedPeer,
        1 => RejectMsgIdReason::BlackListedSource,
        _ => RejectMsgIdReason::SelfOrigin,
    })
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: connect, Subscribe then Graft (Graft needs peer.topics), fill queues,
    // trip AllQueuesFull, then a reject_message sequence.
    if step < 3 {
        return Ok(FuzzAction::Connect {
            peer_slot: (step as u8) % PEER_POOL as u8,
            outbound: step % 2 == 0,
        });
    }
    if step == 3 {
        return Ok(FuzzAction::InjectWire {
            peer_slot: 0,
            wire_bytes: encode_structured_wire(StructuredRpcKind::Subscribe, 0, 0),
        });
    }
    if step == 4 {
        return Ok(FuzzAction::InjectWire {
            peer_slot: 0,
            wire_bytes: encode_structured_wire(StructuredRpcKind::Graft, 0, 0),
        });
    }
    if step == 5 {
        return Ok(FuzzAction::Publish {
            topic_slot: 0,
            data: vec![0xA1; 16],
        });
    }
    if step == 6 {
        // Second Publish with no intervening drain → AllQueuesFull (queue_len=1).
        return Ok(FuzzAction::Publish {
            topic_slot: 0,
            data: vec![0xA2; 16],
        });
    }
    if step == 7 {
        return Ok(FuzzAction::RejectMsgId {
            peer_slot: 0,
            source_slot: 1,
            mid_slot: 0x11,
            reason: RejectMsgIdReason::SelfOrigin,
            with_ihave_promise: true,
        });
    }

    // Coverage-biased weights (sum = 44):
    //   InjectWireStructured 8 | RejectMsgId 6 | InjectRpcStructured 4 | Heartbeat 4
    //   Publish 4 | BlacklistPeer 3 | Connect 3 | Subscribe 2 | raw wire+rpc 2+2
    //   BatchWire 2 | DeferredWire 2 | Disconnect 1 | RemoveBlacklisted 1
    Ok(match u.int_in_range(0u8..=43)? {
        0..=7 => {
            let kind = pick_structured_kind(u)?;
            let topic_slot = u.arbitrary()?;
            let mid_slot = u.arbitrary()?;
            let peer_slot = if matches!(kind, StructuredRpcKind::IHave) {
                0
            } else {
                u.arbitrary()?
            };
            FuzzAction::InjectWire {
                peer_slot,
                wire_bytes: encode_structured_wire(kind, topic_slot, mid_slot),
            }
        }
        8..=13 => FuzzAction::RejectMsgId {
            peer_slot: u.arbitrary()?,
            source_slot: u.arbitrary()?,
            mid_slot: u.arbitrary()?,
            reason: pick_reject_reason(u)?,
            with_ihave_promise: u.ratio(2, 3)?,
        },
        14..=17 => {
            let kind = pick_structured_kind(u)?;
            FuzzAction::InjectRpc {
                peer_slot: u.arbitrary()?,
                rpc_bytes: encode_structured_rpc(kind, u.arbitrary()?, u.arbitrary()?),
            }
        }
        18..=21 => FuzzAction::Heartbeat,
        22..=25 => {
            let mode = u.int_in_range(0u8..=3)?;
            let (topic_slot, data) = match mode {
                0 => {
                    let data = vec![0x41; MAX_TRANSMIT_SIZE + 64];
                    (0u8, data)
                }
                1 => {
                    let topic_slot = 1 + (u.arbitrary::<u8>()? % 3);
                    let len = u.int_in_range(0..=64)?;
                    (topic_slot, u.bytes(len)?.to_vec())
                }
                _ => {
                    let len = u.int_in_range(0..=MAX_TRANSMIT_SIZE.min(128))?;
                    (u.arbitrary()?, u.bytes(len)?.to_vec())
                }
            };
            FuzzAction::Publish { topic_slot, data }
        }
        26..=28 => FuzzAction::BlacklistPeer {
            peer_slot: u.arbitrary()?,
        },
        29..=31 => FuzzAction::Connect {
            peer_slot: u.arbitrary()?,
            outbound: u.arbitrary()?,
        },
        32..=33 => FuzzAction::Subscribe {
            topic_slot: u.arbitrary()?,
        },
        34..=35 => {
            let len = u.int_in_range(0..=MAX_RPC_BYTES.min(256))?;
            let wire_bytes = u.bytes(len)?.to_vec();
            FuzzAction::InjectWire {
                peer_slot: u.arbitrary()?,
                wire_bytes,
            }
        }
        36..=37 => {
            let len = u.int_in_range(0..=MAX_RPC_BYTES.min(256))?;
            let rpc_bytes = u.bytes(len)?.to_vec();
            FuzzAction::InjectRpc {
                peer_slot: u.arbitrary()?,
                rpc_bytes,
            }
        }
        38..=39 => {
            // Multi-publish / multi-control in one length-prefixed frame.
            let n = u.int_in_range(2usize..=4)?;
            let mut kinds = Vec::with_capacity(n);
            for _ in 0..n {
                kinds.push(pick_structured_kind(u)?);
            }
            let topic_slot = u.arbitrary()?;
            let mid_slot = u.arbitrary()?;
            FuzzAction::InjectWire {
                peer_slot: u.arbitrary()?,
                wire_bytes: encode_batch_rpc(&kinds, topic_slot, mid_slot),
            }
        }
        40..=41 => {
            let n = u.int_in_range(1usize..=3)?;
            let mut ops = Vec::with_capacity(n);
            for i in 0..n {
                let kind = pick_structured_kind(u)?;
                ops.push(ScheduleOp {
                    delay_polls: u.int_in_range(0u8..=3)?.saturating_add(i as u8 % 2),
                    bytes: encode_structured_wire(kind, u.arbitrary()?, u.arbitrary()?),
                });
            }
            FuzzAction::InjectWireDeferred {
                peer_slot: u.arbitrary()?,
                ops,
            }
        }
        42 => FuzzAction::RemoveBlacklistedPeer {
            peer_slot: u.arbitrary()?,
        },
        _ => FuzzAction::Disconnect {
            peer_slot: u.arbitrary()?,
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour_seeded(seq.seed, seq.actions);
});
