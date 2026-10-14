#![no_main]

//! Strict + Signed Gossipsub behaviour fuzzer.
//!
//! Sibling of `gossipsub_behaviour` (Author + Permissive). Targets:
//! - Strict missing-field rejects (`InvalidSignature`, `EmptySequenceNumber`)
//! - `MessageSizeTooLargeForTopic` via per-topic max on topic 0
//! - Local publish over topic max → `PublishError::MessageTooLarge`
//! - Optional real signature checks: build with `--features fuzzing-real-verify`
//!   so identity does not stub `PublicKey::verify` under `--cfg fuzzing`.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_gossipsub::{
    FuzzAction, MAX_ACTIONS, MAX_RPC_BYTES, PEER_POOL, StructuredRpcKind, TOPIC_MAX_TRANSMIT_SIZE,
    TOPIC_POOL, encode_structured_wire, fuzz_behaviour_strict_signed,
};

#[derive(Debug)]
struct ActionSeq(Vec<FuzzAction>);

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.int_in_range(8..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n);
        for step in 0..n {
            actions.push(fuzz_action(u, step)?);
        }
        Ok(ActionSeq(actions))
    }
}

fn pick_strict_kind(u: &mut Unstructured<'_>) -> arbitrary::Result<StructuredRpcKind> {
    Ok(match u.int_in_range(0u8..=9)? {
        0 | 1 => StructuredRpcKind::PublishMissingSig,
        2 => StructuredRpcKind::PublishMissingFrom,
        3 | 4 => StructuredRpcKind::PublishMissingSeqno,
        5 | 6 => StructuredRpcKind::PublishOversizedTopic,
        7 => StructuredRpcKind::PublishGarbageSig,
        8 => StructuredRpcKind::PublishBadSig,
        _ => StructuredRpcKind::Subscribe,
    })
}

fn fuzz_action(u: &mut Unstructured<'_>, step: usize) -> arbitrary::Result<FuzzAction> {
    // Setup: connect, inject Strict rejects + oversized topic, publish oversize.
    if step < 2 {
        return Ok(FuzzAction::Connect {
            peer_slot: (step as u8) % PEER_POOL as u8,
            outbound: step % 2 == 0,
        });
    }
    if step == 2 {
        return Ok(FuzzAction::InjectWire {
            peer_slot: 0,
            wire_bytes: encode_structured_wire(StructuredRpcKind::PublishMissingSig, 0, 0),
        });
    }
    if step == 3 {
        return Ok(FuzzAction::InjectWire {
            peer_slot: 0,
            wire_bytes: encode_structured_wire(StructuredRpcKind::PublishMissingSeqno, 0, 1),
        });
    }
    if step == 4 {
        // Tight topic max before oversized inject (signed rejects need roomier budget).
        return Ok(FuzzAction::SetTopicMaxSize {
            topic_slot: 0,
            max: TOPIC_MAX_TRANSMIT_SIZE as u16,
        });
    }
    if step == 5 {
        return Ok(FuzzAction::InjectWire {
            peer_slot: 0,
            wire_bytes: encode_structured_wire(StructuredRpcKind::PublishOversizedTopic, 0, 2),
        });
    }
    if step == 6 {
        return Ok(FuzzAction::Publish {
            topic_slot: 0,
            data: vec![0xA1; TOPIC_MAX_TRANSMIT_SIZE + 16],
        });
    }
    if step == 7 {
        return Ok(FuzzAction::Connect {
            peer_slot: 1,
            outbound: true,
        });
    }

    let peer_slot = u.int_in_range(0u8..=(PEER_POOL as u8 - 1))?;
    let topic_slot = u.int_in_range(0u8..=(TOPIC_POOL as u8 - 1))?;
    Ok(match u.int_in_range(0u8..=12)? {
        0 | 1 => FuzzAction::Connect {
            peer_slot,
            outbound: u.ratio(1, 2)?,
        },
        2 => FuzzAction::Disconnect { peer_slot },
        3 | 4 | 5 => FuzzAction::InjectWire {
            peer_slot,
            wire_bytes: encode_structured_wire(pick_strict_kind(u)?, topic_slot, u.arbitrary()?),
        },
        6 => {
            let len = u.int_in_range(0usize..=MAX_RPC_BYTES.min(256))?;
            FuzzAction::InjectWire {
                peer_slot,
                wire_bytes: u.bytes(len)?.to_vec(),
            }
        }
        7 => FuzzAction::Publish {
            topic_slot,
            data: {
                let len = u.int_in_range(0usize..=TOPIC_MAX_TRANSMIT_SIZE.saturating_add(64))?;
                u.bytes(len)?.to_vec()
            },
        },
        8 => FuzzAction::Subscribe { topic_slot },
        9 => FuzzAction::SetTopicMaxSize {
            topic_slot,
            max: u.int_in_range(16u16..=128)?,
        },
        10 => FuzzAction::Heartbeat,
        11 => FuzzAction::InjectWire {
            peer_slot,
            wire_bytes: encode_structured_wire(
                StructuredRpcKind::PublishGarbageSig,
                topic_slot,
                u.arbitrary()?,
            ),
        },
        _ => FuzzAction::InjectWire {
            peer_slot,
            wire_bytes: encode_structured_wire(
                StructuredRpcKind::PublishOversizedTopic,
                0,
                u.arbitrary()?,
            ),
        },
    })
}

fuzz_target!(|seq: ActionSeq| {
    fuzz_behaviour_strict_signed(seq.0);
});
