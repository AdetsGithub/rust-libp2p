//! Structure-aware handler driver for Gossipsub (feature = `"fuzzing"`).
//!
//! Builds a structured [`GossipsubRpc`] from arbitrary bytes, encodes it into
//! the protobuf wire format, and drives a fresh [`Handler`] through the inbound
//! codec path (the same mock-I/O plumbing used by `fuzz_handler_io`).

use arbitrary::{Arbitrary, Unstructured};
use prost::Message as _;

use crate::{
    MessageId, TopicHash, ValidationMode,
    fuzz_handler::{ChunkFeed, drain_handler, inject_inbound},
    handler,
    protocol,
    queue,
    rpc_proto::proto,
    types::PeerKind,
};

/// A structured Gossipsub RPC generated from fuzz input.
#[derive(Debug, Clone)]
pub struct GossipsubRpc {
    pub message_id: MessageId,
    pub topic: TopicHash,
    pub data: Vec<u8>,
    pub sequence_number: Option<u64>,
    pub source: Option<libp2p_identity::PeerId>,
    pub signature: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub validated: bool,
}

/// Implement Arbitrary to allow libFuzzer to generate structured instances.
impl<'a> Arbitrary<'a> for GossipsubRpc {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let message_id = MessageId::from(u.bytes(8)?);
        let topic = TopicHash::from_raw(String::arbitrary(u)?);
        let data = u.bytes(16)?.to_vec();
        let sequence_number = if bool::arbitrary(u)? { Some(u64::arbitrary(u)?) } else { None };
        let source = if bool::arbitrary(u)? {
            let mut bytes = [0u8; 32];
            for b in bytes.iter_mut() {
                *b = u8::arbitrary(u)?;
            }
            Some(libp2p_identity::PeerId::from(
                libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?
                    .public(),
            ))
        } else { None };
        let signature = if bool::arbitrary(u)? { Some(u.bytes(64)?.to_vec()) } else { None };
        let key = if bool::arbitrary(u)? { Some(u.bytes(32)?.to_vec()) } else { None };
        let validated = bool::arbitrary(u)?;

        Ok(GossipsubRpc {
            message_id,
            topic,
            data,
            sequence_number,
            source,
            signature,
            key,
            validated,
        })
    }
}

/// Encode the structured RPC into the wire format and drive a fresh [`Handler`].
pub fn fuzz_handler_structured(rpc: GossipsubRpc) -> Vec<handler::HandlerEvent> {
    let mut handler = handler::Handler::new(
        fuzz_peer_id(),
        fuzz_protocol_config(),
        queue::Queue::new(8),
    );

    // Convert the structured input into a protobuf RPC and encode it to wire bytes.
    let wire_rpc = proto::Rpc {
        publish: vec![proto::Message {
            from: rpc.source.map(|p| p.to_bytes()),
            data: Some(rpc.data),
            seqno: rpc.sequence_number.map(|n| n.to_be_bytes().to_vec()),
            topic: rpc.topic.into_string(),
            signature: rpc.signature,
            key: rpc.key,
        }],
        ..Default::default()
    };
    let wire_bytes = wire_rpc.encode_to_vec();

    // Inject the encoded message into the handler and drain its events.
    let feed = ChunkFeed::new(wire_bytes, 64, 0);
    feed.close();
    inject_inbound(&mut handler, feed, PeerKind::Gossipsubv1_1);

    let mut events = Vec::new();
    drain_handler(&mut handler, &mut events);
    events
}

fn fuzz_peer_id() -> libp2p_identity::PeerId {
    let mut bytes = [0x42u8; 32];
    libp2p_identity::PeerId::from(
        libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed ed25519 seed")
            .public(),
    )
}

fn fuzz_protocol_config() -> protocol::ProtocolConfig {
    protocol::ProtocolConfig {
        protocol_ids: vec![protocol::GOSSIPSUB_1_1_0_PROTOCOL],
        validation_mode: ValidationMode::Permissive,
        default_max_transmit_size: 256,
        max_transmit_sizes: std::collections::HashMap::new(),
        max_publish_messages: 64,
        max_control_message_size: 2048,
    }
}
