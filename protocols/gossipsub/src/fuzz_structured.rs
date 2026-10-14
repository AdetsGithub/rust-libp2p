use arbitrary::{Arbitrary, Unstructured};
use libp2p_core::multihash::Multihash;
use libp2p_gossipsub::{MessageId, TopicHash, ValidationMode};

// Define a structured message type that represents a valid Gossipsub RPC.
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

// Implement Arbitrary to allow libFuzzer to generate valid instances.
impl<'a> Arbitrary<'a> for GossipsubRpc {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let message_id = MessageId::from(u.bytes(8)?);
        let topic = TopicHash::from_raw(String::arbitrary(u)?);
        let data = u.bytes(16)?.to_vec();
        let sequence_number = u.option(|| u.u64())?;
        let source = u.option(|| {
            let mut bytes = [0u8; 32];
            for b in bytes.iter_mut() {
                *b = u8::arbitrary(u)?;
            }
            Some(libp2p_identity::PeerId::from(
                libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?
                    .public(),
            ))
        })?;
        let signature = u.option(|| u.bytes(64)?.to_vec())?;
        let key = u.option(|| u.bytes(32)?.to_vec())?;
        let validated = u.bool();
        
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

// The fuzzing entry point now takes a structured type.
pub fn fuzz_handler_structured(rpc: GossipsubRpc) -> Vec<libp2p_gossipsub::handler::HandlerEvent> {
    let mut handler = libp2p_gossipsub::handler::Handler::new(
        fuzz_peer_id(), 
        fuzz_protocol_config(), 
        libp2p_gossipsub::queue::Queue::new(8)
    );
    
    // Convert the structured input into the wire format.
    let mut wire_bytes = Vec::new();
    let mut codec = fuzz_codec();
    codec.encode(rpc, &mut wire_bytes).unwrap();
    
    // Inject the now-valid message into the handler.
    let feed = ChunkFeed::new(wire_bytes, 64, 0);
    feed.close();
    inject_inbound(&mut handler, feed);
    
    let mut events = Vec::new();
    drain_handler(&mut handler, &mut events);
    events
}

// Helper functions that need to be available
fn fuzz_peer_id() -> libp2p_identity::PeerId {
    let mut bytes = [0x42u8; 32];
    libp2p_identity::PeerId::from(
        libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed ed25519 seed")
            .public(),
    )
}

fn fuzz_protocol_config() -> libp2p_gossipsub::protocol::ProtocolConfig {
    libp2p_gossipsub::protocol::ProtocolConfig {
        protocol_ids: vec![libp2p_gossipsub::protocol::GOSSIPSUB_1_1_0_PROTOCOL],
        validation_mode: ValidationMode::Permissive,
        default_max_transmit_size: 256,
        max_transmit_sizes: std::collections::HashMap::new(),
        max_publish_messages: 64,
        max_control_message_size: 2048,
    }
}

fn fuzz_codec() -> libp2p_gossipsub::protocol::GossipsubCodec {
    libp2p_gossipsub::protocol::GossipsubCodec::new(
        256,
        ValidationMode::Permissive,
        std::collections::HashMap::new(),
        64,
        2048,
    )
}

// Re-export needed types from the existing fuzz_handler
use crate::fuzz_handler::{ChunkFeed, inject_inbound, drain_handler};