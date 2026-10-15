// Fuzz target for Gossipsub using structure-aware fuzzing

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

// Import the structured fuzzing module (re-exported at the gossipsub crate root).
use libp2p_gossipsub::{GossipsubRpc, fuzz_handler_structured};

fuzz_target!(|data: &[u8]| {
    // Interpret the input bytes as a structured Gossipsub RPC.
    let mut u = arbitrary::Unstructured::new(data);
    if let Ok(rpc) = GossipsubRpc::arbitrary(&mut u) {
        // Drive the RPC through the handler.
        let _ = fuzz_handler_structured(rpc);
    }
});
