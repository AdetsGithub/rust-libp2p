// Fuzz target for Gossipsub using structure-aware fuzzing

#![no_main]
use libfuzzer_sys::fuzz_target;

// Import the structured fuzzing module
use rust_libp2p::protocols::gossipsub::fuzz_structured::GossipsubRpc;

fuzz_target!(|data: &[u8]| {
    // Try to interpret the data as a structured Gossipsub RPC
    if let Ok(mut u) = arbitrary::Unstructured::new(data) {
        if let Ok(rpc) = GossipsubRpc::arbitrary(&mut u) {
            // Use the structured RPC in the fuzzing harness
            let _ = rust_libp2p::protocols::gossipsub::fuzz_structured::fuzz_handler_structured(rpc);
        }
    }
});