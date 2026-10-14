#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "v1")]
pub mod v1;

#[cfg(feature = "v2")]
pub mod v2;

#[cfg(all(feature = "fuzzing", feature = "v1"))]
mod fuzz;
#[cfg(all(feature = "fuzzing", feature = "v2"))]
mod fuzz_v2;
#[cfg(all(feature = "fuzzing", feature = "v2"))]
mod fuzz_v2_server;

#[cfg(feature = "v1")]
pub use v1::*;

#[cfg(all(feature = "fuzzing", feature = "v1"))]
pub use fuzz::{
    FuzzAction, MAX_ACTIONS, MAX_MSG_BYTES, PEER_POOL, StructuredDialKind, encode_structured_dial_wire,
    fuzz_behaviour, fuzz_local_peer_id,
};
#[cfg(all(feature = "fuzzing", feature = "v2"))]
pub use fuzz_v2::{
    FuzzAction as V2FuzzAction, MAX_ACTIONS as V2_MAX_ACTIONS, PEER_POOL as V2_PEER_POOL,
    fuzz_behaviour as fuzz_behaviour_v2, fuzz_local_peer_id as fuzz_local_peer_id_v2,
};
#[cfg(all(feature = "fuzzing", feature = "v2"))]
pub use fuzz_v2_server::{
    FuzzAction as V2ServerFuzzAction, MAX_ACTIONS as V2_SERVER_MAX_ACTIONS,
    PEER_POOL as V2_SERVER_PEER_POOL, fuzz_behaviour as fuzz_behaviour_v2_server,
    fuzz_local_peer_id as fuzz_local_peer_id_v2_server,
};
