//! Action-sequence fuzz driver for AutoNAT v1 [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Exercises dial-back probes, address
//! confidence, inbound DialRequest throttling, and status flips under mock
//! swarm / request-response handler events (no real sockets).

use std::{
    collections::HashMap,
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::Encoder;
use bytes::BytesMut;
use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol,
    transport::{ListenerId, PortUse},
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_request_response::{InboundRequestId, OutboundRequestId};
use libp2p_swarm::{
    ConnectionId, DialError, NetworkBehaviour, ToSwarm,
    behaviour::{
        ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm, NewExternalAddrCandidate,
        NewListenAddr,
    },
};

use crate::v1::{
    Behaviour, Config, NatStatus, ResponseError,
    protocol::{DEFAULT_PROTOCOL_NAME, DialRequest, DialResponse},
    proto,
};

pub const MAX_ACTIONS: usize = 64;
pub const MAX_MSG_BYTES: usize = 1024;
pub const PEER_POOL: usize = 8;
const MAX_POLL_DRAIN: usize = 256;
const MAX_CONFIDENCE: usize = 3;
const MAX_CANDIDATES: usize = 32;

/// Structured AutoNAT v1 wire kinds (length-prefixed protobuf).
#[derive(Clone, Copy, Debug)]
pub enum StructuredDialKind {
    DialOk { addr_slot: u8 },
    DialError,
    DialRefused,
    BadRequest,
    DialManyAddrs { count: u8 },
    Malformed,
}

/// Encode a structured Dial / DialResponse protobuf frame.
pub fn encode_structured_dial_wire(kind: StructuredDialKind, peer: PeerId) -> Vec<u8> {
    let msg = match kind {
        StructuredDialKind::DialOk { addr_slot } => DialResponse {
            status_text: Some("ok".into()),
            result: Ok(global_addr(addr_slot)),
        }
        .into_proto(),
        StructuredDialKind::DialError => DialResponse {
            status_text: None,
            result: Err(ResponseError::DialError),
        }
        .into_proto(),
        StructuredDialKind::DialRefused => DialResponse {
            status_text: None,
            result: Err(ResponseError::DialRefused),
        }
        .into_proto(),
        StructuredDialKind::BadRequest => DialResponse {
            status_text: None,
            result: Err(ResponseError::BadRequest),
        }
        .into_proto(),
        StructuredDialKind::DialManyAddrs { count } => DialRequest {
            peer_id: peer,
            addresses: (0..(count as usize % 16).max(1))
                .map(|i| global_addr(i as u8))
                .collect(),
        }
        .into_proto(),
        StructuredDialKind::Malformed => proto::Message {
            r#type: Some(99),
            dial: None,
            dial_response: None,
        },
    };
    length_prefix(&msg)
}

fn length_prefix(msg: &proto::Message) -> Vec<u8> {
    let mut codec = prost_codec::Codec::<proto::Message>::new(MAX_MSG_BYTES);
    let mut buf = BytesMut::new();
    if codec.encode(msg.clone(), &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect {
        peer_slot: u8,
    },
    AddServer {
        peer_slot: u8,
        with_addr: bool,
    },
    RemoveServer {
        peer_slot: u8,
    },
    NewListenAddr {
        slot: u8,
    },
    NewExternalCandidate {
        slot: u8,
    },
    ProbeAddress {
        slot: u8,
    },
    /// Expire probe timer + drain so an outbound dial-back request is issued.
    AdvanceProbeClock,
    /// Inject DialResponse for an ongoing outbound (Kad-style slot / mismatch).
    InjectDialBack {
        peer_slot: u8,
        request_slot: u8,
        mismatch: bool,
        success: bool,
        addr_slot: u8,
    },
    /// Inject inbound DialRequest (server path).
    InjectInboundDialRequest {
        peer_slot: u8,
        addr_count: u8,
    },
    DialFailure {
        peer_slot: u8,
    },
    /// Flood probe timer expires (confidence / throttle races).
    FloodAdvanceProbe {
        count: u8,
    },
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x41u8; 32]; // 'A'
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn peer_pool() -> Vec<PeerId> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0xA0u8; 32];
            bytes[0] = 0xB0u8.wrapping_add(i as u8);
            bytes[1] = i as u8 + 1;
            PeerId::from(
                Keypair::ed25519_from_bytes(&mut bytes)
                    .expect("pool ed25519")
                    .public(),
            )
        })
        .collect()
}

/// Public IPv4 so Autonat `is_global_ip` accepts the observed address.
fn global_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(
        203,
        0,
        113,
        1 + slot % 200,
    )));
    a.push(Protocol::Tcp(4000 + u16::from(slot)));
    a
}

fn fuzz_config() -> Config {
    Config {
        timeout: Duration::from_millis(50),
        boot_delay: Duration::from_millis(1),
        retry_interval: Duration::from_millis(5),
        refresh_interval: Duration::from_millis(20),
        throttle_server_period: Duration::ZERO,
        use_connected: true,
        confidence_max: MAX_CONFIDENCE,
        max_peer_addresses: 8,
        throttle_clients_global_max: 16,
        throttle_clients_peer_max: 4,
        throttle_clients_period: Duration::from_secs(60),
        only_global_ips: false,
    }
}

fn resolve_outbound_id(
    active: &[OutboundRequestId],
    request_slot: u8,
    mismatch: bool,
) -> Option<OutboundRequestId> {
    if mismatch {
        return Some(OutboundRequestId::fuzz(
            0xF000_0000u64.wrapping_add(u64::from(request_slot)),
        ));
    }
    let n = active.len();
    if n == 0 {
        return None;
    }
    let from_end = (request_slot as usize) % n;
    Some(active[n - 1 - from_end])
}

/// Drive AutoNAT v1 [`Behaviour`] with a sequence of actions.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    let local = fuzz_local_peer_id();
    let mut autonat = Behaviour::new(local, fuzz_config());
    let peers = peer_pool();
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>> = HashMap::new();
    let mut next_conn: usize = 1;

    // Seed a listen address so probes are not aborted with NoAddresses.
    let listen = global_addr(0);
    autonat.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
        listener_id: ListenerId::next(),
        addr: &listen,
    }));

    for action in actions.into_iter().take(MAX_ACTIONS) {
        match action {
            FuzzAction::Connect {
                peer_slot,
                outbound,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let cid = ConnectionId::new_unchecked(next_conn);
                next_conn = next_conn.wrapping_add(1).max(1);
                let remote = global_addr(peer_slot);

                let _handler = if outbound {
                    autonat.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    autonat.handle_established_inbound_connection(
                        cid,
                        peer,
                        &listen,
                        &remote,
                    )
                };

                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: remote.clone(),
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::Reuse,
                    }
                } else {
                    ConnectedPoint::Listener {
                        local_addr: listen.clone(),
                        send_back_addr: remote,
                    }
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                autonat.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids.entry(peer).or_default().push((cid, endpoint));
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                let mut remaining = ids.len();
                for (cid, endpoint) in ids {
                    remaining = remaining.saturating_sub(1);
                    autonat.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
            }
            FuzzAction::AddServer {
                peer_slot,
                with_addr,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let addr = with_addr.then(|| global_addr(peer_slot));
                autonat.add_server(peer, addr);
            }
            FuzzAction::RemoveServer { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                autonat.remove_server(&peer);
            }
            FuzzAction::NewListenAddr { slot } => {
                let addr = global_addr(slot);
                autonat.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
                    listener_id: ListenerId::next(),
                    addr: &addr,
                }));
            }
            FuzzAction::NewExternalCandidate { slot } => {
                let addr = global_addr(slot);
                autonat.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                    NewExternalAddrCandidate { addr: &addr },
                ));
            }
            FuzzAction::ProbeAddress { slot } => {
                autonat.probe_address(global_addr(slot));
            }
            FuzzAction::AdvanceProbeClock => {
                autonat.fuzz_expire_probe_timer();
                drain_behaviour(&mut autonat);
            }
            FuzzAction::InjectDialBack {
                peer_slot,
                request_slot,
                mismatch,
                success,
                addr_slot,
            } => {
                if mismatch && cfg!(debug_assertions) {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let ids = autonat.fuzz_ongoing_outbound_ids();
                let Some(request_id) = resolve_outbound_id(&ids, request_slot, mismatch) else {
                    continue;
                };
                let response = if success {
                    DialResponse {
                        status_text: Some("ok".into()),
                        result: Ok(global_addr(addr_slot)),
                    }
                } else {
                    DialResponse {
                        status_text: None,
                        result: Err(ResponseError::DialError),
                    }
                };
                autonat.fuzz_inject_dial_response(peer, cid, request_id, response);
            }
            FuzzAction::InjectInboundDialRequest {
                peer_slot,
                addr_count,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let n = (addr_count as usize % 8).max(1);
                autonat.fuzz_inject_inbound_dial_request(
                    peer,
                    cid,
                    InboundRequestId::fuzz(u64::from(peer_slot).wrapping_add(1000)),
                    DialRequest {
                        peer_id: peer,
                        addresses: (0..n).map(|i| global_addr(i as u8)).collect(),
                    },
                );
            }
            FuzzAction::DialFailure { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                autonat.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                    peer_id: Some(peer),
                    connection_id: cid,
                    error: &DialError::NoAddresses,
                }));
            }
            FuzzAction::FloodAdvanceProbe { count } => {
                let n = (count as usize % 8).max(1);
                for _ in 0..n {
                    autonat.fuzz_expire_probe_timer();
                    drain_behaviour(&mut autonat);
                }
            }
        }

        drain_behaviour(&mut autonat);
        assert_invariants(&autonat);
    }

    assert_invariants(&autonat);
}

fn assert_invariants(autonat: &Behaviour) {
    let conf = autonat.confidence();
    assert!(
        conf <= MAX_CONFIDENCE.saturating_add(1),
        "confidence unbounded: {conf}"
    );
    // Unknown status must keep confidence at 0.
    if matches!(autonat.nat_status(), NatStatus::Unknown) {
        assert_eq!(
            autonat.confidence(),
            0,
            "Unknown status with non-zero confidence"
        );
    }
    assert!(
        autonat.fuzz_ongoing_outbound_count() <= MAX_ACTIONS.saturating_mul(8).saturating_add(2),
        "outbound probes unbounded: {}",
        autonat.fuzz_ongoing_outbound_count()
    );
    assert!(
        autonat.fuzz_ongoing_inbound_count() <= MAX_ACTIONS.saturating_add(2),
        "inbound probes unbounded: {}",
        autonat.fuzz_ongoing_inbound_count()
    );
    assert!(
        autonat.fuzz_connected_peer_count() <= PEER_POOL.saturating_mul(4).saturating_add(2),
        "connected peers unbounded"
    );
    assert!(
        autonat.fuzz_candidate_count() <= MAX_CANDIDATES.saturating_add(8),
        "candidates unbounded: {}",
        autonat.fuzz_candidate_count()
    );
    // Public status must carry a concrete address.
    if let NatStatus::Public(addr) = autonat.nat_status() {
        assert!(!addr.is_empty(), "Public status with empty address");
    }
    let _ = DEFAULT_PROTOCOL_NAME;
}

fn drain_behaviour(autonat: &mut Behaviour) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match autonat.poll(&mut cx) {
            Poll::Ready(ToSwarm::GenerateEvent(_)) => {}
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_connect_probe_dialback_success() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::AddServer {
                peer_slot: 0,
                with_addr: true,
            },
            FuzzAction::NewExternalCandidate { slot: 1 },
            FuzzAction::AdvanceProbeClock,
            FuzzAction::InjectDialBack {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
                success: true,
                addr_slot: 1,
            },
        ]);
    }

    #[test]
    fn smoke_dialback_private_and_confidence() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: false,
            },
            FuzzAction::AddServer {
                peer_slot: 0,
                with_addr: false,
            },
            FuzzAction::ProbeAddress { slot: 2 },
            FuzzAction::FloodAdvanceProbe { count: 3 },
            FuzzAction::InjectDialBack {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
                success: false,
                addr_slot: 0,
            },
            FuzzAction::AdvanceProbeClock,
            FuzzAction::InjectDialBack {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
                success: false,
                addr_slot: 0,
            },
        ]);
    }

    #[test]
    fn smoke_inbound_dial_request_and_disconnect() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectInboundDialRequest {
                peer_slot: 1,
                addr_count: 3,
            },
            FuzzAction::DialFailure { peer_slot: 1 },
            FuzzAction::Disconnect { peer_slot: 1 },
        ]);
    }

    #[test]
    fn structured_wire_roundtrip_nonempty() {
        let peer = fuzz_local_peer_id();
        let wire = encode_structured_dial_wire(StructuredDialKind::DialOk { addr_slot: 0 }, peer);
        assert!(!wire.is_empty());
        let err = encode_structured_dial_wire(StructuredDialKind::DialError, peer);
        assert!(!err.is_empty());
    }
}
