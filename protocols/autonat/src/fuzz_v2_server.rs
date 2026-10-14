//! Action-sequence fuzz driver for AutoNAT v2 **server** [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Exercises dial-request → dial-back
//! command injection, concurrent dial-back throttle, DialFailure races, and
//! status-event emission — without live dial-request stream I/O.

use std::{
    collections::HashMap,
    io,
    task::{Context, Poll},
    time::Duration,
};

use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionId, NetworkBehaviour, ToSwarm,
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
};
use rand::SeedableRng;

use crate::v2::server::{Behaviour, Event};

pub const MAX_ACTIONS: usize = 64;
pub const PEER_POOL: usize = 8;
const MAX_POLL_DRAIN: usize = 256;
/// Soft clamp: concurrent dial-backs should stay near action budget.
const MAX_DIALING_SLACK: usize = 4;

#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect {
        peer_slot: u8,
    },
    /// Inject one or more dial-back commands (server accepted dial-request).
    InjectDialRequest {
        peer_slot: u8,
        addr_count: u8,
    },
    /// Complete a pending dial-back: success establishes outbound + Ok; fail → DialFailure.
    InjectDialBackResult {
        peer_slot: u8,
        success: bool,
        /// Index into pending dialing ring (0 = newest).
        dial_slot: u8,
    },
    /// Fail all (or one) pending dial-backs via DialFailure (timeout / refuse path).
    AdvanceTimeout {
        /// If true, fail every pending dialing entry; else fail newest only.
        all: bool,
    },
    /// Inject a finished status Event on an inbound connection.
    InjectStatusEvent {
        peer_slot: u8,
        success: bool,
        addr_slot: u8,
    },
    FloodDialRequests {
        peer_slot: u8,
        count: u8,
    },
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x33u8; 32]; // '3'
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn peer_pool() -> Vec<PeerId> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0xE0u8; 32];
            bytes[0] = 0xE1u8.wrapping_add(i as u8);
            bytes[1] = i as u8 + 1;
            PeerId::from(
                Keypair::ed25519_from_bytes(&mut bytes)
                    .expect("pool ed25519")
                    .public(),
            )
        })
        .collect()
}

fn global_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(
        203,
        0,
        113,
        1 + slot % 200,
    )));
    a.push(Protocol::Tcp(6000 + u16::from(slot)));
    a
}

/// Drive AutoNAT v2 server [`Behaviour`] with a sequence of actions.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    let rng = rand::rngs::StdRng::seed_from_u64(0xA271_u64);
    let mut server = Behaviour::new(rng);

    let peers = peer_pool();
    // (cid, endpoint, is_outbound)
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint, bool)>> = HashMap::new();
    let mut next_conn: usize = 1;
    // Dial-back connection ids freshly allocated by InjectDialRequest (newest last).
    let mut pending_dials: Vec<(PeerId, ConnectionId)> = Vec::new();

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
                    server.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    server.handle_established_inbound_connection(
                        cid,
                        peer,
                        &Multiaddr::empty(),
                        &remote,
                    )
                };

                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: remote,
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::Reuse,
                    }
                } else {
                    ConnectedPoint::Listener {
                        local_addr: Multiaddr::empty(),
                        send_back_addr: remote,
                    }
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                server.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids
                    .entry(peer)
                    .or_default()
                    .push((cid, endpoint, outbound));
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                let mut remaining = ids.len();
                for (cid, endpoint, _) in ids {
                    remaining = remaining.saturating_sub(1);
                    server.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
            }
            FuzzAction::InjectDialRequest {
                peer_slot,
                addr_count,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_out)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                // Dial-request handler lives on inbound connections.
                if is_out {
                    continue;
                }
                let n = (addr_count as usize % 8).max(1);
                for i in 0..n {
                    let before = server.fuzz_dialing_count();
                    server.fuzz_inject_dial_back_command(
                        peer,
                        cid,
                        global_addr(peer_slot.wrapping_add(i as u8)),
                        u64::from(peer_slot).wrapping_add(u64::from(i as u8)) << 8,
                    );
                    // Drain so Dial opts land in dialing_dial_back.
                    collect_pending_dials(&mut server, peer, &mut pending_dials);
                    let _ = before;
                }
            }
            FuzzAction::InjectDialBackResult {
                peer_slot,
                success,
                dial_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                // Prefer tracked pending dials for this peer; fall back to behaviour map.
                let dial_cid = resolve_pending_dial(&pending_dials, &server, peer, dial_slot);
                let Some(dial_cid) = dial_cid else {
                    continue;
                };
                pending_dials.retain(|(_, c)| *c != dial_cid);

                if success {
                    let remote = global_addr(peer_slot);
                    let _ = server.handle_established_outbound_connection(
                        dial_cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::New,
                    );
                    let endpoint = ConnectedPoint::Dialer {
                        address: remote,
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::New,
                    };
                    let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                    server.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                        peer_id: peer,
                        connection_id: dial_cid,
                        endpoint: &endpoint,
                        failed_addresses: &[],
                        other_established: other,
                    }));
                    conn_ids
                        .entry(peer)
                        .or_default()
                        .push((dial_cid, endpoint, true));
                    server.fuzz_inject_dial_back_result(peer, dial_cid, true);
                } else {
                    server.fuzz_inject_dial_failure(Some(dial_cid));
                }
            }
            FuzzAction::AdvanceTimeout { all } => {
                if all {
                    pending_dials.clear();
                    server.fuzz_inject_dial_failure(None);
                } else if let Some((_, cid)) = pending_dials.pop() {
                    server.fuzz_inject_dial_failure(Some(cid));
                } else if let Some(cid) = server.fuzz_dialing_connection_ids().into_iter().next() {
                    server.fuzz_inject_dial_failure(Some(cid));
                }
            }
            FuzzAction::InjectStatusEvent {
                peer_slot,
                success,
                addr_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_out)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if is_out {
                    continue;
                }
                let addr = global_addr(addr_slot);
                server.fuzz_inject_status_event(
                    peer,
                    cid,
                    Event {
                        all_addrs: vec![addr.clone()],
                        tested_addr: addr,
                        client: peer,
                        data_amount: usize::from(addr_slot).saturating_mul(64),
                        result: if success {
                            Ok(())
                        } else {
                            Err(io::Error::other("fuzz status fail"))
                        },
                    },
                );
            }
            FuzzAction::FloodDialRequests { peer_slot, count } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_out)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if is_out {
                    continue;
                }
                let n = (count as usize % 8).max(1);
                for i in 0..n {
                    server.fuzz_inject_dial_back_command(
                        peer,
                        cid,
                        global_addr(i as u8),
                        0xF000_0000_0000_0000u64.wrapping_add(i as u64),
                    );
                    collect_pending_dials(&mut server, peer, &mut pending_dials);
                }
            }
        }

        drain_behaviour(&mut server, &mut pending_dials);
        assert_server_invariants(&server, &pending_dials);
    }

    drain_behaviour(&mut server, &mut pending_dials);
    assert_server_invariants(&server, &pending_dials);
}

fn resolve_pending_dial(
    pending: &[(PeerId, ConnectionId)],
    server: &Behaviour<rand::rngs::StdRng>,
    peer: PeerId,
    dial_slot: u8,
) -> Option<ConnectionId> {
    let peer_pending: Vec<ConnectionId> = pending
        .iter()
        .rev()
        .filter_map(|(p, c)| (*p == peer).then_some(*c))
        .collect();
    if !peer_pending.is_empty() {
        let idx = (dial_slot as usize) % peer_pending.len();
        return Some(peer_pending[idx]);
    }
    let ids = server.fuzz_dialing_connection_ids();
    if ids.is_empty() {
        return None;
    }
    let idx = (dial_slot as usize) % ids.len();
    Some(ids[idx])
}

fn collect_pending_dials(
    server: &mut Behaviour<rand::rngs::StdRng>,
    peer: PeerId,
    pending: &mut Vec<(PeerId, ConnectionId)>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match server.poll(&mut cx) {
            Poll::Ready(ToSwarm::Dial { opts }) => {
                pending.push((peer, opts.connection_id()));
                if pending.len() > MAX_ACTIONS.saturating_add(MAX_DIALING_SLACK) {
                    pending.remove(0);
                }
            }
            Poll::Ready(ToSwarm::GenerateEvent(_)) => {}
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

fn drain_behaviour(
    server: &mut Behaviour<rand::rngs::StdRng>,
    pending: &mut Vec<(PeerId, ConnectionId)>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match server.poll(&mut cx) {
            Poll::Ready(ToSwarm::Dial { opts }) => {
                // Orphan dial (no peer attribution) — track under PeerId::random-ish slot 0.
                let _ = opts;
                let ids = server.fuzz_dialing_connection_ids();
                if let Some(&cid) = ids.last() {
                    // Peer unknown here; keep map-only tracking.
                    let _ = cid;
                }
                let _ = pending;
            }
            Poll::Ready(ToSwarm::GenerateEvent(_)) => {}
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

fn assert_server_invariants(
    server: &Behaviour<rand::rngs::StdRng>,
    pending: &[(PeerId, ConnectionId)],
) {
    let dialing = server.fuzz_dialing_count();
    assert!(
        dialing <= MAX_ACTIONS.saturating_add(MAX_DIALING_SLACK),
        "v2 server dialing_dial_back unbounded: {dialing}"
    );
    assert!(
        server.fuzz_pending_event_count() <= MAX_ACTIONS.saturating_add(MAX_DIALING_SLACK),
        "v2 server pending_events unbounded"
    );
    assert!(
        pending.len() <= MAX_ACTIONS.saturating_add(MAX_DIALING_SLACK),
        "tracked pending dials unbounded"
    );
    let _ = Duration::from_millis(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_inbound_dial_request_and_failure() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: false,
            },
            FuzzAction::InjectDialRequest {
                peer_slot: 0,
                addr_count: 2,
            },
            FuzzAction::InjectDialBackResult {
                peer_slot: 0,
                success: false,
                dial_slot: 0,
            },
            FuzzAction::AdvanceTimeout { all: true },
        ]);
    }

    #[test]
    fn smoke_dial_back_success_and_status() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectDialRequest {
                peer_slot: 1,
                addr_count: 1,
            },
            FuzzAction::InjectDialBackResult {
                peer_slot: 1,
                success: true,
                dial_slot: 0,
            },
            FuzzAction::InjectStatusEvent {
                peer_slot: 1,
                success: true,
                addr_slot: 3,
            },
            FuzzAction::FloodDialRequests {
                peer_slot: 1,
                count: 4,
            },
            FuzzAction::AdvanceTimeout { all: true },
            FuzzAction::Disconnect { peer_slot: 1 },
        ]);
    }
}
