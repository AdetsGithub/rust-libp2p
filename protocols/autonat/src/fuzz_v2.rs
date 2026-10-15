//! Action-sequence fuzz driver for AutoNAT v2 **client** [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Exercises address-candidate scoring,
//! dial-request probe ticks, dial-back nonce injection, and TestOutcome races.

use std::{
    collections::HashMap,
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
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm, NewExternalAddrCandidate},
};
use rand::SeedableRng;

use crate::v2::client::{Behaviour, Config};

pub const MAX_ACTIONS: usize = 64;
pub const PEER_POOL: usize = 8;
const MAX_POLL_DRAIN: usize = 256;
const MAX_CANDIDATES: usize = 16;

#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect {
        peer_slot: u8,
    },
    NewExternalCandidate {
        slot: u8,
    },
    /// Mark peer as supporting AutoNAT dial-request protocol.
    InjectPeerHasServerSupport {
        peer_slot: u8,
    },
    /// Expire probe interval so untested candidates are issued.
    AdvanceProbeClock,
    /// Inject dial-back nonce (pending nonce ring / ghost mismatch).
    InjectDialBackNonce {
        peer_slot: u8,
        mismatch: bool,
        nonce_slot: u8,
    },
    /// Inject TestOutcome for a pending nonce.
    InjectTestOutcome {
        peer_slot: u8,
        success: bool,
        nonce_slot: u8,
        mismatch: bool,
    },
    FloodCandidates {
        count: u8,
    },
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x32u8; 32]; // '2'
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn peer_pool() -> Vec<PeerId> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0xC0u8; 32];
            bytes[0] = 0xD0u8.wrapping_add(i as u8);
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
        198,
        51,
        100,
        1 + slot % 200,
    )));
    a.push(Protocol::Tcp(5000 + u16::from(slot)));
    a
}

/// Drive AutoNAT v2 client [`Behaviour`] with a sequence of actions.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    let rng = rand::rngs::StdRng::seed_from_u64(0xA270_u64);
    let config = Config::default()
        .with_max_candidates(MAX_CANDIDATES)
        .with_probe_interval(Duration::from_millis(5));
    let mut client = Behaviour::new(rng, config);

    let peers = peer_pool();
    // (cid, endpoint, is_outbound) — outbound uses dial_request handler.
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint, bool)>> = HashMap::new();
    let mut next_conn: usize = 1;

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
                    client.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    client.handle_established_inbound_connection(
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
                client.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
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
                    client.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
            }
            FuzzAction::NewExternalCandidate { slot } => {
                let addr = global_addr(slot);
                client.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                    NewExternalAddrCandidate { addr: &addr },
                ));
            }
            FuzzAction::InjectPeerHasServerSupport { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_out)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if !is_out {
                    continue;
                }
                client.fuzz_inject_peer_has_server_support(peer, cid);
            }
            FuzzAction::AdvanceProbeClock => {
                client.fuzz_expire_probe_timer();
                drain_behaviour(&mut client);
            }
            FuzzAction::InjectDialBackNonce {
                peer_slot,
                mismatch,
                nonce_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                let pending = client.fuzz_pending_nonces();
                let nonce = resolve_nonce(&pending, nonce_slot, mismatch);
                client.fuzz_inject_dial_back_nonce(peer, cid, nonce);
            }
            FuzzAction::InjectTestOutcome {
                peer_slot,
                success,
                nonce_slot,
                mismatch,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_out)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if !is_out {
                    continue;
                }
                let pending = client.fuzz_pending_nonces();
                let nonce = resolve_nonce(&pending, nonce_slot, mismatch);
                client.fuzz_inject_test_outcome(
                    peer,
                    cid,
                    nonce,
                    success,
                    global_addr(nonce_slot),
                );
            }
            FuzzAction::FloodCandidates { count } => {
                let n = (count as usize % 8).max(1);
                for i in 0..n {
                    let addr = global_addr(i as u8);
                    client.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                        NewExternalAddrCandidate { addr: &addr },
                    ));
                }
            }
        }

        drain_behaviour(&mut client);
        assert_v2_invariants(&client);
    }

    assert_v2_invariants(&client);
}

fn resolve_nonce(pending: &[u64], slot: u8, mismatch: bool) -> u64 {
    if mismatch || pending.is_empty() {
        return 0xF000_0000_0000_0000u64.wrapping_add(u64::from(slot));
    }
    let from_end = (slot as usize) % pending.len();
    pending[pending.len() - 1 - from_end]
}

fn drain_behaviour(client: &mut Behaviour<rand::rngs::StdRng>) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match client.poll(&mut cx) {
            Poll::Ready(ToSwarm::GenerateEvent(_))
            | Poll::Ready(ToSwarm::NotifyHandler { .. })
            | Poll::Ready(ToSwarm::ExternalAddrConfirmed(_)) => {}
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

fn assert_v2_invariants(client: &Behaviour<rand::rngs::StdRng>) {
    assert!(
        client.fuzz_candidate_count() <= MAX_CANDIDATES.saturating_add(8),
        "v2 candidates unbounded: {}",
        client.fuzz_candidate_count()
    );
    assert!(
        client.fuzz_peer_info_count() <= MAX_ACTIONS.saturating_add(2),
        "v2 peer_info unbounded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_candidate_support_probe_dialback() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectPeerHasServerSupport { peer_slot: 0 },
            FuzzAction::NewExternalCandidate { slot: 0 },
            FuzzAction::AdvanceProbeClock,
            FuzzAction::InjectDialBackNonce {
                peer_slot: 1,
                mismatch: false,
                nonce_slot: 0,
            },
            FuzzAction::InjectTestOutcome {
                peer_slot: 0,
                success: true,
                nonce_slot: 0,
                mismatch: false,
            },
        ]);
    }

    #[test]
    fn smoke_flood_candidates_and_ghost_nonce() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectPeerHasServerSupport { peer_slot: 0 },
            FuzzAction::FloodCandidates { count: 6 },
            FuzzAction::AdvanceProbeClock,
            FuzzAction::InjectDialBackNonce {
                peer_slot: 0,
                mismatch: true,
                nonce_slot: 3,
            },
            FuzzAction::Disconnect { peer_slot: 0 },
        ]);
    }
}
