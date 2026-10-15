#![no_main]

//! MemoryTransport swarm compose: relay hop server + relay clients + DCUtR.
//!
//! Exercises reservation → circuit dial → hole-punch upgrade scheduling under
//! paused Tokio time (no live UDP). Complements isolated `relay_behaviour` /
//! `dcutr_behaviour` bins with real Swarm transport + client::Transport.
//!
//! FOCUS counters (kept live so llvm-cov / soaks can see the pipeline warm):
//! reservation_accepted → circuit_established / circuit_req_* → dcutr_ok|err
//! + relayed ConnectionEstablished.
//!
//! Invariants (panic = finding):
//! - Event-tracked peer maps stay aligned with `Swarm::is_connected`.
//! - Soft DoS clamps on swarm/client counts and tracked connections.

use std::{
    collections::HashMap,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use futures::{future::poll_fn, Stream};
use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_core::{
    Multiaddr, Transport,
    multiaddr::Protocol,
    transport::{MemoryTransport, OrTransport},
    upgrade::Version,
};
// Relay reservations require an advertised external address (see relay tests).
use libp2p_dcutr as dcutr;
use libp2p_identify::{Behaviour as IdentifyBehaviour, Config as IdentifyConfig};
use libp2p_identity::{Keypair, PeerId};
use libp2p_plaintext as plaintext;
use libp2p_relay as relay;
use libp2p_swarm::{
    NetworkBehaviour, Swarm, SwarmEvent,
    Config as SwarmConfig,
    dial_opts::{DialOpts, PeerCondition},
};
use libp2p_yamux as yamux;

const MAX_ACTIONS: usize = 48;
const MAX_POLL_PER_ACTION: usize = 96;
const MAX_TOTAL_POLLS: usize = 2_048;
const MIN_CLIENTS: usize = 2;
const MAX_CLIENTS: usize = 3;

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct RelayServerBehaviour {
    relay: relay::Behaviour,
    identify: IdentifyBehaviour,
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct ClientBehaviour {
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: IdentifyBehaviour,
}

#[derive(Debug, Clone)]
enum FuzzAction {
    /// Relay listens on `/memory/0`.
    RelayListen,
    /// Client `i` listens on `/memory/0`.
    ClientListen { client: u8 },
    /// Client dials the relay peer (learn addrs / reservation path).
    DialRelay { client: u8 },
    /// Client listens on `relay_addr/p2p-circuit` after learning the relay listen addr.
    ListenCircuit { client: u8 },
    /// Client A dials client B via `relay/p2p-circuit/p2p/<B>`.
    DialViaCircuit { from: u8, to: u8 },
    /// Direct MemoryTransport dial between clients (DCUtR upgrade race).
    DialDirect { from: u8, to: u8 },
    Disconnect {
        /// 0 = relay, 1+ = client index+1
        node: u8,
        peer_slot: u8,
    },
    Poll { budget: u8 },
}

#[derive(Debug)]
struct ActionSeq {
    n_clients: usize,
    actions: Vec<FuzzAction>,
}

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n_clients = u.int_in_range(MIN_CLIENTS..=MAX_CLIENTS)?;
        let n = u.int_in_range(10..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n + 8);
        // Recipe mirrors protocols/relay/tests: listen → add_external (in event
        // handler) → dial relay → listen_on(p2p-circuit) → long poll for
        // ReservationReqAccepted → circuit dials.
        actions.push(FuzzAction::RelayListen);
        actions.push(FuzzAction::Poll { budget: 32 });
        for i in 0..n_clients {
            actions.push(FuzzAction::ClientListen { client: i as u8 });
        }
        actions.push(FuzzAction::Poll { budget: 32 });
        for i in 0..n_clients {
            actions.push(FuzzAction::DialRelay { client: i as u8 });
        }
        actions.push(FuzzAction::Poll { budget: 64 });
        for i in 0..n_clients {
            actions.push(FuzzAction::ListenCircuit { client: i as u8 });
        }
        // Reservation hop RTT under paused time needs a fat poll window.
        actions.push(FuzzAction::Poll { budget: 96 });
        // One guaranteed circuit dial (client0 → client1) before free actions.
        if n_clients >= 2 {
            actions.push(FuzzAction::DialViaCircuit { from: 0, to: 1 });
            actions.push(FuzzAction::Poll { budget: 96 });
            actions.push(FuzzAction::DialDirect { from: 0, to: 1 });
            actions.push(FuzzAction::Poll { budget: 64 });
        }
        for step in 0..n {
            actions.push(fuzz_action(u, step, n_clients)?);
        }
        actions.push(FuzzAction::Poll { budget: 96 });
        Ok(ActionSeq { n_clients, actions })
    }
}

fn fuzz_action(
    u: &mut Unstructured<'_>,
    _step: usize,
    n_clients: usize,
) -> arbitrary::Result<FuzzAction> {
    let nc = n_clients as u8;
    Ok(match u.int_in_range(0u8..=19)? {
        0..=3 => FuzzAction::DialViaCircuit {
            from: u.int_in_range(0..=nc.saturating_sub(1))?,
            to: u.int_in_range(0..=nc.saturating_sub(1))?,
        },
        4..=6 => FuzzAction::DialDirect {
            from: u.int_in_range(0..=nc.saturating_sub(1))?,
            to: u.int_in_range(0..=nc.saturating_sub(1))?,
        },
        7..=8 => FuzzAction::ListenCircuit {
            client: u.int_in_range(0..=nc.saturating_sub(1))?,
        },
        9..=10 => FuzzAction::DialRelay {
            client: u.int_in_range(0..=nc.saturating_sub(1))?,
        },
        11..=12 => FuzzAction::Disconnect {
            node: u.int_in_range(0..=nc)?, // 0=relay
            peer_slot: u.arbitrary()?,
        },
        _ => FuzzAction::Poll {
            budget: u.int_in_range(8..=48)?,
        },
    })
}

struct NodeState<B: NetworkBehaviour> {
    swarm: Swarm<B>,
    listen: Option<Multiaddr>,
    /// Last `/p2p-circuit` listen addr (reservation surface).
    circuit_listen: Option<Multiaddr>,
    connected: HashMap<PeerId, usize>,
}

/// End-of-run FOCUS tallies for reservation → circuit → DCUtR.
#[derive(Default)]
struct FocusCounters {
    reservation_accepted_server: u32,
    reservation_accepted_client: u32,
    reservation_denied: u32,
    circuit_req_accepted: u32,
    circuit_req_denied: u32,
    circuit_out_established: u32,
    circuit_in_established: u32,
    relayed_connections: u32,
    dcutr_ok: u32,
    dcutr_err: u32,
}

struct World {
    relay: NodeState<RelayServerBehaviour>,
    clients: Vec<NodeState<ClientBehaviour>>,
    focus: FocusCounters,
    total_polls: usize,
}

impl World {
    fn new(n_clients: usize) -> Self {
        Self {
            relay: NodeState {
                swarm: new_relay(0),
                listen: None,
                circuit_listen: None,
                connected: HashMap::new(),
            },
            clients: (0..n_clients)
                .map(|i| NodeState {
                    swarm: new_client(i as u8),
                    listen: None,
                    circuit_listen: None,
                    connected: HashMap::new(),
                })
                .collect(),
            focus: FocusCounters::default(),
            total_polls: 0,
        }
    }

    fn assert_invariants(&self) {
        assert!(self.clients.len() <= MAX_CLIENTS);
        check_connected(&self.relay);
        for c in &self.clients {
            check_connected(c);
        }
        // Soft DoS: FOCUS counters must not explode beyond action budget.
        let f = &self.focus;
        let soft = (MAX_ACTIONS as u32).saturating_mul(MAX_CLIENTS as u32 + 2);
        assert!(f.reservation_accepted_server <= soft);
        assert!(f.reservation_accepted_client <= soft);
        assert!(f.circuit_req_accepted <= soft);
        assert!(f.circuit_out_established <= soft);
        assert!(f.circuit_in_established <= soft);
        assert!(f.relayed_connections <= soft.saturating_mul(2));
        assert!(f.dcutr_ok.saturating_add(f.dcutr_err) <= soft);
    }
}

fn check_connected<B: NetworkBehaviour>(st: &NodeState<B>) {
    for (peer, &n) in &st.connected {
        assert!(n > 0, "tracked zero conns for {peer}");
        assert!(
            st.swarm.is_connected(peer),
            "tracked {peer} but is_connected=false"
        );
    }
    for peer in st.swarm.connected_peers() {
        assert!(
            st.connected.contains_key(peer),
            "swarm connected to {peer} but not tracked"
        );
    }
}

fn seed_keypair(role: u8, slot: u8) -> Keypair {
    let mut seed = [0xC1u8; 32];
    seed[30] = role;
    seed[31] = slot;
    Keypair::ed25519_from_bytes(&mut seed).expect("circuit ed25519")
}

fn new_relay(slot: u8) -> Swarm<RelayServerBehaviour> {
    let identity = seed_keypair(0, slot);
    let peer_id = PeerId::from(identity.public());
    // Match relay integration tests (`Version::V1`, not V1Lazy).
    let transport = MemoryTransport::default()
        .upgrade(Version::V1)
        .authenticate(plaintext::Config::new(&identity))
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_millis(500))
        .boxed();
    let relay = relay::Behaviour::new(
        peer_id,
        relay::Config {
            reservation_duration: Duration::from_secs(60),
            max_reservations: 8,
            max_reservations_per_peer: 2,
            max_circuits: 8,
            max_circuits_per_peer: 2,
            max_circuit_duration: Duration::from_secs(60),
            max_circuit_bytes: 1 << 17,
            ..Default::default()
        },
    );
    let identify = IdentifyBehaviour::new(
        IdentifyConfig::new("/swarm-circuit-relay/1.0.0".into(), identity.public())
            .with_interval(Duration::from_millis(200)),
    );
    Swarm::new(
        transport,
        RelayServerBehaviour { relay, identify },
        peer_id,
        SwarmConfig::with_tokio_executor()
            // Keep relayed / reservation streams alive across fat Poll windows.
            .with_idle_connection_timeout(Duration::from_millis(500)),
    )
}

fn new_client(slot: u8) -> Swarm<ClientBehaviour> {
    let identity = seed_keypair(1, slot);
    let peer_id = PeerId::from(identity.public());
    let (relay_transport, relay_behaviour) = relay::client::new(peer_id);
    let transport = OrTransport::new(relay_transport, MemoryTransport::default())
        .upgrade(Version::V1)
        .authenticate(plaintext::Config::new(&identity))
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_millis(500))
        .boxed();
    let identify = IdentifyBehaviour::new(
        IdentifyConfig::new("/swarm-circuit-client/1.0.0".into(), identity.public())
            .with_interval(Duration::from_millis(200)),
    );
    Swarm::new(
        transport,
        ClientBehaviour {
            relay: relay_behaviour,
            dcutr: dcutr::Behaviour::new(peer_id),
            identify,
        },
        peer_id,
        SwarmConfig::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_millis(500)),
    )
}

fn memory_addr() -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Memory(0));
    a
}

fn on_relay_event(
    st: &mut NodeState<RelayServerBehaviour>,
    focus: &mut FocusCounters,
    ev: SwarmEvent<RelayServerBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Hop server only advertises reservations for external addresses.
            st.swarm.add_external_address(address.clone());
            st.listen = Some(address);
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            *st.connected.entry(peer_id).or_insert(0) += 1;
            if endpoint.is_relayed() {
                focus.relayed_connections = focus.relayed_connections.saturating_add(1);
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            if let Some(n) = st.connected.get_mut(&peer_id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.connected.remove(&peer_id);
                }
            }
        }
        SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(ev)) => match ev {
            relay::Event::ReservationReqAccepted { .. } => {
                focus.reservation_accepted_server =
                    focus.reservation_accepted_server.saturating_add(1);
            }
            relay::Event::ReservationReqDenied { .. } => {
                focus.reservation_denied = focus.reservation_denied.saturating_add(1);
            }
            relay::Event::CircuitReqAccepted { .. } => {
                focus.circuit_req_accepted = focus.circuit_req_accepted.saturating_add(1);
            }
            relay::Event::CircuitReqDenied { .. } => {
                focus.circuit_req_denied = focus.circuit_req_denied.saturating_add(1);
            }
            _ => {}
        },
        _ => {}
    }
}

fn on_client_event(
    st: &mut NodeState<ClientBehaviour>,
    focus: &mut FocusCounters,
    ev: SwarmEvent<ClientBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            let is_circuit = address.iter().any(|p| matches!(p, Protocol::P2pCircuit));
            if is_circuit {
                st.circuit_listen = Some(address.clone());
            }
            // Prefer direct memory listen for DialDirect.
            if address.iter().any(|p| matches!(p, Protocol::Memory(_))) && !is_circuit {
                st.listen = Some(address);
            } else if st.listen.is_none() && !is_circuit {
                st.listen = Some(address);
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            *st.connected.entry(peer_id).or_insert(0) += 1;
            if endpoint.is_relayed() {
                focus.relayed_connections = focus.relayed_connections.saturating_add(1);
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            if let Some(n) = st.connected.get_mut(&peer_id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.connected.remove(&peer_id);
                }
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Relay(ev)) => match ev {
            relay::client::Event::ReservationReqAccepted { .. } => {
                focus.reservation_accepted_client =
                    focus.reservation_accepted_client.saturating_add(1);
            }
            relay::client::Event::OutboundCircuitEstablished { .. } => {
                focus.circuit_out_established =
                    focus.circuit_out_established.saturating_add(1);
            }
            relay::client::Event::InboundCircuitEstablished { .. } => {
                focus.circuit_in_established =
                    focus.circuit_in_established.saturating_add(1);
            }
        },
        SwarmEvent::Behaviour(ClientBehaviourEvent::Dcutr(dcutr::Event { result, .. })) => {
            match result {
                Ok(_) => focus.dcutr_ok = focus.dcutr_ok.saturating_add(1),
                Err(_) => focus.dcutr_err = focus.dcutr_err.saturating_add(1),
            }
        }
        _ => {}
    }
}

async fn drive(world: &mut World, budget: usize) {
    let budget = budget.min(MAX_POLL_PER_ACTION);
    for tick in 0..budget {
        if world.total_polls >= MAX_TOTAL_POLLS {
            break;
        }
        world.total_polls += 1;

        let mut progress = false;
        loop {
            let ev = poll_fn(|cx| match Pin::new(&mut world.relay.swarm).poll_next(cx) {
                Poll::Ready(Some(e)) => Poll::Ready(Some(e)),
                Poll::Ready(None) | Poll::Pending => Poll::Ready(None),
            })
            .await;
            match ev {
                Some(e) => {
                    on_relay_event(&mut world.relay, &mut world.focus, e);
                    progress = true;
                }
                None => break,
            }
        }
        for i in 0..world.clients.len() {
            loop {
                let ev = poll_fn(|cx| match Pin::new(&mut world.clients[i].swarm).poll_next(cx) {
                    Poll::Ready(Some(e)) => Poll::Ready(Some(e)),
                    Poll::Ready(None) | Poll::Pending => Poll::Ready(None),
                })
                .await;
                match ev {
                    Some(e) => {
                        on_client_event(&mut world.clients[i], &mut world.focus, e);
                        progress = true;
                    }
                    None => break,
                }
            }
        }
        tokio::task::yield_now().await;
        if tick % 4 == 3 {
            tokio::time::advance(Duration::from_millis(60)).await;
        }
        if !progress {
            tokio::time::advance(Duration::from_millis(10)).await;
        }
    }
    world.assert_invariants();
}

static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn run(seq: ActionSeq) {
    // Reuse a single runtime across iterations: a fresh
    // `new_current_thread().enable_all()` per input leaks the I/O driver's
    // epoll + eventfd fds (~2 fds/iteration), exhausting the process fd limit
    // (EMFILE, "Too many open files") after a few hundred execs.
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio")
    });
    rt.block_on(async move {
        tokio::time::pause();
        let mut world = World::new(seq.n_clients);
        for action in seq.actions {
            match action {
                FuzzAction::RelayListen => {
                    let _ = world.relay.swarm.listen_on(memory_addr());
                }
                FuzzAction::ClientListen { client } => {
                    let i = (client as usize) % world.clients.len();
                    let _ = world.clients[i].swarm.listen_on(memory_addr());
                }
                FuzzAction::DialRelay { client } => {
                    let i = (client as usize) % world.clients.len();
                    let Some(relay_addr) = world.relay.listen.clone() else {
                        continue;
                    };
                    let relay_peer = *world.relay.swarm.local_peer_id();
                    let addr = relay_addr.with(Protocol::P2p(relay_peer));
                    let _ = world.clients[i].swarm.dial(
                        DialOpts::peer_id(relay_peer)
                            .condition(PeerCondition::Always)
                            .addresses(vec![addr])
                            .build(),
                    );
                }
                FuzzAction::ListenCircuit { client } => {
                    let i = (client as usize) % world.clients.len();
                    let Some(relay_addr) = world.relay.listen.clone() else {
                        continue;
                    };
                    let relay_peer = *world.relay.swarm.local_peer_id();
                    let circuit = relay_addr
                        .with(Protocol::P2p(relay_peer))
                        .with(Protocol::P2pCircuit);
                    let _ = world.clients[i].swarm.listen_on(circuit);
                }
                FuzzAction::DialViaCircuit { from, to } => {
                    let a = (from as usize) % world.clients.len();
                    let b = (to as usize) % world.clients.len();
                    if a == b {
                        continue;
                    }
                    let Some(relay_addr) = world.relay.listen.clone() else {
                        continue;
                    };
                    let relay_peer = *world.relay.swarm.local_peer_id();
                    let dest = *world.clients[b].swarm.local_peer_id();
                    let addr = relay_addr
                        .with(Protocol::P2p(relay_peer))
                        .with(Protocol::P2pCircuit)
                        .with(Protocol::P2p(dest));
                    let _ = world.clients[a].swarm.dial(
                        DialOpts::peer_id(dest)
                            .condition(PeerCondition::Always)
                            .addresses(vec![addr])
                            .build(),
                    );
                }
                FuzzAction::DialDirect { from, to } => {
                    let a = (from as usize) % world.clients.len();
                    let b = (to as usize) % world.clients.len();
                    if a == b {
                        continue;
                    }
                    let Some(addr) = world.clients[b].listen.clone() else {
                        continue;
                    };
                    let dest = *world.clients[b].swarm.local_peer_id();
                    let addr = addr.with(Protocol::P2p(dest));
                    let _ = world.clients[a].swarm.dial(
                        DialOpts::peer_id(dest)
                            .condition(PeerCondition::Always)
                            .addresses(vec![addr])
                            .build(),
                    );
                }
                FuzzAction::Disconnect { node, peer_slot } => {
                    if node == 0 {
                        let peers: Vec<_> = world.relay.connected.keys().copied().collect();
                        if peers.is_empty() {
                            continue;
                        }
                        let peer = peers[(peer_slot as usize) % peers.len()];
                        let _ = world.relay.swarm.disconnect_peer_id(peer);
                    } else {
                        let i = ((node - 1) as usize) % world.clients.len();
                        let peers: Vec<_> = world.clients[i].connected.keys().copied().collect();
                        if peers.is_empty() {
                            continue;
                        }
                        let peer = peers[(peer_slot as usize) % peers.len()];
                        let _ = world.clients[i].swarm.disconnect_peer_id(peer);
                    }
                }
                FuzzAction::Poll { budget } => {
                    drive(&mut world, budget as usize).await;
                }
            }
            world.assert_invariants();
        }
        drive(&mut world, 32).await;
        world.assert_invariants();
        // Keep FOCUS tallies live for coverage / ASan builds.
        let _ = (
            world.focus.reservation_accepted_server,
            world.focus.reservation_accepted_client,
            world.focus.circuit_req_accepted,
            world.focus.circuit_out_established,
            world.focus.circuit_in_established,
            world.focus.relayed_connections,
            world.focus.dcutr_ok,
            world.focus.dcutr_err,
            world
                .clients
                .iter()
                .filter(|c| c.circuit_listen.is_some())
                .count(),
        );
        // Reset the paused clock so the next input starts from a clean state.
        tokio::time::resume();
    });
}

fuzz_target!(|seq: ActionSeq| {
    run(seq);
});
