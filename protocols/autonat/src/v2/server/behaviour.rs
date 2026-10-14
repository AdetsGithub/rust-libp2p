use std::{
    collections::{HashMap, VecDeque},
    io,
    task::{Context, Poll},
};

use either::Either;
use libp2p_core::{Endpoint, Multiaddr, transport::PortUse};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionId, DialFailure, FromSwarm, NetworkBehaviour,
    ToSwarm,
    dial_opts::{DialOpts, PeerCondition},
    dummy,
};
use rand::{SeedableRng, rngs::StdRng};

use crate::v2::server::handler::{
    Handler, dial_back,
    dial_request::{self, DialBackCommand, DialBackStatus},
};

#[cfg(feature = "fuzzing")]
use crate::v2::Nonce;
#[cfg(feature = "fuzzing")]
use futures::channel::oneshot;
#[cfg(feature = "fuzzing")]
use libp2p_swarm::DialError;

pub struct Behaviour<R = StdRng>
where
    R: Send + rand::Rng + SeedableRng + 'static,
{
    dialing_dial_back: HashMap<ConnectionId, DialBackCommand>,
    pending_events: VecDeque<
        ToSwarm<
            <Self as NetworkBehaviour>::ToSwarm,
            <<Self as NetworkBehaviour>::ConnectionHandler as ConnectionHandler>::FromBehaviour,
        >,
    >,
    rng: R,
}

impl Default for Behaviour<StdRng> {
    fn default() -> Self {
        Self::new(rand::make_rng::<StdRng>())
    }
}

impl<R> Behaviour<R>
where
    R: rand::Rng + Send + SeedableRng + 'static,
{
    pub fn new(rng: R) -> Self {
        Self {
            dialing_dial_back: HashMap::new(),
            pending_events: VecDeque::new(),
            rng,
        }
    }

    /// Number of in-flight dial-back dials awaiting connect / DialFailure.
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_dialing_count(&self) -> usize {
        self.dialing_dial_back.len()
    }

    /// Pending `ToSwarm` queue length (Dial / GenerateEvent).
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_pending_event_count(&self) -> usize {
        self.pending_events.len()
    }

    /// ConnectionIds currently waiting for dial-back connect.
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_dialing_connection_ids(&self) -> Vec<ConnectionId> {
        self.dialing_dial_back.keys().copied().collect()
    }

    /// Inject a dial-back command as if the dial-request handler requested it.
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_inject_dial_back_command(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        addr: Multiaddr,
        nonce: Nonce,
    ) {
        let (back_channel, _rx) = oneshot::channel();
        self.on_connection_handler_event(
            peer_id,
            connection_id,
            Either::Right(Either::Left(DialBackCommand {
                addr,
                nonce,
                back_channel,
            })),
        );
    }

    /// Fail one (or all) pending dial-back dials via [`FromSwarm::DialFailure`].
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_inject_dial_failure(&mut self, connection_id: Option<ConnectionId>) {
        let ids: Vec<ConnectionId> = match connection_id {
            Some(id) => vec![id],
            None => self.dialing_dial_back.keys().copied().collect(),
        };
        for connection_id in ids {
            self.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                peer_id: None,
                error: &DialError::NoAddresses,
                connection_id,
            }));
        }
    }

    /// Inject dial-back handler result (Ok / DialBackErr) on an outbound connection.
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_inject_dial_back_result(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        success: bool,
    ) {
        let result = if success {
            Ok(())
        } else {
            Err(io::Error::other("fuzz dial-back failed"))
        };
        self.on_connection_handler_event(
            peer_id,
            connection_id,
            Either::Left(Either::Left(result)),
        );
    }

    /// Inject a completed dial-request status event (server observed outcome).
    #[cfg(feature = "fuzzing")]
    pub fn fuzz_inject_status_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: Event,
    ) {
        self.on_connection_handler_event(
            peer_id,
            connection_id,
            Either::Right(Either::Right(event)),
        );
    }
}

impl<R> NetworkBehaviour for Behaviour<R>
where
    R: rand::Rng + Send + SeedableRng + 'static,
{
    type ConnectionHandler = Handler<R>;

    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<<Self as NetworkBehaviour>::ConnectionHandler, ConnectionDenied> {
        Ok(Either::Right(dial_request::Handler::new(
            peer,
            remote_addr.clone(),
            self.rng.fork(),
        )))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<<Self as NetworkBehaviour>::ConnectionHandler, ConnectionDenied> {
        Ok(match self.dialing_dial_back.remove(&connection_id) {
            Some(cmd) => Either::Left(Either::Left(dial_back::Handler::new(cmd))),
            None => Either::Left(Either::Right(dummy::ConnectionHandler)),
        })
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::DialFailure(DialFailure { connection_id, .. }) = event
            && let Some(DialBackCommand { back_channel, .. }) =
                self.dialing_dial_back.remove(&connection_id)
        {
            let dial_back_status = DialBackStatus::DialErr;
            let _ = back_channel.send(Err(dial_back_status));
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: <Handler<R> as ConnectionHandler>::ToBehaviour,
    ) {
        match event {
            Either::Left(Either::Left(Ok(_))) => {}
            Either::Left(Either::Left(Err(e))) => {
                tracing::debug!("dial back error: {e:?}");
            }
            Either::Left(Either::Right(v)) => libp2p_core::util::unreachable(v),
            Either::Right(Either::Left(cmd)) => {
                let addr = cmd.addr.clone();
                let opts = DialOpts::peer_id(peer_id)
                    .addresses(Vec::from([addr]))
                    .condition(PeerCondition::Always)
                    .allocate_new_port()
                    .build();
                let conn_id = opts.connection_id();
                self.dialing_dial_back.insert(conn_id, cmd);
                self.pending_events.push_back(ToSwarm::Dial { opts });
            }
            Either::Right(Either::Right(status_update)) => self
                .pending_events
                .push_back(ToSwarm::GenerateEvent(status_update)),
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, <Handler<R> as ConnectionHandler>::FromBehaviour>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}

#[derive(Debug)]
pub struct Event {
    /// All address that were submitted for testing.
    pub all_addrs: Vec<Multiaddr>,
    /// The address that was eventually tested.
    pub tested_addr: Multiaddr,
    /// The peer id of the client that submitted addresses for testing.
    pub client: PeerId,
    /// The amount of data that was requested by the server and was transmitted.
    pub data_amount: usize,
    /// The result of the test.
    pub result: Result<(), io::Error>,
}
