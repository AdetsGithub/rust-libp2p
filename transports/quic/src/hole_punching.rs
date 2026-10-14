use std::{
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use futures::{channel::oneshot, future::Either};
use rand::{RngExt, distr};

use crate::{Connecting, Error, provider::Provider};

/// Tracks in-flight `dial_as_listener` hole-punch attempts keyed by remote UDP addr.
///
/// Mirrors the Occupied/Vacant / stale-canceled overwrite logic used by
/// [`crate::GenTransport::dial`].
#[derive(Debug, Default)]
pub(crate) struct HolePunchBook {
    attempts: HashMap<SocketAddr, oneshot::Sender<Connecting>>,
}

impl HolePunchBook {
    pub(crate) fn new() -> Self {
        Self {
            attempts: HashMap::new(),
        }
    }

    /// Register a new hole-punch waiter. Returns the receiver side.
    ///
    /// Errors with [`Error::HolePunchInProgress`] if an active (non-canceled)
    /// attempt already exists for `addr`.
    pub(crate) fn register(
        &mut self,
        addr: SocketAddr,
    ) -> Result<oneshot::Receiver<Connecting>, Error> {
        let (sender, receiver) = oneshot::channel();
        match self.attempts.entry(addr) {
            Entry::Occupied(mut sender_entry) => {
                // Stale senders, i.e. from failed hole punches are not removed.
                // Thus, we can just overwrite a stale sender.
                if !sender_entry.get().is_canceled() {
                    return Err(Error::HolePunchInProgress(addr));
                }
                sender_entry.insert(sender);
            }
            Entry::Vacant(entry) => {
                entry.insert(sender);
            }
        }
        Ok(receiver)
    }

    /// Take the waiter for an inbound connection matching `addr` (completes punch).
    pub(crate) fn complete(&mut self, addr: &SocketAddr) -> Option<oneshot::Sender<Connecting>> {
        self.attempts.remove(addr)
    }

    pub(crate) fn len(&self) -> usize {
        self.attempts.len()
    }

    pub(crate) fn contains(&self, addr: &SocketAddr) -> bool {
        self.attempts.contains_key(addr)
    }
}

pub(crate) async fn hole_puncher<P: Provider>(
    socket: UdpSocket,
    remote_addr: SocketAddr,
    timeout_duration: Duration,
) -> Error {
    let punch_holes_future = punch_holes::<P>(socket, remote_addr);
    futures::pin_mut!(punch_holes_future);
    match futures::future::select(P::sleep(timeout_duration), punch_holes_future).await {
        Either::Left(_) => Error::HandshakeTimedOut,
        Either::Right((Err(hole_punch_err), _)) => hole_punch_err,
        Either::Right((Ok(never), _)) => match never {},
    }
}

async fn punch_holes<P: Provider>(
    socket: UdpSocket,
    remote_addr: SocketAddr,
) -> Result<Infallible, Error> {
    loop {
        let contents: Vec<u8> = rand::rng()
            .sample_iter(distr::StandardUniform)
            .take(64)
            .collect();

        tracing::trace!("Sending random UDP packet to {remote_addr}");

        P::send_to(&socket, &contents, remote_addr).await?;

        let sleep_duration = Duration::from_millis(rand::random_range(10..=200));
        P::sleep(sleep_duration).await;
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) mod fuzz_book {
    use super::*;

    /// Drive [`HolePunchBook`] register / cancel / complete races (no UDP).
    pub(crate) fn fuzz_hole_punch_book(data: &[u8]) {
        let mut book = HolePunchBook::new();
        let mut receivers: HashMap<SocketAddr, oneshot::Receiver<Connecting>> = HashMap::new();
        const MAX_STEPS: usize = 64;
        const MAX_ADDRS: u8 = 8;

        for (i, &byte) in data.iter().take(MAX_STEPS).enumerate() {
            let addr = SocketAddr::from(([198, 51, 100, 1 + (byte % MAX_ADDRS)], 4000 + u16::from(byte)));
            match byte % 4 {
                0 => {
                    // Register (may HolePunchInProgress).
                    match book.register(addr) {
                        Ok(rx) => {
                            receivers.insert(addr, rx);
                        }
                        Err(Error::HolePunchInProgress(_)) => {
                            assert!(book.contains(&addr));
                        }
                        Err(_) => {}
                    }
                }
                1 => {
                    // Cancel by dropping receiver (stale sender → overwriteable).
                    let _ = receivers.remove(&addr);
                }
                2 => {
                    // Complete inbound: take sender; drop without send (timed-out punch).
                    if let Some(tx) = book.complete(&addr) {
                        let _ = tx;
                        receivers.remove(&addr);
                    }
                }
                _ => {
                    // Double-register stress: register then immediately register again.
                    if let Ok(rx) = book.register(addr) {
                        receivers.insert(addr, rx);
                    }
                    let err = book.register(addr);
                    assert!(
                        matches!(err, Err(Error::HolePunchInProgress(_)))
                            || matches!(err, Ok(_)),
                        "unexpected register result at step {i}"
                    );
                    if let Ok(rx) = err {
                        // Only Ok if previous was canceled between calls.
                        receivers.insert(addr, rx);
                    }
                }
            }
            assert!(
                book.len() <= MAX_ADDRS as usize + 2,
                "hole-punch book unbounded: {}",
                book.len()
            );
        }
    }
}
