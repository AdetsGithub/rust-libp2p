// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
    task::{Context, Poll, Waker},
};

#[cfg(feature = "loom")]
use loom::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
#[cfg(not(feature = "loom"))]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::{MessageId, types::RpcOut};

const CONTROL_MSGS_LIMIT: usize = 20_000;

/// An async priority queue used to dispatch messages from the `NetworkBehaviour`
/// Provides a clean abstraction over high-priority (unbounded), control (bounded),
/// and non priority (bounded) message queues.
#[derive(Debug)]
pub(crate) struct Queue {
    /// High-priority unbounded queue (Subscribe, Unsubscribe)
    pub(crate) priority: Shared,
    /// Control messages bounded queue (Graft, Prune, IDontWant)
    pub(crate) control: Shared,
    /// Low-priority bounded queue (Publish, Forward, IHave, IWant)
    pub(crate) non_priority: Shared,
    /// The id of the current reference of the counter.
    pub(crate) id: usize,
    /// The total number of references for the queue.
    pub(crate) count: Arc<AtomicUsize>,
}

impl Queue {
    /// Create a new `Queue` with `capacity`.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            priority: Shared::new(),
            control: Shared::with_capacity(CONTROL_MSGS_LIMIT),
            non_priority: Shared::with_capacity(capacity),
            id: 1,
            count: Arc::new(AtomicUsize::new(1)),
        }
    }

    /// Try to push a message to the Queue, return Err if the queue is full,
    /// which will only happen for control and non priority messages.
    pub(crate) fn try_push(&mut self, message: RpcOut) -> Result<(), Box<RpcOut>> {
        match message {
            RpcOut::Extensions(_)
            | RpcOut::Subscribe { .. }
            | RpcOut::SubscribeMany(_)
            | RpcOut::Unsubscribe(_) => {
                self.priority
                    .try_push(message)
                    .expect("Shared is unbounded");
                Ok(())
            }
            RpcOut::Graft(_) | RpcOut::Prune(_) | RpcOut::IDontWant(_) => {
                self.control.try_push(message)
            }
            RpcOut::Publish { .. }
            | RpcOut::IHave(_)
            | RpcOut::TestExtension
            | RpcOut::IWant(_) => self.non_priority.try_push(message),
            #[cfg(feature = "partial-messages")]
            RpcOut::PartialMessage(_) => self.non_priority.try_push(message),
        }
    }

    /// Remove pending low priority Publish and Forward messages.
    /// Returns the number of messages removed.
    pub(crate) fn remove_data_messages(&mut self, message_ids: &[MessageId]) -> usize {
        if message_ids.is_empty() {
            return 0;
        }

        // Look the ids up in a set, so a pass costs O(queue + ids) instead of O(queue * ids).
        let message_ids: HashSet<&MessageId> = message_ids.iter().collect();

        let mut count = 0;
        self.non_priority.retain(|message| match message {
            RpcOut::Publish { message_id, .. } if message_ids.contains(message_id) => {
                count += 1;
                false
            }
            _ => true,
        });
        count
    }

    /// Pop an element from the queue.
    pub(crate) fn poll_pop(&mut self, cx: &mut Context) -> Poll<RpcOut> {
        // First we try the priority messages.
        if let Poll::Ready(rpc) = Pin::new(&mut self.priority).poll_pop(cx) {
            return Poll::Ready(rpc);
        }

        // Then we try the control messages.
        if let Poll::Ready(rpc) = Pin::new(&mut self.control).poll_pop(cx) {
            return Poll::Ready(rpc);
        }

        // Finally we try the non priority messages
        if let Poll::Ready(rpc) = Pin::new(&mut self.non_priority).poll_pop(cx) {
            return Poll::Ready(rpc);
        }

        Poll::Pending
    }

    /// Check if the queue is empty.
    pub(crate) fn is_empty(&self) -> bool {
        if !self.priority.is_empty() {
            return false;
        }

        if !self.control.is_empty() {
            return false;
        }

        if !self.non_priority.is_empty() {
            return false;
        }

        true
    }

    /// Returns the length of the priority queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn priority_len(&self) -> usize {
        self.priority.len() + self.control.len()
    }

    /// Returns the length of the non priority queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn non_priority_len(&self) -> usize {
        self.non_priority.len()
    }

    /// Attempts to pop a message from the queue.
    /// returns None if the queue is empty.
    #[cfg(test)]
    pub(crate) fn try_pop(&mut self) -> Option<RpcOut> {
        // Try priority first
        self.priority
            .try_pop()
            // Then control messages
            .or_else(|| self.control.try_pop())
            // Finally non priority
            .or_else(|| self.non_priority.try_pop())
    }
}

impl Clone for Queue {
    fn clone(&self) -> Self {
        let new_id = self.count.fetch_add(1, Ordering::SeqCst);
        Self {
            priority: Shared {
                inner: self.priority.inner.clone(),
                capacity: self.priority.capacity,
                id: new_id,
            },
            control: Shared {
                inner: self.control.inner.clone(),
                capacity: self.control.capacity,
                id: new_id,
            },
            non_priority: Shared {
                inner: self.non_priority.inner.clone(),
                capacity: self.non_priority.capacity,
                id: new_id,
            },
            id: self.id,
            count: self.count.clone(),
        }
    }
}

/// The internal shared part of the queue,
/// that allows for shallow copies of the queue among each connection of the remote.
#[derive(Debug)]
pub(crate) struct Shared {
    inner: Arc<Mutex<SharedInner>>,
    capacity: Option<usize>,
    id: usize,
}

impl Shared {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedInner {
                queue: VecDeque::new(),
                pending_pops: Default::default(),
            })),
            capacity: Some(capacity),
            id: 1,
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedInner {
                queue: VecDeque::new(),
                pending_pops: Default::default(),
            })),
            capacity: None,
            id: 1,
        }
    }

    /// Pop an element from the queue.
    pub(crate) fn poll_pop(self: std::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<RpcOut> {
        let mut guard = self.inner.lock().expect("lock to not be poisoned");
        match guard.queue.pop_front() {
            Some(t) => Poll::Ready(t),
            None => {
                guard
                    .pending_pops
                    .entry(self.id)
                    .or_insert(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(crate) fn try_push(&mut self, message: RpcOut) -> Result<(), Box<RpcOut>> {
        let mut guard = self.inner.lock().expect("lock to not be poisoned");
        if self
            .capacity
            .is_some_and(|capacity| guard.queue.len() >= capacity)
        {
            return Err(Box::new(message));
        }

        guard.queue.push_back(message);
        // Wake pending registered pops.
        for (_, s) in guard.pending_pops.drain() {
            s.wake();
        }

        Ok(())
    }

    /// Retain only the elements specified by the predicate.
    /// In other words, remove all elements e for which f(&e) returns false. The elements are
    /// visited in unsorted (and unspecified) order. Returns the cleared messages.
    pub(crate) fn retain<F: FnMut(&RpcOut) -> bool>(&mut self, f: F) {
        let mut shared = self.inner.lock().expect("lock to not be poisoned");
        shared.queue.retain(f);
    }

    /// Mutate each queued message in place (fuzz harness: expire Publish delays).
    #[cfg(feature = "fuzzing")]
    pub(crate) fn for_each_mut<F: FnMut(&mut RpcOut)>(&mut self, mut f: F) {
        let mut shared = self.inner.lock().expect("lock to not be poisoned");
        for msg in shared.queue.iter_mut() {
            f(msg);
        }
    }

    /// Check if the queue is empty.
    pub(crate) fn is_empty(&self) -> bool {
        let guard = self.inner.lock().expect("lock to not be poisoned");
        guard.queue.len() == 0
    }

    /// Returns the length of the queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn len(&self) -> usize {
        let guard = self.inner.lock().expect("lock to not be poisoned");
        guard.queue.len()
    }

    /// Attempts to pop an message from the queue.
    /// returns None if the queue is empty.
    #[cfg(test)]
    pub(crate) fn try_pop(&mut self) -> Option<RpcOut> {
        let mut guard = self.inner.lock().expect("lock to not be poisoned");
        guard.queue.pop_front()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        let mut guard = self.inner.lock().expect("lock to not be poisoned");
        guard.pending_pops.remove(&self.id);
    }
}

/// The shared stated by the `NetworkBehaviour`s and the `ConnectionHandler`s.
#[derive(Debug)]
struct SharedInner {
    queue: VecDeque<RpcOut>,
    pending_pops: HashMap<usize, Waker>,
}

/// Loom concurrency models for [`Shared`] / [`Queue`].
///
/// **Not** part of cargo-fuzz. Exhaustive scheduler exploration of Behaviour↔
/// Handler Shared-queue races (priority vs non_priority, capacity / AllQueuesFull,
/// dual-handler poll_pending, remove_data vs pop). Keep per-model branching small.
///
/// ```text
/// cargo test -p libp2p-gossipsub --features loom --lib queue::loom_tests
/// ```
#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use futures::task::noop_waker_ref;
    use futures_timer::Delay;
    use loom::{sync::Arc, thread};

    use super::{Queue, Shared};
    use crate::{
        MessageId, TopicHash,
        types::{RawMessage, RpcOut},
    };

    fn subscribe_msg(tag: u8) -> RpcOut {
        RpcOut::Subscribe {
            topic: TopicHash::from_raw(format!("loom-{tag}")),
            requests_partial: false,
            supports_partial: false,
        }
    }

    fn ihave_msg(tag: u8) -> RpcOut {
        use crate::types::IHave;
        RpcOut::IHave(IHave {
            topic_hash: TopicHash::from_raw(format!("loom-{tag}")),
            message_ids: vec![],
        })
    }

    fn publish_msg(tag: u8) -> RpcOut {
        RpcOut::Publish {
            message_id: MessageId(vec![tag]),
            message: RawMessage {
                source: None,
                data: vec![tag],
                sequence_number: Some(u64::from(tag)),
                topic: TopicHash::from_raw(format!("loom-{tag}")),
                signature: None,
                key: None,
                validated: true,
            },
            timeout: Delay::new(Duration::from_secs(3600)),
        }
    }

    fn is_subscribe(rpc: &RpcOut) -> bool {
        matches!(rpc, RpcOut::Subscribe { .. })
    }

    fn is_publish(rpc: &RpcOut) -> bool {
        matches!(rpc, RpcOut::Publish { .. })
    }

    /// Behaviour clone try_push vs Handler clone try_pop — no lost / double-pop.
    #[test]
    fn queue_clone_push_pop_race() {
        loom::model(|| {
            let q = Queue::new(8);
            let mut producer = q.clone();
            let mut consumer = q.clone();

            let t = thread::spawn(move || {
                let _ = producer.try_push(subscribe_msg(1));
                let _ = producer.try_push(subscribe_msg(2));
            });

            let mut got = 0usize;
            for _ in 0..4 {
                if consumer.try_pop().is_some() {
                    got += 1;
                }
            }
            t.join().unwrap();
            while consumer.try_pop().is_some() {
                got += 1;
            }
            assert_eq!(got, 2, "lost or duplicated messages: got={got}");
        });
    }

    /// Bounded Shared: concurrent push (may full) + pop — len never exceeds capacity.
    #[test]
    fn shared_capacity_push_pop_race() {
        loom::model(|| {
            let shared = Shared::with_capacity(1);
            let mut p = Shared {
                inner: Arc::clone(&shared.inner),
                capacity: shared.capacity,
                id: 2,
            };
            let mut c = Shared {
                inner: Arc::clone(&shared.inner),
                capacity: shared.capacity,
                id: 3,
            };

            let t = thread::spawn(move || {
                let mut accepted = 0usize;
                for i in 0..2u8 {
                    if p.try_push(ihave_msg(i)).is_ok() {
                        accepted += 1;
                    }
                }
                accepted
            });

            let mut popped = 0usize;
            if c.try_pop().is_some() {
                popped += 1;
            }
            let accepted = t.join().unwrap();
            while c.try_pop().is_some() {
                popped += 1;
            }
            assert!(
                popped <= accepted,
                "popped more than accepted: popped={popped} accepted={accepted}"
            );
            assert!(
                accepted <= 2,
                "accepted more than attempted: {accepted}"
            );
            // Capacity 1: at most one in-flight beyond what we popped mid-race.
            assert!(accepted - popped <= 1 || popped == accepted);
        });
    }

    /// Empty poll registers waker; concurrent push drains `pending_pops` — one delivery.
    #[test]
    fn shared_poll_pending_then_push() {
        loom::model(|| {
            let mut waiter = Shared::new();
            let mut pusher = Shared {
                inner: Arc::clone(&waiter.inner),
                capacity: None,
                id: 2,
            };

            let t = thread::spawn(move || {
                let waker = noop_waker_ref();
                let mut cx = Context::from_waker(waker);
                let got = matches!(Pin::new(&mut waiter).poll_pop(&mut cx), Poll::Ready(_));
                (got, waiter)
            });

            let _ = pusher.try_push(subscribe_msg(9));

            let (got_poll, mut waiter) = t.join().unwrap();
            let mut delivered = usize::from(got_poll);
            if waiter.try_pop().is_some() {
                delivered += 1;
            }
            if pusher.try_pop().is_some() {
                delivered += 1;
            }
            assert_eq!(delivered, 1, "lost or duplicated after poll+push: {delivered}");
        });
    }

    /// Dual consumers race on Shared try_pop — each message delivered at most once.
    #[test]
    fn shared_dual_consumer_no_double_pop() {
        loom::model(|| {
            let mut source = Shared::new();
            let _ = source.try_push(subscribe_msg(1));
            let _ = source.try_push(subscribe_msg(2));

            let mut a = Shared {
                inner: Arc::clone(&source.inner),
                capacity: None,
                id: 2,
            };
            let mut b = Shared {
                inner: Arc::clone(&source.inner),
                capacity: None,
                id: 3,
            };

            let t = thread::spawn(move || {
                let mut n = 0usize;
                while a.try_pop().is_some() {
                    n += 1;
                }
                n
            });

            let mut n_b = 0usize;
            while b.try_pop().is_some() {
                n_b += 1;
            }
            let n_a = t.join().unwrap();
            assert_eq!(n_a + n_b, 2, "double-pop or loss: a={n_a} b={n_b}");
        });
    }

    /// Handler-shaped: Behaviour fills `non_priority` (cap 1) while Handler
    /// `poll_pop` drains — Accepted + remaining ≤ attempts; no overflow past cap.
    #[test]
    fn handler_queue_publish_cap_vs_handler_poll() {
        loom::model(|| {
            let q = Queue::new(1);
            let mut behaviour = q.clone();
            let mut handler = q.clone();

            let t = thread::spawn(move || {
                let mut accepted = 0usize;
                let mut rejected = 0usize;
                for tag in [1u8, 2] {
                    match behaviour.try_push(publish_msg(tag)) {
                        Ok(()) => accepted += 1,
                        Err(_) => rejected += 1,
                    }
                }
                (accepted, rejected)
            });

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);
            let mut drained = 0usize;
            for _ in 0..3 {
                if matches!(
                    Pin::new(&mut handler).poll_pop(&mut cx),
                    Poll::Ready(_)
                ) {
                    drained += 1;
                }
            }
            let (accepted, rejected) = t.join().unwrap();
            while handler.try_pop().is_some() {
                drained += 1;
            }
            assert_eq!(accepted + rejected, 2);
            assert_eq!(
                drained, accepted,
                "lost/extra Publish: drained={drained} accepted={accepted}"
            );
        });
    }

    /// Dual Handlers race `try_pop` with both priority + non_priority seeded —
    /// each lane delivers exactly once (Subscribe XOR IHAVE per message).
    #[test]
    fn handler_queue_priority_lanes_dual_pop() {
        loom::model(|| {
            let q = Queue::new(4);
            let mut seed = q.clone();
            let _ = seed.try_push(ihave_msg(1));
            let _ = seed.try_push(subscribe_msg(2));

            let mut h0 = q.clone();
            let mut h1 = q.clone();
            let t = thread::spawn(move || h0.try_pop());
            let b = h1.try_pop();
            let a = t.join().unwrap();

            let msgs: Vec<_> = [a, b].into_iter().flatten().collect();
            assert_eq!(msgs.len(), 2, "lost message under dual-handler pop");
            assert_eq!(
                msgs.iter().filter(|m| is_subscribe(m)).count(),
                1,
                "Subscribe not delivered exactly once"
            );
            assert_eq!(
                msgs.iter().filter(|m| matches!(m, RpcOut::IHave(_))).count(),
                1,
                "IHAVE not delivered exactly once"
            );
        });
    }

    /// Dual Handler clones both `poll_pop` Pending; one Behaviour push → one delivery.
    #[test]
    fn dual_handler_poll_pending_single_push() {
        loom::model(|| {
            let q = Queue::new(4);
            let mut h0 = q.clone();
            let mut h1 = q.clone();
            let mut behaviour = q.clone();

            let t0 = thread::spawn(move || {
                let waker = noop_waker_ref();
                let mut cx = Context::from_waker(waker);
                let ready = matches!(Pin::new(&mut h0).poll_pop(&mut cx), Poll::Ready(_));
                (ready, h0)
            });
            let t1 = thread::spawn(move || {
                let waker = noop_waker_ref();
                let mut cx = Context::from_waker(waker);
                let ready = matches!(Pin::new(&mut h1).poll_pop(&mut cx), Poll::Ready(_));
                (ready, h1)
            });

            let _ = behaviour.try_push(subscribe_msg(7));

            let (r0, mut h0) = t0.join().unwrap();
            let (r1, mut h1) = t1.join().unwrap();
            let mut delivered = usize::from(r0) + usize::from(r1);
            if h0.try_pop().is_some() {
                delivered += 1;
            }
            if h1.try_pop().is_some() {
                delivered += 1;
            }
            if behaviour.try_pop().is_some() {
                delivered += 1;
            }
            assert_eq!(
                delivered, 1,
                "dual-handler poll+push lost/duplicated: {delivered}"
            );
        });
    }

    /// Behaviour `remove_data_messages` races Handler pop — Publish delivered XOR removed.
    #[test]
    fn remove_data_vs_handler_pop() {
        loom::model(|| {
            let q = Queue::new(4);
            let mut behaviour = q.clone();
            let mut handler = q.clone();
            let mid = MessageId(vec![9]);
            let _ = behaviour.try_push(publish_msg(9));

            let remover = {
                let mid = MessageId(mid.0.clone());
                thread::spawn(move || behaviour.remove_data_messages(&[mid]))
            };

            let popped = handler.try_pop();
            let removed = remover.join().unwrap();
            let got_publish = popped.as_ref().is_some_and(is_publish);
            assert_eq!(
                usize::from(got_publish) + removed,
                1,
                "Publish XOR remove: popped={got_publish:?} removed={removed}"
            );
        });
    }
}
