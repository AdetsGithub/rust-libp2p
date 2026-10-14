#![no_main]

//! Fuzz target for libp2p **mplex** multiplexed I/O (`muxers/mplex/src/io.rs`).
//!
//! Unlike `mplex_frame_codec` (codec-only), this drives the full [`Multiplexed`]
//! state machine over a mock socket: inbound Open → accept, Data buffering,
//! Close/Reset, unknown-stream data drops, outbound open/write/half-close/drop,
//! and [`MaxBufferBehaviour`] ({Block, ResetStream}) under clamped buffer limits.
//!
//! Arms (via `Arbitrary`):
//!   - **Raw wire** — dict-mutated / truncated blobs (legacy lane)
//!   - **Structured sequences** — Open→Data→Close/Reset frame lists with
//!     type-correct flags, plus multi-outbound + optional write loopback
//!
//! Bias: `MaxBufferBehaviour::ResetStream` + tiny `max_buffer_len` + dual-Open
//! Data floods so the overflow `ResetStream` arm stays warm (was ~6 vs Block ~30k).
//!
//! Dict: `dicts/mplex.dict`. Seeds: `seeds/mplex_multiplexed_io/`.
//!
//! Invariants: never panics; always terminates within a bounded poll budget.

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_mplex::{encode_structured_frames, fuzz_multiplexed_io};

const MAX_FRAMES: usize = 16;
const MAX_PAYLOAD: usize = 48;

#[derive(Debug)]
struct Case {
    /// Packed like `fuzz_multiplexed_io` ctrl byte.
    ctrl: u8,
    /// Fragment size + loopback bit (see `fuzz_multiplexed_io` docs).
    chunk_ctrl: u8,
    wire: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut ctrl = u.arbitrary::<u8>()?;
        // Bias ResetStream (~¾) — bit0 = 1.
        if u.ratio(3, 4)? {
            ctrl |= 1;
        } else {
            ctrl &= !1;
        }
        // Bias tiny max_buffer_len in 1..=2 (bits2–4) so overflow is cheap.
        if u.ratio(3, 4)? {
            let tiny = u.int_in_range(0u8..=1)?; // → max_buffer_len 1..=2
            ctrl = (ctrl & !0b1_1100) | (tiny << 2);
        }
        // Prefer outbound opens when ResetStream (multi-stream buffer pressure).
        if ctrl & 1 != 0 && u.ratio(2, 3)? {
            ctrl |= 2;
        }

        // Prefer loopback on ~25% of cases (bit6 of chunk_ctrl).
        let mut chunk_ctrl = u.arbitrary::<u8>()?;
        if u.ratio(1, 4)? {
            chunk_ctrl |= 0x40;
        } else {
            chunk_ctrl &= !0x40;
        }

        let reset_bias = ctrl & 1 != 0;
        // Bias: structured sequences (flag-correct) over raw blobs.
        let wire = if u.ratio(4, 5)? {
            let n = u.int_in_range(if reset_bias { 6 } else { 1 }..=MAX_FRAMES)?;
            let mut frames = Vec::with_capacity(n + 4);
            let sid0 = u.int_in_range(0u64..=7)?;
            let sid1 = (sid0 + 1) % 8;
            // Dual Open so poll_read on A can buffer Data for B → ResetStream overflow.
            frames.push((0u8, sid0, Vec::new()));
            if reset_bias || u.ratio(1, 2)? {
                frames.push((0u8, sid1, Vec::new()));
            }
            // Guaranteed unknown-stream Data (id never Opened).
            frames.push((2u8, sid0.wrapping_add(64), vec![0x75])); // 'u'

            // Data flood on both sids before Close/Reset (fills tiny buffers).
            let flood = if reset_bias {
                u.int_in_range(4..=10)?
            } else {
                u.int_in_range(1..=4)?
            };
            for i in 0..flood {
                let id = if i % 2 == 0 { sid0 } else { sid1 };
                let plen = u.int_in_range(1..=MAX_PAYLOAD.min(16))?;
                frames.push((2u8, id, u.bytes(plen)?.to_vec()));
            }

            while frames.len() < n {
                let flag = match u.int_in_range(0u8..=5)? {
                    0 => 2, // Data dialer
                    1 => 1, // Data listener
                    2 => 4, // Close dialer
                    3 => 6, // Reset dialer
                    4 => 0, // another Open
                    _ => 2,
                };
                let id = if flag == 0 {
                    u.int_in_range(0u64..=7)?
                } else if flag == 1 || flag == 2 {
                    if u.ratio(1, 5)? {
                        u.int_in_range(8u64..=15)?
                    } else if u.ratio(1, 2)? {
                        sid0
                    } else {
                        sid1
                    }
                } else {
                    sid0
                };
                let plen = if flag == 1 || flag == 2 {
                    u.int_in_range(0..=MAX_PAYLOAD)?
                } else {
                    0
                };
                frames.push((flag, id, u.bytes(plen)?.to_vec()));
            }
            encode_structured_frames(&frames)
        } else {
            let len = u.int_in_range(0..=512)?;
            u.bytes(len)?.to_vec()
        };
        Ok(Case {
            ctrl,
            chunk_ctrl,
            wire,
        })
    }
}

fuzz_target!(|case: Case| {
    let mut buf = Vec::with_capacity(2 + case.wire.len());
    buf.push(case.ctrl);
    buf.push(case.chunk_ctrl);
    buf.extend_from_slice(&case.wire);
    fuzz_multiplexed_io(&buf);
});
