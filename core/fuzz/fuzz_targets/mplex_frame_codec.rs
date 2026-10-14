#![no_main]

//! Fuzz target for the libp2p **mplex** frame-header decoder
//! (`libp2p-mplex`'s home-grown `Codec`, in `muxers/mplex/src/codec.rs`).
//!
//! Arms (via `Arbitrary`):
//!   - **Raw** — arbitrary bytes (truncation / garbage twin of structured)
//!   - **Structured** — `(flag∈0..=7, stream_id, payload)` sequences encoded
//!     to wire, optionally fed in chunks so Begin/HasHeader/HasHeaderAndLen
//!     sees fragmented varints
//!
//! Invariants: decode never panics; decode→encode→decode HARD.
//!
//! Dict: `dicts/mplex.dict`. Twin of `mplex_multiplexed_io` (codec-only).

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_mplex::{encode_structured_frames, fuzz_frame_codec, fuzz_frame_codec_chunked};

const MAX_FRAMES: usize = 16;
const MAX_PAYLOAD: usize = 64;

#[derive(Debug)]
enum Case {
    Raw {
        data: Vec<u8>,
        chunk: usize,
    },
    Structured {
        frames: Vec<(u8, u64, Vec<u8>)>,
        chunk: usize,
    },
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bias toward structured (type-correct flags) but keep a raw lane.
        Ok(match u.int_in_range(0u8..=3)? {
            0 => {
                let len = u.int_in_range(0..=512)?;
                let data = u.bytes(len)?.to_vec();
                let chunk = 1 + usize::from(u.arbitrary::<u8>()?) % 16;
                Case::Raw { data, chunk }
            }
            _ => {
                let n = u.int_in_range(1..=MAX_FRAMES)?;
                let mut frames = Vec::with_capacity(n);
                for _ in 0..n {
                    let flag = u.int_in_range(0u8..=7)?; // 7 = invalid-header path
                    let stream_id = u.int_in_range(0u64..=32)?;
                    let plen = if flag == 1 || flag == 2 {
                        u.int_in_range(0..=MAX_PAYLOAD)?
                    } else {
                        // Open/Close/Reset: empty body (still has len varint = 0).
                        0
                    };
                    let payload = u.bytes(plen)?.to_vec();
                    frames.push((flag, stream_id, payload));
                }
                let chunk = 1 + usize::from(u.arbitrary::<u8>()?) % 16;
                Case::Structured { frames, chunk }
            }
        })
    }
}

fuzz_target!(|case: Case| {
    match case {
        Case::Raw { data, chunk } => {
            if chunk >= data.len() {
                fuzz_frame_codec(&data);
            } else {
                fuzz_frame_codec_chunked(&data, chunk);
            }
        }
        Case::Structured { frames, chunk } => {
            let wire = encode_structured_frames(&frames);
            if chunk >= wire.len() {
                fuzz_frame_codec(&wire);
            } else {
                fuzz_frame_codec_chunked(&wire, chunk);
            }
        }
    }
});
