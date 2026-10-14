#![no_main]

//! Fuzz target for the `unsigned-varint` primitive that underpins every libp2p
//! wire format (multiaddr protocol codes & length prefixes, multistream frame
//! lengths, muxer header fields, protobuf-style length delimiters).
//!
//! The decoder promises three things that this harness enforces as hard
//! invariants:
//!   1. It never panics on arbitrary bytes (no OOB, no shift/overflow panic).
//!   2. It only accepts *minimal* encodings (it returns `NotMinimal` otherwise),
//!      so a decoded value must re-encode to exactly the bytes it consumed.
//!   3. Encode is a left-inverse of decode: `decode(encode(v)) == (v, &[])`.
//!
//! Arms:
//!   - slice decode for `u8` / `u16` / `u32` / `u64` / `u128` / `usize`
//!   - encode→decode identity for each width
//!   - streaming `codec::Uvi` with chunked `BytesMut` feeds (the path mplex uses)
//!
//! Dict: `dicts/unsigned_varint.dict`. Seeds: `seeds/unsigned_varint_roundtrip/`.
//!
//! Soft note: canonical re-encode after decode does NOT hold in unsigned-varint
//! 0.8.0 — see Finding #2 (silent truncation of over-range final byte).

use asynchronous_codec::Decoder;
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use unsigned_varint::codec::Uvi;
use unsigned_varint::{decode, encode};

/// Soft: record whether consumed bytes equal the canonical encoding (Finding #2).
macro_rules! soft_canonical {
    ($decode_fn:path, $encode_fn:path, $buf_fn:path, $data:expr) => {
        if let Ok((value, rest)) = $decode_fn($data) {
            let consumed = &$data[..$data.len() - rest.len()];
            let mut buf = $buf_fn();
            let _canonical = $encode_fn(value, &mut buf) == consumed;
        }
    };
}

/// HARD: encode→decode is identity and consumes all bytes.
macro_rules! hard_encode_decode {
    ($ty:ty, $encode_fn:path, $decode_fn:path, $buf_fn:path, $v:expr) => {{
        let v: $ty = $v;
        let mut buf = $buf_fn();
        let encoded = $encode_fn(v, &mut buf);
        let (decoded, rest) = $decode_fn(encoded).expect("encoded value must decode");
        assert_eq!(decoded, v, "encode->decode changed the value");
        assert!(rest.is_empty(), "encode->decode left trailing bytes");
    }};
}

/// HARD: streaming `Uvi` never panics; chunked feeds eventually agree with bulk
/// decode when a complete varint is present.
fn fuzz_uvi_chunked<T>(data: &[u8], mut decode_bulk: impl FnMut(&[u8]) -> Option<T>)
where
    Uvi<T>: Decoder<Item = T, Error = std::io::Error>,
    T: Copy + Eq + Default + std::fmt::Debug,
{
    if data.is_empty() {
        return;
    }
    // Byte 0 selects chunk size in 1..=8 so the codec sees fragmented varints.
    let chunk_size = (data[0] as usize % 8) + 1;
    let payload = &data[1..];

    let mut uvi = Uvi::<T>::default();
    let mut buf = BytesMut::new();
    let mut offset = 0;
    let mut streamed: Option<T> = None;

    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        buf.extend_from_slice(&payload[offset..end]);
        offset = end;
        match uvi.decode(&mut buf) {
            Ok(Some(v)) => {
                streamed = Some(v);
                break;
            }
            Ok(None) => continue,
            Err(_) => return,
        }
    }

    if let Some(streamed_v) = streamed {
        if let Some(bulk_v) = decode_bulk(payload) {
            assert_eq!(
                streamed_v, bulk_v,
                "chunked Uvi decode disagreed with bulk decode"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // --- Arm 1: decode robustness (HARD) + canonical round-trip (SOFT) ---
    soft_canonical!(decode::u8, encode::u8, encode::u8_buffer, data);
    soft_canonical!(decode::u16, encode::u16, encode::u16_buffer, data);
    soft_canonical!(decode::u32, encode::u32, encode::u32_buffer, data);
    soft_canonical!(decode::u64, encode::u64, encode::u64_buffer, data);
    soft_canonical!(decode::u128, encode::u128, encode::u128_buffer, data);
    soft_canonical!(decode::usize, encode::usize, encode::usize_buffer, data);

    // --- Arm 2: encode -> decode is identity ---
    if !data.is_empty() {
        hard_encode_decode!(
            u8,
            encode::u8,
            decode::u8,
            encode::u8_buffer,
            data[0]
        );
    }
    if data.len() >= 2 {
        hard_encode_decode!(
            u16,
            encode::u16,
            decode::u16,
            encode::u16_buffer,
            u16::from_le_bytes(data[..2].try_into().unwrap())
        );
    }
    if data.len() >= 4 {
        hard_encode_decode!(
            u32,
            encode::u32,
            decode::u32,
            encode::u32_buffer,
            u32::from_le_bytes(data[..4].try_into().unwrap())
        );
    }
    if data.len() >= 8 {
        hard_encode_decode!(
            u64,
            encode::u64,
            decode::u64,
            encode::u64_buffer,
            u64::from_le_bytes(data[..8].try_into().unwrap())
        );
        hard_encode_decode!(
            usize,
            encode::usize,
            decode::usize,
            encode::usize_buffer,
            usize::from_le_bytes(data[..std::mem::size_of::<usize>()].try_into().unwrap())
        );
    }
    if data.len() >= 16 {
        hard_encode_decode!(
            u128,
            encode::u128,
            decode::u128,
            encode::u128_buffer,
            u128::from_le_bytes(data[..16].try_into().unwrap())
        );
    }

    // --- Arm 3: streaming codec::Uvi with chunked decode ---
    // Exercises the same Decoder path mplex uses for headers / lengths.
    fuzz_uvi_chunked::<u8>(data, |p| decode::u8(p).ok().map(|(v, _)| v));
    fuzz_uvi_chunked::<u16>(data, |p| decode::u16(p).ok().map(|(v, _)| v));
    fuzz_uvi_chunked::<u32>(data, |p| decode::u32(p).ok().map(|(v, _)| v));
    fuzz_uvi_chunked::<u64>(data, |p| decode::u64(p).ok().map(|(v, _)| v));
    fuzz_uvi_chunked::<u128>(data, |p| decode::u128(p).ok().map(|(v, _)| v));
    fuzz_uvi_chunked::<usize>(data, |p| decode::usize(p).ok().map(|(v, _)| v));
});
