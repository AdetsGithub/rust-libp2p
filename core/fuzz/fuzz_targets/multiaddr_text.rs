#![no_main]

//! Text-format multiaddr parser (`FromStr`) with structured label edge cases.
//!
//! Two input modes via `Arbitrary`:
//! - raw UTF-8-ish strings (classic `/ip4/...` corpus path)
//! - assembled `/proto/label/...` chains that deliberately stress Dns*/Unix
//!   labels (empty, `/`, `%`, control chars) without relying on Display→parse.

use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use libp2p_core::multiaddr::Multiaddr;

#[path = "common.rs"]
mod common;

const MAX_LABEL: usize = 48;
const MAX_COMPONENTS: usize = 6;

#[derive(Debug)]
enum TextInput {
    Raw(String),
    Labels {
        /// Protocol name tokens (without leading slash), e.g. `"dns4"`, `"unix"`.
        parts: Vec<(String, Option<String>)>,
    },
}

impl<'a> Arbitrary<'a> for TextInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 2)? {
            let s = String::arbitrary(u)?;
            // Cap to keep tokenizer work bounded.
            let s = if s.len() > 256 {
                s.chars().take(256).collect()
            } else {
                s
            };
            return Ok(TextInput::Raw(s));
        }

        let n = u.int_in_range(0..=MAX_COMPONENTS)?;
        let protos = [
            "ip4", "ip6", "tcp", "udp", "dns", "dns4", "dns6", "dnsaddr", "unix", "p2p", "quic-v1",
            "tls", "ws", "http", "https", "onion3", "certhash", "p2p-circuit",
        ];
        let mut parts = Vec::with_capacity(n);
        for _ in 0..n {
            let name = (*u.choose(&protos)?).to_string();
            let value = if matches!(
                name.as_str(),
                "dns" | "dns4" | "dns6" | "dnsaddr" | "unix" | "ip6zone" | "sni" | "http-path"
            ) {
                Some(edge_label(u)?)
            } else if matches!(name.as_str(), "ip4" | "tcp" | "udp" | "ip6" | "p2p" | "onion3" | "certhash")
            {
                // Prefer plausible values so we reach value parsers, not only UnknownProtocol.
                Some(plausible_value(&name, u)?)
            } else {
                // Flag-ish protocols: optional junk value to stress tokenizer.
                if u.ratio(1, 4)? {
                    Some(edge_label(u)?)
                } else {
                    None
                }
            };
            parts.push((name, value));
        }
        Ok(TextInput::Labels { parts })
    }
}

fn edge_label(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let kind = u.int_in_range(0..=6)?;
    Ok(match kind {
        0 => String::new(),
        1 => "/".into(),
        2 => "//".into(),
        3 => "%".into(),
        4 => "%2f".into(),
        5 => "\t\n\r".into(),
        _ => {
            let n = u.int_in_range(0..=MAX_LABEL)?;
            let bytes = u.bytes(n)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
    })
}

fn plausible_value(proto: &str, u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    Ok(match proto {
        "ip4" => {
            let b: [u8; 4] = Arbitrary::arbitrary(u)?;
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        "tcp" | "udp" => u.int_in_range(0u16..=65535)?.to_string(),
        "ip6" => "::1".into(),
        "p2p" => "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC".into(),
        "onion3" => "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234".into(),
        "certhash" => "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g".into(),
        _ => edge_label(u)?,
    })
}

fn assemble(parts: &[(String, Option<String>)]) -> String {
    let mut s = String::new();
    for (name, value) in parts {
        s.push('/');
        s.push_str(name);
        if let Some(v) = value {
            s.push('/');
            s.push_str(v);
        }
    }
    s
}

fuzz_target!(|input: TextInput| {
    let text = match &input {
        TextInput::Raw(s) => s.clone(),
        TextInput::Labels { parts } => assemble(parts),
    };

    if let Ok(addr) = text.parse::<Multiaddr>() {
        common::assert_binary_roundtrip(&addr);
        common::exercise_text_roundtrip(&addr);
    }
});
