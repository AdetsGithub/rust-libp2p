// Copyright 2021 Parity Technologies (UK) Ltd.
// Copyright 2022 Protocol Labs.
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

//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod certificate;
mod upgrade;
mod verifier;

#[cfg(feature = "fuzzing")]
mod fuzz;
#[cfg(feature = "fuzzing")]
pub use fuzz::fuzz_tls;

use std::sync::Arc;

use certificate::AlwaysResolvesCert;
pub use futures_rustls::TlsStream;
use libp2p_identity::{Keypair, PeerId};
pub use upgrade::{Config, UpgradeError};

const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Create a TLS client configuration for libp2p.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;
    make_client_config_with_material(keypair, certificate, &private_key, remote_peer_id)
}

/// Create a TLS client configuration from pre-generated cert material.
///
/// Exposed under `fuzzing` so transport harnesses (e.g. QUIC) can inject
/// corrupted DER.
#[cfg(feature = "fuzzing")]
pub fn make_client_config_with_material(
    keypair: &Keypair,
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    make_client_config_with_material_impl(keypair, certificate, private_key, remote_peer_id)
}

#[cfg(not(feature = "fuzzing"))]
pub(crate) fn make_client_config_with_material(
    keypair: &Keypair,
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    make_client_config_with_material_impl(keypair, certificate, private_key, remote_peer_id)
}

fn make_client_config_with_material_impl(
    _keypair: &Keypair,
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, private_key)
            .map_err(|_| rcgen::Error::RingUnspecified)?,
    );

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_client_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];
    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(crypto)
}

/// Create a TLS server configuration for libp2p.
pub fn make_server_config(
    keypair: &Keypair,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;
    make_server_config_with_material(certificate, &private_key)
}

/// Create a TLS server configuration from pre-generated cert material.
#[cfg(feature = "fuzzing")]
pub fn make_server_config_with_material(
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    make_server_config_with_material_impl(certificate, private_key)
}

#[cfg(not(feature = "fuzzing"))]
pub(crate) fn make_server_config_with_material(
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    make_server_config_with_material_impl(certificate, private_key)
}

fn make_server_config_with_material_impl(
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, private_key)
            .map_err(|_| rcgen::Error::RingUnspecified)?,
    );

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];
    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(crypto)
}

#[cfg(test)]
mod tests {
    use rustls::NamedGroup;

    use super::*;

    #[test]
    fn prefers_x25519_mlkem768() {
        let keypair = Keypair::generate_ed25519();
        let config = make_client_config(&keypair, None).unwrap();

        assert_eq!(
            config.crypto_provider().kx_groups[0].name(),
            NamedGroup::X25519MLKEM768
        );
    }
}
