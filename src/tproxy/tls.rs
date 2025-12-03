use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use rustls::{
    ServerConfig,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

#[derive(Debug, Clone)]
pub struct TlsMitmState {
    issuer: Arc<Issuer<'static, KeyPair>>,
    ca_chain: Arc<Vec<CertificateDer<'static>>>,
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    crypto: Arc<CryptoProvider>,
}

impl TlsMitmState {
    pub fn from_ca_pem<P1: AsRef<Path>, P2: AsRef<Path>>(
        ca_cert_path: P1,
        ca_key_path: P2,
    ) -> std::io::Result<Self> {
        let ca_key_pem = fs::read_to_string(ca_key_path)?;
        let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(|e| std::io::Error::other(e))?;

        let ca_cert_pem = fs::read_to_string(ca_cert_path)?;
        let issuer =
            Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key).map_err(|e| std::io::Error::other(e))?;

        let mut reader = BufReader::new(ca_cert_pem.as_bytes());
        let mut ca_chain = Vec::new();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert: CertificateDer<'static> = cert?.into_owned();
            ca_chain.push(cert);
        }

        if ca_chain.is_empty() {
            return Err(std::io::Error::other("no CA certificates found"));
        }

        Ok(Self {
            issuer: Arc::new(issuer),
            ca_chain: Arc::new(ca_chain),
            cache: Arc::new(DashMap::new()),
            crypto: Arc::new(aws_lc_rs::default_provider()),
        })
    }

    fn get_or_create_for_host(&self, host: &str) -> std::io::Result<Arc<CertifiedKey>> {
        if let Some(entry) = self.cache.get(host) {
            return Ok(entry.clone());
        }

        let ck = self.make_leaf_cert(host)?;
        let ck = Arc::new(ck);
        self.cache.insert(host.to_owned(), ck.clone());
        Ok(ck)
    }

    fn make_leaf_cert(&self, host: &str) -> std::io::Result<CertifiedKey> {
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|e| std::io::Error::other(e))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::NoCa;
        params.subject_alt_names.push(SanType::DnsName(
            host.to_owned()
                .try_into()
                .map_err(|e| std::io::Error::other(e))?,
        ));

        use rcgen::{ExtendedKeyUsagePurpose as EKU, KeyUsagePurpose as KU};
        params.key_usages = vec![KU::KeyEncipherment, KU::DigitalSignature];
        params.extended_key_usages.push(EKU::ServerAuth);

        let leaf_key = KeyPair::generate().map_err(|e| std::io::Error::other(e))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| std::io::Error::other(e))?;

        let mut chain: Vec<CertificateDer<'static>> = Vec::with_capacity(1 + self.ca_chain.len());
        chain.push(leaf_cert.der().clone());
        chain.extend(self.ca_chain.iter().cloned());

        let leaf_key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let ck = CertifiedKey::from_der(chain, leaf_key_der, &self.crypto)
            .map_err(|e| std::io::Error::other(e))?;

        Ok(ck)
    }
}

impl ResolvesServerCert for TlsMitmState {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        self.get_or_create_for_host(server_name).ok()
    }

    fn only_raw_public_keys(&self) -> bool {
        false
    }
}

pub(crate) fn make_server_config(state: TlsMitmState) -> ServerConfig {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(state));

    config.alpn_protocols.push(b"http/1.1".to_vec());

    config
}
