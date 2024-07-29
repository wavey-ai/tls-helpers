use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::{self, Cursor};
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub fn certs_from_base64(cert_base64: &str) -> io::Result<Vec<Certificate>> {
    let cert_bytes = base64_engine
        .decode(cert_base64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut cursor = Cursor::new(cert_bytes);
    certs(&mut cursor)
        .map(|result| result.map(|der| Certificate(der.to_vec())))
        .collect()
}

// New function to get rustls::PrivateKey from base64 string
pub fn privkey_from_base64(privkey_base64: &str) -> io::Result<PrivateKey> {
    let key_bytes = base64_engine
        .decode(privkey_base64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut cursor = Cursor::new(key_bytes);
    let keys = pkcs8_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to read private keys"))?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No private key found"))?;
    Ok(PrivateKey(key.secret_pkcs8_der().to_vec()))
}

pub fn tls_connector_from_base64(
    ca_cert_base64: &str,
) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();
    let certs = load_certs_from_base64(ca_cert_base64)?;
    for cert in certs {
        root_store.add(cert)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

pub fn tls_acceptor_from_base64(
    cert_base64: &str,
    privkey_base64: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs_from_base64(cert_base64)?;
    let key = load_keys_from_base64(privkey_base64)?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    Ok(tls_acceptor)
}

fn load_certs_from_base64(cert_base64: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_bytes = base64_engine
        .decode(cert_base64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut cursor = Cursor::new(cert_bytes);
    certs(&mut cursor).collect()
}

fn load_keys_from_base64(privkey_base64: &str) -> io::Result<PrivateKeyDer<'static>> {
    let key_bytes = base64_engine
        .decode(privkey_base64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut cursor = Cursor::new(key_bytes);

    let keys = pkcs8_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>() // This collects results and returns Result<Vec<T>, E>
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to read private keys"))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No private key found"))?;

    Ok(PrivateKeyDer::from(key))
}
