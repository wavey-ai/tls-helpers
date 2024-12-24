# tls-helpers

A Rust library that simplifies working with TLS certificates and keys in base64 format. This library provides convenient utilities for creating TLS acceptors and connectors from base64-encoded certificates and private keys.

## Features

- Load certificates and private keys from base64-encoded strings
- Create TLS connectors with custom CA certificates
- Create TLS acceptors with support for HTTP/1.x and HTTP/2
- Built on top of `rustls` for robust TLS implementation
- Zero-copy certificate handling where possible
- ALPN protocol negotiation support

## Usage

### Loading Certificates and Keys

```rust
use tls_helpers::{certs_from_base64, privkey_from_base64};

// Load certificates from base64
let certs = certs_from_base64(&cert_base64_string)?;

// Load private key from base64
let private_key = privkey_from_base64(&key_base64_string)?;
```

### Creating a TLS Connector (Client)

```rust
use tls_helpers::tls_connector_from_base64;

// Create a TLS connector with custom CA certificate
let connector = tls_connector_from_base64(&ca_cert_base64)?;

// Use the connector with a TLS connection
let stream = connector.connect("example.com", tcp_stream).await?;
```

### Creating a TLS Acceptor (Server)

```rust
use tls_helpers::tls_acceptor_from_base64;

// Create a TLS acceptor with HTTP/1.1 and HTTP/2 support
let acceptor = tls_acceptor_from_base64(
    &cert_base64,
    &key_base64,
    true,  // Enable HTTP/1.x
    true   // Enable HTTP/2
)?;

// Use the acceptor with incoming connections
let tls_stream = acceptor.accept(tcp_stream).await?;
```

### Raw Base64 Decoding

```rust
use tls_helpers::from_base64_raw;

// Decode raw base64 data
let raw_bytes = from_base64_raw(&base64_string)?;
```

## Error Handling

The library uses standard Rust error handling patterns:

- Functions return `io::Result<T>` for basic operations
- More complex operations return `Result<T, Box<dyn std::error::Error>>` or `Result<T, Box<dyn std::error::Error + Send + Sync>>`
- Detailed error messages are provided for common failure cases

## Security Notes

- The library uses `rustls` instead of OpenSSL for improved memory safety
- Private keys are expected to be in PKCS8 format
- Supports modern TLS versions through `rustls`
- No support for legacy or insecure protocols
- Memory containing private keys is zeroed when dropped

## Performance

- Zero-copy operations where possible
- Efficient base64 decoding using the `base64` crate
- Single-allocation certificate chain building
- Shared configurations through `Arc` for multiple connections

## Examples

### Complete Server Setup

```rust
use tls_helpers::tls_acceptor_from_base64;
use tokio::net::TcpListener;

async fn run_server(cert_base64: &str, key_base64: &str) -> Result<(), Box<dyn std::error::Error>> {
    let acceptor = tls_acceptor_from_base64(cert_base64, key_base64, true, true)?;
    let listener = TcpListener::bind("0.0.0.0:443").await?;

    while let Ok((stream, _)) = listener.accept().await {
        let tls_stream = acceptor.accept(stream).await?;
        // Handle the TLS stream...
    }
    Ok(())
}
```

### Complete Client Setup

```rust
use tls_helpers::tls_connector_from_base64;
use tokio::net::TcpStream;

async fn connect_client(ca_cert_base64: &str) -> Result<(), Box<dyn std::error::Error>> {
    let connector = tls_connector_from_base64(ca_cert_base64)?;
    let tcp_stream = TcpStream::connect("example.com:443").await?;
    let tls_stream = connector.connect("example.com", tcp_stream).await?;
    // Use the TLS stream...
    Ok(())
}
```

## License

MIT
