//! Shared constants for the iroh-rdp-tunnel server / client.

// ALPN identifier negotiated in the QUIC handshake; both sides must match exactly.
pub const ALPN: &[u8] = b"iroh-rdp-tunnel/0";

// Windows built-in RDP service (loopback) by default.
pub const RDP_LOCAL: &str = "127.0.0.1:3389";
