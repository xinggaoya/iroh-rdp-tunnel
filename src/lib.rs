//! Shared constants for the iroh-rdp-tunnel server / client.

// ALPN identifier negotiated in the QUIC handshake; both sides must match exactly.
pub const ALPN: &[u8] = b"iroh-rdp-tunnel/0";

// Windows built-in RDP service (loopback) by default.
pub const RDP_LOCAL: &str = "127.0.0.1:3389";

// Build tag — printed by both binaries on startup so users can tell at a
// glance whether they are running an old or new binary.
pub const BUILD_TAG: &str = "v0.1.3-ipv4-only-switch";

