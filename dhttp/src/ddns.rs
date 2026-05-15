//! DNS resolution schemes and genmeta infrastructure constants.
//!
//! The DnsScheme enum selects between mDNS local discovery,
//! H3-based DNS lookup, and system resolver. All three can
//! coexist in the same endpoint via `Resolvers`.

pub use ddns::*;

/// DNS resolution backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsScheme {
    /// Multicast DNS for LAN service discovery.
    Mdns,
    /// DNS over HTTP/3 using genmeta's DNS server.
    H3,
    /// System resolver (e.g., /etc/resolv.conf).
    System,
}

/// Default DNS-over-H3 server.
pub const DNS_SERVER: &str = "https://dns.genmeta.net:4433";

/// mDNS service type used by genmeta endpoints.
pub const MDNS_SERVICE: &str = "_genmeta.local";
