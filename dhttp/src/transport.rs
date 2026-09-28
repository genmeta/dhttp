//! Native QUIC and TCP stream adapters for h3x.
#[cfg(not(feature = "tcp-mock"))]
mod quic;
#[cfg(feature = "tcp-mock")]
pub(crate) mod tcp;
#[cfg(not(feature = "tcp-mock"))]
pub(crate) use quic::QuicTransport;
