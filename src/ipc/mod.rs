pub(crate) mod aggregation;
pub(crate) mod event_codec;
#[allow(
    dead_code,
    reason = "checksum mutation helper is compiled for protocol integrity tests"
)]
pub(crate) mod framing;
mod handshake;
#[allow(
    dead_code,
    reason = "opaque endpoint identity remains reserved for the restricted pipe transport"
)]
pub(crate) mod identity;
#[allow(
    dead_code,
    reason = "session state accessor is used by protocol state-machine tests"
)]
pub(crate) mod session;
