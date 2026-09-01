pub(crate) mod aggregation;
pub(crate) mod event_codec;
#[allow(
    dead_code,
    reason = "private protocol encoder is wired into the launcher IPC transport in the next phase"
)]
pub(crate) mod framing;
mod handshake;
#[allow(
    dead_code,
    reason = "execution identity is connected to secure named-pipe creation later"
)]
pub(crate) mod identity;
#[allow(
    dead_code,
    reason = "session protocol is wired into the launcher IPC transport in the next phase"
)]
pub(crate) mod session;
