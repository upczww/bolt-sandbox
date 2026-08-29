#[allow(
    dead_code,
    reason = "violation aggregation is wired into the public event stream in a later phase"
)]
mod aggregation;
mod event_codec;
#[allow(
    dead_code,
    reason = "private protocol encoder is wired into the launcher IPC transport in the next phase"
)]
mod framing;
mod handshake;
#[allow(
    dead_code,
    reason = "execution identity is connected to secure named-pipe creation later"
)]
mod identity;
#[allow(
    dead_code,
    reason = "session protocol is wired into the launcher IPC transport in the next phase"
)]
mod session;
