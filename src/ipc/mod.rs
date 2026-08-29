mod event_codec;
mod framing;
mod handshake;
#[allow(
    dead_code,
    reason = "session protocol is wired into the launcher IPC transport in the next phase"
)]
mod session;
