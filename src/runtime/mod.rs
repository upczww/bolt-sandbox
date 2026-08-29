#[allow(
    dead_code,
    reason = "image architecture selection is connected to launcher component selection later"
)]
mod architecture;
#[allow(
    dead_code,
    reason = "opened native components are connected to the launcher adapter later"
)]
mod components;
#[allow(
    dead_code,
    reason = "event channel driver is connected to the Windows named-pipe reader later"
)]
mod event_channel;
#[allow(
    dead_code,
    reason = "runtime lifecycle is connected to Windows process and Job Object adapters later"
)]
mod lifecycle;
#[allow(
    dead_code,
    reason = "launch preparation is connected to the native launcher adapter later"
)]
mod preparation;
#[allow(
    dead_code,
    reason = "startup orchestration is connected to the native launcher adapter later"
)]
mod startup;
#[allow(
    dead_code,
    reason = "bounded stream buffers are connected to Windows pipe readers later"
)]
mod streams;
