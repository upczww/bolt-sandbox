#[allow(
    dead_code,
    reason = "image architecture selection is connected to launcher component selection later"
)]
mod architecture;
#[cfg(test)]
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
