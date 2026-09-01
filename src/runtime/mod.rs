#[allow(
    dead_code,
    reason = "image architecture selection is connected to launcher component selection later"
)]
mod architecture;
mod component_manifest;
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
mod launcher_adapter;
#[allow(
    dead_code,
    reason = "launcher stdio protocol is connected to the native adapter next"
)]
mod launcher_protocol;
#[allow(
    dead_code,
    reason = "multiplexed launcher frames are connected after the native transport lands"
)]
mod launcher_transport;
mod lifecycle;
#[allow(
    dead_code,
    reason = "launch preparation is connected to the native launcher adapter later"
)]
mod preparation;
#[allow(
    dead_code,
    reason = "process observation is connected to the public execution handle later"
)]
mod process_observer;
mod recovery;
mod recovery_protocol;
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

use crate::{ExecutionHandle, InitializationStage, SandboxConfig, SandboxError, SandboxRequest};

pub(crate) fn start_execution(
    request: SandboxRequest,
    config: &SandboxConfig,
) -> Result<ExecutionHandle, SandboxError> {
    let prepared = preparation::prepare_launch_with_security_denies(
        &request,
        &config.credential_environment_variables,
        &config.component_root,
        &config.mandatory_filesystem_denies,
        &config.mandatory_registry_denies,
        config.component_manifest_sha256.as_ref(),
    )
    .map_err(|error| match error {
        preparation::LaunchPreparationError::Request(error) => error,
        preparation::LaunchPreparationError::ProgramOpen
        | preparation::LaunchPreparationError::InvalidProgramImage
        | preparation::LaunchPreparationError::UnsupportedArchitecture { .. } => {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Program,
            }
        }
        preparation::LaunchPreparationError::Component(_) => SandboxError::InitializationFailed {
            stage: InitializationStage::Components,
        },
        preparation::LaunchPreparationError::PolicyPayload => SandboxError::InitializationFailed {
            stage: InitializationStage::Policy,
        },
        preparation::LaunchPreparationError::ExecutionIdentity => {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            }
        }
    })?;
    drop(request);
    launcher_adapter::start(
        prepared,
        config.stream_capacity,
        config.violation_aggregate_capacity,
    )
}
