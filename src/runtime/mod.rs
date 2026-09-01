#[allow(
    dead_code,
    reason = "path wrapper is retained for architecture parser contract tests"
)]
mod architecture;
mod component_manifest;
#[allow(
    dead_code,
    reason = "opened component handles are intentionally retained as execution identity leases"
)]
mod components;
#[cfg(test)]
mod event_channel;
mod launcher_adapter;
#[allow(
    dead_code,
    reason = "Rust decoder is retained for native launcher protocol parity and fuzz tests"
)]
mod launcher_protocol;
mod launcher_transport;
mod lifecycle;
#[allow(
    dead_code,
    reason = "prepared target and component handles are intentionally retained through execution"
)]
mod preparation;
#[cfg(test)]
mod process_observer;
mod recovery;
mod recovery_protocol;
#[cfg(test)]
mod startup;
#[cfg(test)]
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
