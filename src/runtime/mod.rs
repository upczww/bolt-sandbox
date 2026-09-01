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
pub(crate) mod projected_workspace;
mod projected_workspace_protocol;
mod recovery;
mod recovery_protocol;
#[cfg(test)]
mod startup;
#[cfg(test)]
mod streams;
pub(crate) mod workspace;
pub(crate) mod workspace_security;
mod workspace_security_protocol;

use crate::{
    CommandId, ExecutionAttribution, ExecutionHandle, ExecutionId, InitializationStage,
    PolicyGeneration, SandboxConfig, SandboxError, SandboxRequest, TerminalMode,
};

pub(crate) fn start_execution(
    request: SandboxRequest,
    config: &SandboxConfig,
    command_id: CommandId,
    policy_generation: PolicyGeneration,
    terminal: TerminalMode,
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
        preparation::LaunchPreparationError::PolicyPayload
        | preparation::LaunchPreparationError::CompatibilityProfile => {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Policy,
            }
        }
        preparation::LaunchPreparationError::ExecutionIdentity => {
            SandboxError::InitializationFailed {
                stage: InitializationStage::Identity,
            }
        }
        preparation::LaunchPreparationError::Workspace => SandboxError::InitializationFailed {
            stage: InitializationStage::Workspace,
        },
    })?;
    let execution_id = ExecutionId::new(*prepared.ipc_endpoint_identifier()).ok_or(
        SandboxError::InitializationFailed {
            stage: InitializationStage::Identity,
        },
    )?;
    let attribution = ExecutionAttribution {
        execution_id,
        command_id,
        policy_generation,
    };
    drop(request);
    launcher_adapter::start(
        prepared,
        config.stream_capacity,
        config.violation_aggregate_capacity,
        attribution,
        terminal,
    )
}
