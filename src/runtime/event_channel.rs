use crate::{
    SandboxEvent,
    ipc::session::{SessionProtocol, SessionState},
};

use super::lifecycle::{
    InfrastructureFailure, LifecycleAction, LifecycleController, LifecycleError, LifecyclePhase,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum EventChannelError {
    InitializationProtocol,
    InitializationChannelLost,
    PostReadyFailure {
        failure: InfrastructureFailure,
        action: LifecycleAction,
    },
    Lifecycle(LifecycleError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EventChannelEof {
    Clean,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RoutedEvent {
    pub(super) event: SandboxEvent,
    pub(super) lifecycle_action: LifecycleAction,
}

pub(super) struct EventChannelDriver {
    session: SessionProtocol,
}

impl EventChannelDriver {
    pub(super) fn new(expected_nonce: [u8; 16]) -> Self {
        Self {
            session: SessionProtocol::new(expected_nonce),
        }
    }

    pub(super) fn accept(
        &mut self,
        encoded: &[u8],
        lifecycle: &mut LifecycleController,
    ) -> Result<RoutedEvent, EventChannelError> {
        let event = self.session.accept(encoded).map_err(|_| {
            if lifecycle.phase() == LifecyclePhase::Starting {
                EventChannelError::InitializationProtocol
            } else {
                post_ready_failure(lifecycle, InfrastructureFailure::ProtocolIntegrity)
            }
        })?;
        let lifecycle_action = match &event {
            SandboxEvent::ProcessExited(exit) => {
                if lifecycle.phase() == LifecyclePhase::Starting {
                    return Err(EventChannelError::InitializationProtocol);
                }
                lifecycle
                    .mark_terminal_event(exit.clone())
                    .map_err(EventChannelError::Lifecycle)?
            }
            SandboxEvent::Ready
            | SandboxEvent::EventsDropped(_)
            | SandboxEvent::FilesystemViolation(_)
            | SandboxEvent::RegistryViolation(_)
            | SandboxEvent::NetworkViolation(_)
            | SandboxEvent::RecoveryArtifactCreated(_)
            | SandboxEvent::RecoveryFailed(_)
            | SandboxEvent::ChildInjectionFailed(_)
            | SandboxEvent::ProcessViolation(_) => LifecycleAction::None,
        };
        Ok(RoutedEvent {
            event,
            lifecycle_action,
        })
    }

    pub(super) fn disconnect(
        &mut self,
        lifecycle: &mut LifecycleController,
    ) -> Result<EventChannelEof, EventChannelError> {
        if self.session.state() == SessionState::Exited {
            return Ok(EventChannelEof::Clean);
        }
        if lifecycle.phase() == LifecyclePhase::Starting {
            return Err(EventChannelError::InitializationChannelLost);
        }
        Err(post_ready_failure(
            lifecycle,
            InfrastructureFailure::EventChannelLost,
        ))
    }
}

fn post_ready_failure(
    lifecycle: &mut LifecycleController,
    failure: InfrastructureFailure,
) -> EventChannelError {
    match lifecycle.mark_infrastructure_failure(failure) {
        Ok(action) => EventChannelError::PostReadyFailure { failure, action },
        Err(error) => EventChannelError::Lifecycle(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProcessExit, ProcessExitReason, SandboxEvent,
        ipc::event_codec,
        runtime::lifecycle::{
            InfrastructureFailure, LifecycleAction, LifecycleController, LifecyclePhase,
            TerminationCause,
        },
    };

    const NONCE: [u8; 16] = [0x5A; 16];

    fn ready() -> Vec<u8> {
        event_codec::encode_ready(NONCE, 0).expect("Ready frame must encode")
    }

    fn process_exit() -> Vec<u8> {
        event_codec::encode_event(
            &SandboxEvent::ProcessExited(ProcessExit {
                process_id: 42,
                exit_code: Some(0),
                reason: ProcessExitReason::Exited,
            }),
            1,
        )
        .expect("exit frame must encode")
    }

    #[test]
    fn ipc_007_pre_ready_protocol_failure_remains_initialization_failure() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();

        assert_eq!(
            channel.accept(&[0; 4], &mut lifecycle),
            Err(EventChannelError::InitializationProtocol)
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Starting);
    }

    #[test]
    fn ipc_025_post_ready_bad_frame_requests_job_termination() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();
        assert_eq!(
            channel.accept(&ready(), &mut lifecycle),
            Ok(RoutedEvent {
                event: SandboxEvent::Ready,
                lifecycle_action: LifecycleAction::None,
            })
        );
        lifecycle.start().expect("execution must enter running");
        let mut corrupted = process_exit();
        *corrupted.last_mut().expect("frame has payload") ^= 0x80;

        assert_eq!(
            channel.accept(&corrupted, &mut lifecycle),
            Err(EventChannelError::PostReadyFailure {
                failure: InfrastructureFailure::ProtocolIntegrity,
                action: LifecycleAction::TerminateJob(TerminationCause::Infrastructure(
                    InfrastructureFailure::ProtocolIntegrity,
                )),
            })
        );
    }

    #[test]
    fn ipc_014_post_ready_disconnect_requests_job_termination() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();
        channel
            .accept(&ready(), &mut lifecycle)
            .expect("Ready must authenticate");
        lifecycle.start().expect("execution must enter running");

        assert_eq!(
            channel.disconnect(&mut lifecycle),
            Err(EventChannelError::PostReadyFailure {
                failure: InfrastructureFailure::EventChannelLost,
                action: LifecycleAction::TerminateJob(TerminationCause::Infrastructure(
                    InfrastructureFailure::EventChannelLost,
                )),
            })
        );
    }

    #[test]
    fn ipc_012_pre_ready_disconnect_does_not_issue_runtime_job_action() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();

        assert_eq!(
            channel.disconnect(&mut lifecycle),
            Err(EventChannelError::InitializationChannelLost)
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Starting);
    }

    #[test]
    fn life_010_disconnect_after_terminal_event_is_clean_eof() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();
        channel
            .accept(&ready(), &mut lifecycle)
            .expect("Ready must authenticate");
        lifecycle.start().expect("execution must enter running");
        assert!(matches!(
            channel.accept(&process_exit(), &mut lifecycle),
            Ok(RoutedEvent {
                event: SandboxEvent::ProcessExited(_),
                lifecycle_action: LifecycleAction::BeginDrain,
            })
        ));

        assert_eq!(
            channel.disconnect(&mut lifecycle),
            Ok(EventChannelEof::Clean)
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Draining(TerminationCause::Exited)
        );
    }

    #[test]
    fn life_010_process_exit_frame_atomically_routes_begin_drain() {
        let mut channel = EventChannelDriver::new(NONCE);
        let mut lifecycle = LifecycleController::new();
        channel
            .accept(&ready(), &mut lifecycle)
            .expect("Ready must authenticate");
        lifecycle.start().expect("execution must enter running");
        let exit = ProcessExit {
            process_id: 42,
            exit_code: Some(0),
            reason: ProcessExitReason::Exited,
        };

        assert_eq!(
            channel.accept(&process_exit(), &mut lifecycle),
            Ok(RoutedEvent {
                event: SandboxEvent::ProcessExited(exit),
                lifecycle_action: LifecycleAction::BeginDrain,
            })
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Draining(TerminationCause::Exited)
        );
    }
}
