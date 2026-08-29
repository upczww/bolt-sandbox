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
            Ok(SandboxEvent::Ready)
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
            Ok(SandboxEvent::ProcessExited(_))
        ));

        assert_eq!(
            channel.disconnect(&mut lifecycle),
            Ok(EventChannelEof::Clean)
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
    }
}
