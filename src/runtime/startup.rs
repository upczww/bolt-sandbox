#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_001_startup_actions_enforce_suspended_job_injection_ready_resume_order() {
        let mut startup = StartupCoordinator::new();

        assert_eq!(startup.begin(), Ok(StartupAction::CreateSuspended));
        assert_eq!(startup.target_created(), Ok(StartupAction::AssignJob));
        assert_eq!(startup.job_assigned(), Ok(StartupAction::InjectHook));
        assert_eq!(startup.hook_injected(), Ok(StartupAction::AwaitReady));
        assert_eq!(startup.ready_verified(), Ok(StartupAction::ResumeTarget));
        assert_eq!(startup.target_resumed(), Ok(StartupAction::Started));
        assert_eq!(startup.state(), StartupState::Running);
    }

    #[test]
    fn ipc_012_resume_before_verified_ready_is_rejected_without_state_change() {
        let mut startup = StartupCoordinator::new();
        startup.begin().expect("begin must succeed");
        startup.target_created().expect("create must succeed");
        startup.job_assigned().expect("job must succeed");
        startup.hook_injected().expect("inject must succeed");

        assert_eq!(
            startup.target_resumed(),
            Err(StartupError::InvalidTransition {
                state: StartupState::AwaitingReady,
                operation: StartupOperation::TargetResumed,
            })
        );
        assert_eq!(startup.state(), StartupState::AwaitingReady);
    }

    #[test]
    fn proc_014_failure_after_target_creation_requests_exactly_one_job_termination() {
        for failure_state in [
            StartupState::AssigningJob,
            StartupState::InjectingHook,
            StartupState::AwaitingReady,
            StartupState::Resuming,
        ] {
            let mut startup = StartupCoordinator::new();
            startup.begin().expect("begin must succeed");
            startup.target_created().expect("create must succeed");
            if failure_state >= StartupState::InjectingHook {
                startup.job_assigned().expect("job must succeed");
            }
            if failure_state >= StartupState::AwaitingReady {
                startup.hook_injected().expect("inject must succeed");
            }
            if failure_state >= StartupState::Resuming {
                startup.ready_verified().expect("ready must succeed");
            }
            assert_eq!(startup.state(), failure_state);

            assert_eq!(startup.fail(), Ok(StartupAction::TerminateJob));
            assert_eq!(startup.fail(), Ok(StartupAction::None));
            assert_eq!(startup.termination_complete(), Ok(StartupAction::Failed));
            assert_eq!(startup.state(), StartupState::Failed);
        }
    }

    #[test]
    fn proc_001_failure_before_process_creation_aborts_without_job_action() {
        let mut startup = StartupCoordinator::new();
        startup.begin().expect("begin must succeed");

        assert_eq!(startup.fail(), Ok(StartupAction::Failed));
        assert_eq!(startup.state(), StartupState::Failed);
    }

    #[test]
    fn life_007_running_startup_cannot_be_reclassified_as_initialization_failure() {
        let mut startup = StartupCoordinator::new();
        startup.begin().expect("begin must succeed");
        startup.target_created().expect("create must succeed");
        startup.job_assigned().expect("job must succeed");
        startup.hook_injected().expect("inject must succeed");
        startup.ready_verified().expect("ready must succeed");
        startup.target_resumed().expect("resume must succeed");

        assert_eq!(
            startup.fail(),
            Err(StartupError::InvalidTransition {
                state: StartupState::Running,
                operation: StartupOperation::Fail,
            })
        );
    }
}
