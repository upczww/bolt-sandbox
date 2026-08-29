#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum StartupState {
    Prepared,
    CreatingSuspended,
    AssigningJob,
    InjectingHook,
    AwaitingReady,
    Resuming,
    Running,
    Terminating,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartupAction {
    None,
    CreateSuspended,
    AssignJob,
    InjectHook,
    AwaitReady,
    ResumeTarget,
    Started,
    TerminateJob,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartupOperation {
    Begin,
    TargetCreated,
    JobAssigned,
    HookInjected,
    ReadyVerified,
    TargetResumed,
    Fail,
    TerminationComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartupError {
    InvalidTransition {
        state: StartupState,
        operation: StartupOperation,
    },
}

pub(super) struct StartupCoordinator {
    state: StartupState,
}

impl StartupCoordinator {
    pub(super) const fn new() -> Self {
        Self {
            state: StartupState::Prepared,
        }
    }

    pub(super) const fn state(&self) -> StartupState {
        self.state
    }

    pub(super) fn begin(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::Prepared,
            StartupState::CreatingSuspended,
            StartupOperation::Begin,
            StartupAction::CreateSuspended,
        )
    }

    pub(super) fn target_created(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::CreatingSuspended,
            StartupState::AssigningJob,
            StartupOperation::TargetCreated,
            StartupAction::AssignJob,
        )
    }

    pub(super) fn job_assigned(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::AssigningJob,
            StartupState::InjectingHook,
            StartupOperation::JobAssigned,
            StartupAction::InjectHook,
        )
    }

    pub(super) fn hook_injected(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::InjectingHook,
            StartupState::AwaitingReady,
            StartupOperation::HookInjected,
            StartupAction::AwaitReady,
        )
    }

    pub(super) fn ready_verified(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::AwaitingReady,
            StartupState::Resuming,
            StartupOperation::ReadyVerified,
            StartupAction::ResumeTarget,
        )
    }

    pub(super) fn target_resumed(&mut self) -> Result<StartupAction, StartupError> {
        self.advance(
            StartupState::Resuming,
            StartupState::Running,
            StartupOperation::TargetResumed,
            StartupAction::Started,
        )
    }

    pub(super) fn fail(&mut self) -> Result<StartupAction, StartupError> {
        match self.state {
            StartupState::Prepared | StartupState::CreatingSuspended => {
                self.state = StartupState::Failed;
                Ok(StartupAction::Failed)
            }
            StartupState::AssigningJob
            | StartupState::InjectingHook
            | StartupState::AwaitingReady
            | StartupState::Resuming => {
                self.state = StartupState::Terminating;
                Ok(StartupAction::TerminateJob)
            }
            StartupState::Terminating | StartupState::Failed => Ok(StartupAction::None),
            StartupState::Running => Err(self.invalid_transition(StartupOperation::Fail)),
        }
    }

    pub(super) fn termination_complete(&mut self) -> Result<StartupAction, StartupError> {
        match self.state {
            StartupState::Terminating => {
                self.state = StartupState::Failed;
                Ok(StartupAction::Failed)
            }
            StartupState::Failed => Ok(StartupAction::None),
            StartupState::Prepared
            | StartupState::CreatingSuspended
            | StartupState::AssigningJob
            | StartupState::InjectingHook
            | StartupState::AwaitingReady
            | StartupState::Resuming
            | StartupState::Running => {
                Err(self.invalid_transition(StartupOperation::TerminationComplete))
            }
        }
    }

    fn advance(
        &mut self,
        expected: StartupState,
        next: StartupState,
        operation: StartupOperation,
        action: StartupAction,
    ) -> Result<StartupAction, StartupError> {
        if self.state != expected {
            return Err(self.invalid_transition(operation));
        }
        self.state = next;
        Ok(action)
    }

    const fn invalid_transition(&self, operation: StartupOperation) -> StartupError {
        StartupError::InvalidTransition {
            state: self.state,
            operation,
        }
    }
}

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
