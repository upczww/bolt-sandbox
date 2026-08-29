use std::time::{Duration, Instant};

use crate::ProcessExit;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminationCause {
    Exited,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecyclePhase {
    Starting,
    Running,
    Terminating(TerminationCause),
    Draining(TerminationCause),
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LifecycleAction {
    None,
    Launch,
    TerminateJob(TerminationCause),
    BeginDrain,
    Completed(ProcessExit),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleOperation {
    Start,
    ObserveTriggers,
    MarkJobTerminated,
    MarkStreamEof,
    MarkTerminalEvent,
    MarkEventEof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleError {
    InvalidTransition {
        phase: LifecyclePhase,
        operation: LifecycleOperation,
    },
    MissingTerminalEvent,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TriggerSet {
    pub(super) cancelled: bool,
    pub(super) timed_out: bool,
    pub(super) process_exited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamKind {
    Stdout,
    Stderr,
}

pub(super) struct LifecycleController {
    phase: LifecyclePhase,
    stdout_eof: bool,
    stderr_eof: bool,
    event_eof: bool,
    terminal_event: Option<ProcessExit>,
}

impl LifecycleController {
    pub(super) const fn new() -> Self {
        Self {
            phase: LifecyclePhase::Starting,
            stdout_eof: false,
            stderr_eof: false,
            event_eof: false,
            terminal_event: None,
        }
    }

    pub(super) const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    pub(super) fn start(&mut self) -> Result<LifecycleAction, LifecycleError> {
        if self.phase != LifecyclePhase::Starting {
            return Err(self.invalid_transition(LifecycleOperation::Start));
        }
        self.phase = LifecyclePhase::Running;
        Ok(LifecycleAction::Launch)
    }

    pub(super) fn observe_triggers(
        &mut self,
        triggers: TriggerSet,
    ) -> Result<LifecycleAction, LifecycleError> {
        match self.phase {
            LifecyclePhase::Starting => {
                Err(self.invalid_transition(LifecycleOperation::ObserveTriggers))
            }
            LifecyclePhase::Running => {
                if triggers.cancelled {
                    self.phase = LifecyclePhase::Terminating(TerminationCause::Cancelled);
                    Ok(LifecycleAction::TerminateJob(TerminationCause::Cancelled))
                } else if triggers.timed_out {
                    self.phase = LifecyclePhase::Terminating(TerminationCause::TimedOut);
                    Ok(LifecycleAction::TerminateJob(TerminationCause::TimedOut))
                } else if triggers.process_exited {
                    self.phase = LifecyclePhase::Draining(TerminationCause::Exited);
                    Ok(LifecycleAction::BeginDrain)
                } else {
                    Ok(LifecycleAction::None)
                }
            }
            LifecyclePhase::Terminating(_)
            | LifecyclePhase::Draining(_)
            | LifecyclePhase::Completed => Ok(LifecycleAction::None),
        }
    }

    pub(super) fn mark_job_terminated(&mut self) -> Result<LifecycleAction, LifecycleError> {
        match self.phase {
            LifecyclePhase::Terminating(cause) => {
                self.phase = LifecyclePhase::Draining(cause);
                Ok(LifecycleAction::BeginDrain)
            }
            LifecyclePhase::Draining(_) | LifecyclePhase::Completed => Ok(LifecycleAction::None),
            LifecyclePhase::Starting | LifecyclePhase::Running => {
                Err(self.invalid_transition(LifecycleOperation::MarkJobTerminated))
            }
        }
    }

    pub(super) fn mark_stream_eof(
        &mut self,
        stream: StreamKind,
    ) -> Result<LifecycleAction, LifecycleError> {
        match self.phase {
            LifecyclePhase::Starting => {
                return Err(self.invalid_transition(LifecycleOperation::MarkStreamEof));
            }
            LifecyclePhase::Completed => return Ok(LifecycleAction::None),
            LifecyclePhase::Running
            | LifecyclePhase::Terminating(_)
            | LifecyclePhase::Draining(_) => {}
        }
        match stream {
            StreamKind::Stdout => self.stdout_eof = true,
            StreamKind::Stderr => self.stderr_eof = true,
        }
        Ok(self.complete_if_drained())
    }

    pub(super) fn mark_terminal_event(
        &mut self,
        event: ProcessExit,
    ) -> Result<LifecycleAction, LifecycleError> {
        if !matches!(self.phase, LifecyclePhase::Draining(_)) || self.terminal_event.is_some() {
            return Err(self.invalid_transition(LifecycleOperation::MarkTerminalEvent));
        }
        self.terminal_event = Some(event);
        Ok(self.complete_if_drained())
    }

    pub(super) fn mark_event_eof(&mut self) -> Result<LifecycleAction, LifecycleError> {
        if !matches!(self.phase, LifecyclePhase::Draining(_)) {
            return Err(self.invalid_transition(LifecycleOperation::MarkEventEof));
        }
        if self.terminal_event.is_none() {
            return Err(LifecycleError::MissingTerminalEvent);
        }
        self.event_eof = true;
        Ok(self.complete_if_drained())
    }

    fn complete_if_drained(&mut self) -> LifecycleAction {
        if !matches!(self.phase, LifecyclePhase::Draining(_))
            || !self.stdout_eof
            || !self.stderr_eof
            || !self.event_eof
        {
            return LifecycleAction::None;
        }
        let Some(exit) = self.terminal_event.clone() else {
            return LifecycleAction::None;
        };
        self.phase = LifecyclePhase::Completed;
        LifecycleAction::Completed(exit)
    }

    const fn invalid_transition(&self, operation: LifecycleOperation) -> LifecycleError {
        LifecycleError::InvalidTransition {
            phase: self.phase,
            operation,
        }
    }
}

pub(super) struct MonotonicDeadline {
    instant: Instant,
}

impl MonotonicDeadline {
    pub(super) fn new(start: Instant, timeout: Duration) -> Option<Self> {
        start.checked_add(timeout).map(|instant| Self { instant })
    }

    pub(super) fn has_expired(&self, now: Instant) -> bool {
        now >= self.instant
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{ProcessExit, ProcessExitReason};

    fn exit_event(reason: ProcessExitReason) -> ProcessExit {
        ProcessExit {
            process_id: 42,
            exit_code: (reason == ProcessExitReason::Exited).then_some(0),
            reason,
        }
    }

    #[test]
    fn life_001_start_is_committed_exactly_once() {
        let mut lifecycle = LifecycleController::new();

        assert_eq!(lifecycle.start(), Ok(LifecycleAction::Launch));
        assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
        assert_eq!(
            lifecycle.start(),
            Err(LifecycleError::InvalidTransition {
                phase: LifecyclePhase::Running,
                operation: LifecycleOperation::Start,
            })
        );
    }

    #[test]
    fn life_014_exact_tick_tie_prefers_cancellation_then_timeout_then_exit() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");

        assert_eq!(
            lifecycle.observe_triggers(TriggerSet {
                cancelled: true,
                timed_out: true,
                process_exited: true,
            }),
            Ok(LifecycleAction::TerminateJob(TerminationCause::Cancelled))
        );
        assert_eq!(
            lifecycle.observe_triggers(TriggerSet {
                cancelled: false,
                timed_out: true,
                process_exited: true,
            }),
            Ok(LifecycleAction::None)
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Terminating(TerminationCause::Cancelled)
        );
    }

    #[test]
    fn life_003_timeout_requests_one_job_tree_termination_and_then_drains() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");

        assert_eq!(
            lifecycle.observe_triggers(TriggerSet {
                timed_out: true,
                ..TriggerSet::default()
            }),
            Ok(LifecycleAction::TerminateJob(TerminationCause::TimedOut))
        );
        assert_eq!(
            lifecycle.mark_job_terminated(),
            Ok(LifecycleAction::BeginDrain)
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Draining(TerminationCause::TimedOut)
        );
    }

    #[test]
    fn life_010_completion_waits_for_both_streams_and_terminal_event_eof() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");
        assert_eq!(
            lifecycle.observe_triggers(TriggerSet {
                process_exited: true,
                ..TriggerSet::default()
            }),
            Ok(LifecycleAction::BeginDrain)
        );

        assert_eq!(
            lifecycle.mark_stream_eof(StreamKind::Stdout),
            Ok(LifecycleAction::None)
        );
        assert_eq!(
            lifecycle.mark_terminal_event(exit_event(ProcessExitReason::Exited)),
            Ok(LifecycleAction::None)
        );
        assert_eq!(lifecycle.mark_event_eof(), Ok(LifecycleAction::None));
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Draining(TerminationCause::Exited)
        );
        assert_eq!(
            lifecycle.mark_stream_eof(StreamKind::Stderr),
            Ok(LifecycleAction::Completed(exit_event(
                ProcessExitReason::Exited
            )))
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Completed);
    }

    #[test]
    fn life_010_event_eof_without_process_exit_fails_closed() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");
        lifecycle
            .observe_triggers(TriggerSet {
                process_exited: true,
                ..TriggerSet::default()
            })
            .expect("exit must begin draining");

        assert_eq!(
            lifecycle.mark_event_eof(),
            Err(LifecycleError::MissingTerminalEvent)
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Draining(TerminationCause::Exited)
        );
    }

    #[test]
    fn life_015_deadline_uses_inclusive_monotonic_instant_boundary() {
        let start = Instant::now();
        let deadline = MonotonicDeadline::new(start, Duration::from_millis(50))
            .expect("representable deadline");

        assert!(!deadline.has_expired(start + Duration::from_millis(49)));
        assert!(deadline.has_expired(start + Duration::from_millis(50)));
        assert!(deadline.has_expired(start + Duration::from_secs(1)));
    }
}
