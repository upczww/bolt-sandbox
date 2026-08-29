use std::time::{Duration, Instant};

use crate::{ProcessExit, ProcessExitReason};

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
    Completed(ExecutionOutcome),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ReceiverLoss {
    pub(super) stdout: bool,
    pub(super) stderr: bool,
    pub(super) events: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExecutionOutcome {
    pub(super) exit: ProcessExit,
    pub(super) receiver_loss: ReceiverLoss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleOperation {
    Start,
    ObserveTriggers,
    MarkJobTerminated,
    MarkStreamEof,
    MarkTerminalEvent,
    MarkEventEof,
    MarkReceiverLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleError {
    InvalidTransition {
        phase: LifecyclePhase,
        operation: LifecycleOperation,
    },
    MissingTerminalEvent,
    TerminalReasonMismatch {
        cause: TerminationCause,
        actual: ProcessExitReason,
    },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReceiverKind {
    Stdout,
    Stderr,
    Events,
}

pub(super) struct LifecycleController {
    phase: LifecyclePhase,
    stdout_eof: bool,
    stderr_eof: bool,
    event_eof: bool,
    terminal_event: Option<ProcessExit>,
    receiver_loss: ReceiverLoss,
}

impl LifecycleController {
    pub(super) const fn new() -> Self {
        Self {
            phase: LifecyclePhase::Starting,
            stdout_eof: false,
            stderr_eof: false,
            event_eof: false,
            terminal_event: None,
            receiver_loss: ReceiverLoss {
                stdout: false,
                stderr: false,
                events: false,
            },
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
        let LifecyclePhase::Draining(cause) = self.phase else {
            return Err(self.invalid_transition(LifecycleOperation::MarkTerminalEvent));
        };
        if self.terminal_event.is_some() {
            return Err(self.invalid_transition(LifecycleOperation::MarkTerminalEvent));
        }
        if !terminal_reason_matches(cause, event.reason) {
            return Err(LifecycleError::TerminalReasonMismatch {
                cause,
                actual: event.reason,
            });
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

    pub(super) fn mark_receiver_lost(
        &mut self,
        receiver: ReceiverKind,
    ) -> Result<(), LifecycleError> {
        if self.phase == LifecyclePhase::Completed {
            return Err(self.invalid_transition(LifecycleOperation::MarkReceiverLost));
        }
        match receiver {
            ReceiverKind::Stdout => self.receiver_loss.stdout = true,
            ReceiverKind::Stderr => self.receiver_loss.stderr = true,
            ReceiverKind::Events => self.receiver_loss.events = true,
        }
        Ok(())
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
        LifecycleAction::Completed(ExecutionOutcome {
            exit,
            receiver_loss: self.receiver_loss,
        })
    }

    const fn invalid_transition(&self, operation: LifecycleOperation) -> LifecycleError {
        LifecycleError::InvalidTransition {
            phase: self.phase,
            operation,
        }
    }
}

const fn terminal_reason_matches(cause: TerminationCause, reason: ProcessExitReason) -> bool {
    match cause {
        TerminationCause::Exited => matches!(
            reason,
            ProcessExitReason::Exited | ProcessExitReason::Terminated | ProcessExitReason::Crashed
        ),
        TerminationCause::Cancelled => matches!(reason, ProcessExitReason::Terminated),
        TerminationCause::TimedOut => matches!(reason, ProcessExitReason::TimedOut),
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
            Ok(LifecycleAction::Completed(ExecutionOutcome {
                exit: exit_event(ProcessExitReason::Exited),
                receiver_loss: ReceiverLoss::default(),
            }))
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

    #[test]
    fn life_014_terminal_event_must_match_the_committed_timeout_cause() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");
        lifecycle
            .observe_triggers(TriggerSet {
                timed_out: true,
                ..TriggerSet::default()
            })
            .expect("timeout must commit");
        lifecycle
            .mark_job_terminated()
            .expect("termination must begin draining");

        assert_eq!(
            lifecycle.mark_terminal_event(exit_event(ProcessExitReason::Exited)),
            Err(LifecycleError::TerminalReasonMismatch {
                cause: TerminationCause::TimedOut,
                actual: ProcessExitReason::Exited,
            })
        );
        assert_eq!(
            lifecycle.mark_terminal_event(exit_event(ProcessExitReason::TimedOut)),
            Ok(LifecycleAction::None)
        );
    }

    #[test]
    fn life_005_cancelled_execution_requires_terminated_terminal_reason() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");
        lifecycle
            .observe_triggers(TriggerSet {
                cancelled: true,
                ..TriggerSet::default()
            })
            .expect("cancellation must commit");
        lifecycle
            .mark_job_terminated()
            .expect("termination must begin draining");

        assert_eq!(
            lifecycle.mark_terminal_event(exit_event(ProcessExitReason::TimedOut)),
            Err(LifecycleError::TerminalReasonMismatch {
                cause: TerminationCause::Cancelled,
                actual: ProcessExitReason::TimedOut,
            })
        );
        assert_eq!(
            lifecycle.mark_terminal_event(exit_event(ProcessExitReason::Terminated)),
            Ok(LifecycleAction::None)
        );
    }

    #[test]
    fn life_016_completion_flags_each_lost_receiver_without_cancelling() {
        let mut lifecycle = LifecycleController::new();
        lifecycle.start().expect("start must succeed");

        lifecycle
            .mark_receiver_lost(ReceiverKind::Stdout)
            .expect("stdout receiver loss must be recorded");
        lifecycle
            .mark_receiver_lost(ReceiverKind::Events)
            .expect("event receiver loss must be recorded");
        lifecycle
            .mark_receiver_lost(ReceiverKind::Stdout)
            .expect("duplicate receiver loss must be idempotent");
        assert_eq!(lifecycle.phase(), LifecyclePhase::Running);

        assert_eq!(
            lifecycle.observe_triggers(TriggerSet {
                process_exited: true,
                ..TriggerSet::default()
            }),
            Ok(LifecycleAction::BeginDrain)
        );
        lifecycle
            .mark_stream_eof(StreamKind::Stdout)
            .expect("stdout EOF must drain");
        lifecycle
            .mark_stream_eof(StreamKind::Stderr)
            .expect("stderr EOF must drain");
        lifecycle
            .mark_terminal_event(exit_event(ProcessExitReason::Exited))
            .expect("terminal event must drain");

        assert_eq!(
            lifecycle.mark_event_eof(),
            Ok(LifecycleAction::Completed(ExecutionOutcome {
                exit: exit_event(ProcessExitReason::Exited),
                receiver_loss: ReceiverLoss {
                    stdout: true,
                    stderr: false,
                    events: true,
                },
            }))
        );
    }
}
