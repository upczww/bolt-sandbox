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
