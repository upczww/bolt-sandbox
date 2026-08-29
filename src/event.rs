#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SandboxEvent {
    Ready,
    ProcessExited(ProcessExit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExit {
    pub process_id: u32,
    pub exit_code: Option<u32>,
    pub reason: ProcessExitReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExitReason {
    Exited,
    Terminated,
    TimedOut,
    Crashed,
}
