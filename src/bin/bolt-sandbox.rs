use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    thread,
    time::Duration,
};

use bolt_sandbox::{
    ChildProcessPolicy, DEFAULT_STREAM_CAPACITY, ExecutionTerminal, NetworkPolicy,
    ProcessExitReason, RecoveryLimits, RecoveryPolicy, Sandbox, SandboxConfig, SandboxEvent,
    SandboxPolicy, SandboxRequest,
};

struct RunArguments {
    component_root: PathBuf,
    cwd: PathBuf,
    timeout: Option<Duration>,
    program: PathBuf,
    arguments: Vec<OsString>,
    policy: SandboxPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliError {
    InvalidArguments,
    Sandbox,
    Stream,
}

fn main() {
    let code = match run(std::env::args_os().skip(1).collect()) {
        Ok(code) => code,
        Err(CliError::InvalidArguments) => {
            eprintln!(
                "usage: bolt-sandbox run --component-root PATH --cwd PATH [--timeout-ms N] -- PROGRAM [ARG ...]"
            );
            2
        }
        Err(CliError::Sandbox | CliError::Stream) => 125,
    };
    std::process::exit(i32::from_ne_bytes(code.to_ne_bytes()));
}

fn run(arguments: Vec<OsString>) -> Result<u32, CliError> {
    let parsed = parse_run_arguments(arguments)?;
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: parsed.component_root,
        credential_environment_variables: default_credential_names(),
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .map_err(|_| CliError::Sandbox)?;
    let environment: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    let mut handle = sandbox
        .start(SandboxRequest {
            program: parsed.program,
            arguments: parsed.arguments,
            cwd: parsed.cwd,
            environment,
            policy: parsed.policy,
            timeout: parsed.timeout,
        })
        .map_err(|_| CliError::Sandbox)?;
    let stdout = handle.take_stdout().map_err(|_| CliError::Stream)?;
    let stderr = handle.take_stderr().map_err(|_| CliError::Stream)?;
    let events = handle.take_events().map_err(|_| CliError::Stream)?;
    let stdout_thread = thread::spawn(move || copy_stream(stdout, io::stdout()));
    let stderr_thread = thread::spawn(move || copy_stream(stderr, io::stderr()));
    let event_thread = thread::spawn(move || {
        for event in events {
            write_event(&event);
        }
    });
    let result = handle.wait().map_err(|_| CliError::Sandbox)?;
    if stdout_thread.join().map_err(|_| CliError::Stream)?.is_err()
        || stderr_thread.join().map_err(|_| CliError::Stream)?.is_err()
        || event_thread.join().is_err()
    {
        return Err(CliError::Stream);
    }
    Ok(exit_code(&result.terminal))
}

#[allow(
    clippy::too_many_lines,
    reason = "the flat CLI grammar is kept in one auditable option table"
)]
fn parse_run_arguments(arguments: Vec<OsString>) -> Result<RunArguments, CliError> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("run")) {
        return Err(CliError::InvalidArguments);
    }
    let mut component_root = None;
    let mut cwd = None;
    let mut timeout = None;
    let mut policy = SandboxPolicy::default();
    let mut network_set = false;
    let mut child_processes_set = false;
    let mut recovery_directory = None;
    let mut recovery_maximum_bytes = None;
    let mut recovery_maximum_items = None;
    let mut program_and_arguments = None;
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            program_and_arguments = Some(arguments.collect::<Vec<_>>());
            break;
        }
        match argument.to_str() {
            Some("--component-root") if component_root.is_none() => {
                component_root = arguments.next().map(PathBuf::from);
            }
            Some("--cwd") if cwd.is_none() => {
                cwd = arguments.next().map(PathBuf::from);
            }
            Some("--timeout-ms") if timeout.is_none() => {
                let milliseconds = arguments
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
                    .filter(|value| *value != 0)
                    .ok_or(CliError::InvalidArguments)?;
                timeout = Some(Duration::from_millis(milliseconds));
            }
            Some("--read-write") => policy
                .filesystem
                .read_write
                .push(next_path(&mut arguments)?),
            Some("--read-only") => policy.filesystem.read_only.push(next_path(&mut arguments)?),
            Some("--deny") => policy.filesystem.deny.push(next_path(&mut arguments)?),
            Some("--metadata-read") => policy
                .filesystem
                .metadata_read
                .push(next_path(&mut arguments)?),
            Some("--inherit-user") => policy
                .filesystem
                .inherit_user
                .push(next_path(&mut arguments)?),
            Some("--registry-no-access") => {
                policy.registry.no_access.push(next_string(&mut arguments)?);
            }
            Some("--registry-read-only") => {
                policy.registry.read_only.push(next_string(&mut arguments)?);
            }
            Some("--registry-inherit-user") => policy
                .registry
                .inherit_user
                .push(next_string(&mut arguments)?),
            Some("--registry-read-write") => policy
                .registry
                .read_write
                .push(next_string(&mut arguments)?),
            Some("--network") if !network_set => {
                policy.network = match next_string(&mut arguments)?.as_str() {
                    "unrestricted" => NetworkPolicy::Unrestricted,
                    "denied" => NetworkPolicy::Denied,
                    _ => return Err(CliError::InvalidArguments),
                };
                network_set = true;
            }
            Some("--child-processes") if !child_processes_set => {
                policy.child_processes = match next_string(&mut arguments)?.as_str() {
                    "inherit" => ChildProcessPolicy::Inherit,
                    "deny" => ChildProcessPolicy::Deny,
                    _ => return Err(CliError::InvalidArguments),
                };
                child_processes_set = true;
            }
            Some("--recovery-dir") if recovery_directory.is_none() => {
                recovery_directory = Some(next_path(&mut arguments)?);
            }
            Some("--recovery-max-bytes") if recovery_maximum_bytes.is_none() => {
                recovery_maximum_bytes = Some(next_nonzero_u64(&mut arguments)?);
            }
            Some("--recovery-max-items") if recovery_maximum_items.is_none() => {
                recovery_maximum_items = Some(
                    u32::try_from(next_nonzero_u64(&mut arguments)?)
                        .map_err(|_| CliError::InvalidArguments)?,
                );
            }
            _ => return Err(CliError::InvalidArguments),
        }
    }
    let mut program_and_arguments = program_and_arguments.ok_or(CliError::InvalidArguments)?;
    if program_and_arguments.is_empty() {
        return Err(CliError::InvalidArguments);
    }
    let program = PathBuf::from(program_and_arguments.remove(0));
    match (
        recovery_directory,
        recovery_maximum_bytes,
        recovery_maximum_items,
    ) {
        (None, None, None) => {}
        (Some(directory), Some(maximum_bytes), Some(maximum_items)) => {
            policy.recovery = RecoveryPolicy::Enabled(RecoveryLimits {
                directory,
                maximum_bytes,
                maximum_items,
            });
        }
        _ => return Err(CliError::InvalidArguments),
    }
    Ok(RunArguments {
        component_root: component_root.ok_or(CliError::InvalidArguments)?,
        cwd: cwd.ok_or(CliError::InvalidArguments)?,
        timeout,
        program,
        arguments: program_and_arguments,
        policy,
    })
}

fn next_path(arguments: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, CliError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(CliError::InvalidArguments)
}

fn next_string(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, CliError> {
    arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(CliError::InvalidArguments)
}

fn next_nonzero_u64(arguments: &mut impl Iterator<Item = OsString>) -> Result<u64, CliError> {
    next_string(arguments)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(CliError::InvalidArguments)
}

fn copy_stream(stream: bolt_sandbox::ByteStream, mut output: impl Write) -> io::Result<()> {
    for bytes in stream {
        output.write_all(&bytes)?;
    }
    output.flush()
}

fn write_event(event: &SandboxEvent) {
    match event {
        SandboxEvent::Ready => eprintln!("sandbox-event ready"),
        SandboxEvent::FilesystemViolation(violation) => {
            eprintln!(
                "sandbox-event filesystem-violation pid={}",
                violation.process_id
            );
        }
        SandboxEvent::RegistryViolation(violation) => {
            eprintln!(
                "sandbox-event registry-violation pid={}",
                violation.process_id
            );
        }
        SandboxEvent::NetworkViolation(violation) => {
            eprintln!(
                "sandbox-event network-violation pid={}",
                violation.process_id
            );
        }
        SandboxEvent::EventsDropped(events) => {
            eprintln!(
                "sandbox-event dropped pid={} count={}",
                events.process_id, events.count
            );
        }
        SandboxEvent::RecoveryArtifactCreated(artifact) => {
            eprintln!("sandbox-event recovery-created pid={}", artifact.process_id);
        }
        SandboxEvent::RecoveryFailed(failure) => {
            eprintln!("sandbox-event recovery-failed pid={}", failure.process_id);
        }
        SandboxEvent::ChildInjectionFailed(failure) => {
            eprintln!(
                "sandbox-event child-injection-failed pid={}",
                failure.child_process_id
            );
        }
        SandboxEvent::ProcessViolation(violation) => {
            eprintln!(
                "sandbox-event process-violation pid={}",
                violation.process_id
            );
        }
        SandboxEvent::ProcessExited(exit) => {
            eprintln!("sandbox-event process-exited pid={}", exit.process_id);
        }
        _ => eprintln!("sandbox-event unknown"),
    }
}

fn exit_code(terminal: &ExecutionTerminal) -> u32 {
    match terminal {
        ExecutionTerminal::Process(exit) => match exit.reason {
            ProcessExitReason::Exited | ProcessExitReason::Crashed => exit.exit_code.unwrap_or(1),
            ProcessExitReason::Terminated => 130,
            ProcessExitReason::TimedOut => 124,
        },
        ExecutionTerminal::Infrastructure(_) => 125,
    }
}

fn default_credential_names() -> Vec<OsString> {
    [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf, time::Duration};

    use super::*;

    #[test]
    fn cli_001_run_parser_preserves_native_program_arguments() {
        let parsed = parse_run_arguments(vec![
            OsString::from("run"),
            OsString::from("--component-root"),
            OsString::from(r"C:\components"),
            OsString::from("--cwd"),
            OsString::from(r"C:\work"),
            OsString::from("--timeout-ms"),
            OsString::from("2500"),
            OsString::from("--"),
            OsString::from(r"C:\Program Files\tool.exe"),
            OsString::from(""),
            OsString::from("空 格"),
        ])
        .expect("valid run arguments must parse");

        assert_eq!(parsed.component_root, PathBuf::from(r"C:\components"));
        assert_eq!(parsed.cwd, PathBuf::from(r"C:\work"));
        assert_eq!(parsed.timeout, Some(Duration::from_millis(2_500)));
        assert_eq!(parsed.program, PathBuf::from(r"C:\Program Files\tool.exe"));
        assert_eq!(
            parsed.arguments,
            [OsString::from(""), OsString::from("空 格")]
        );
    }

    #[test]
    fn cli_002_parser_rejects_missing_separator_value_and_program() {
        for arguments in [
            vec![OsString::from("run")],
            vec![OsString::from("run"), OsString::from("--component-root")],
            vec![
                OsString::from("run"),
                OsString::from("--component-root"),
                OsString::from(r"C:\components"),
                OsString::from("--cwd"),
                OsString::from(r"C:\work"),
                OsString::from(r"C:\tool.exe"),
            ],
        ] {
            assert!(parse_run_arguments(arguments).is_err());
        }
    }

    #[test]
    fn cli_004_parser_builds_typed_policy_without_reimplementing_validation() {
        let parsed = parse_run_arguments(vec![
            OsString::from("run"),
            OsString::from("--component-root"),
            OsString::from(r"C:\components"),
            OsString::from("--cwd"),
            OsString::from(r"C:\work"),
            OsString::from("--read-write"),
            OsString::from(r"C:\cache"),
            OsString::from("--read-only"),
            OsString::from(r"C:\sdk"),
            OsString::from("--deny"),
            OsString::from(r"C:\secret"),
            OsString::from("--registry-read-only"),
            OsString::from(r"HKCU\SOFTWARE\Example"),
            OsString::from("--network"),
            OsString::from("denied"),
            OsString::from("--child-processes"),
            OsString::from("deny"),
            OsString::from("--recovery-dir"),
            OsString::from(r"C:\recovery"),
            OsString::from("--recovery-max-bytes"),
            OsString::from("4096"),
            OsString::from("--recovery-max-items"),
            OsString::from("8"),
            OsString::from("--"),
            OsString::from(r"C:\tool.exe"),
        ])
        .expect("typed policy arguments must parse");

        assert_eq!(
            parsed.policy.filesystem.read_write,
            [PathBuf::from(r"C:\cache")]
        );
        assert_eq!(
            parsed.policy.filesystem.read_only,
            [PathBuf::from(r"C:\sdk")]
        );
        assert_eq!(parsed.policy.filesystem.deny, [PathBuf::from(r"C:\secret")]);
        assert_eq!(
            parsed.policy.registry.read_only,
            [String::from(r"HKCU\SOFTWARE\Example")]
        );
        assert_eq!(parsed.policy.network, NetworkPolicy::Denied);
        assert_eq!(parsed.policy.child_processes, ChildProcessPolicy::Deny);
        assert_eq!(
            parsed.policy.recovery,
            RecoveryPolicy::Enabled(RecoveryLimits {
                directory: PathBuf::from(r"C:\recovery"),
                maximum_bytes: 4_096,
                maximum_items: 8,
            })
        );
    }
}
