use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

use bolt_sandbox::{ExecutionTerminal, Sandbox, SandboxConfig, SandboxPolicy, SandboxRequest};

const USAGE: &str = "usage: bolt-sandbox-benchmark --component-root <absolute-directory> --warmup <count> --samples <count> --filesystem-iterations <count>";
const MAX_SAMPLES: usize = 100;
const MAX_FILESYSTEM_ITERATIONS: usize = 100_000;

#[derive(Clone, Debug)]
struct Options {
    component_root: PathBuf,
    warmup: usize,
    samples: usize,
    filesystem_iterations: usize,
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|value| value == "--noop-fixture")
    {
        return ExitCode::SUCCESS;
    }
    if arguments
        .first()
        .is_some_and(|value| value == "--filesystem-fixture")
    {
        return run_filesystem_fixture(&arguments[1..]);
    }

    let Some(options) = parse_options(&arguments) else {
        eprintln!("{USAGE}");
        if !arguments.is_empty() {
            eprintln!("invalid benchmark arguments");
        }
        return ExitCode::from(2);
    };
    if let Ok(evidence) = run_benchmark(&options) {
        println!("{evidence}");
        ExitCode::SUCCESS
    } else {
        eprintln!("benchmark failed");
        ExitCode::FAILURE
    }
}

fn parse_options(arguments: &[OsString]) -> Option<Options> {
    if arguments.len() != 8 {
        return None;
    }
    let mut component_root = None;
    let mut warmup = None;
    let mut samples = None;
    let mut filesystem_iterations = None;
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].to_str()?;
        match name {
            "--component-root" if component_root.is_none() => {
                component_root = Some(PathBuf::from(&pair[1]));
            }
            "--warmup" if warmup.is_none() => warmup = pair[1].to_str()?.parse().ok(),
            "--samples" if samples.is_none() => samples = pair[1].to_str()?.parse().ok(),
            "--filesystem-iterations" if filesystem_iterations.is_none() => {
                filesystem_iterations = pair[1].to_str()?.parse().ok();
            }
            _ => return None,
        }
    }
    let options = Options {
        component_root: component_root?,
        warmup: warmup?,
        samples: samples?,
        filesystem_iterations: filesystem_iterations?,
    };
    if !options.component_root.is_absolute()
        || !(1..=10).contains(&options.warmup)
        || !(1..=MAX_SAMPLES).contains(&options.samples)
        || !(1..=MAX_FILESYSTEM_ITERATIONS).contains(&options.filesystem_iterations)
    {
        return None;
    }
    Some(options)
}

fn run_benchmark(options: &Options) -> Result<String, ()> {
    let executable = std::env::current_exe().map_err(|_| ())?;
    let root = std::env::temp_dir().join(format!(
        "bolt-sandbox-benchmark-{}-{}",
        std::process::id(),
        monotonic_nonce()
    ));
    fs::create_dir(&root).map_err(|_| ())?;
    let result = benchmark_in_root(options, &executable, &root);
    let cleanup = fs::remove_dir_all(&root);
    result.and_then(|evidence| cleanup.map(|()| evidence).map_err(|_| ()))
}

fn benchmark_in_root(options: &Options, executable: &Path, root: &Path) -> Result<String, ()> {
    let sandbox = Sandbox::new(SandboxConfig {
        component_root: options.component_root.clone(),
        credential_environment_variables: Vec::new(),
        stream_capacity: 1_048_576,
        mandatory_filesystem_denies: Vec::new(),
        mandatory_registry_denies: Vec::new(),
        component_manifest_sha256: None,
    })
    .map_err(|_| ())?;

    for index in 0..options.warmup {
        run_sandbox(
            &sandbox,
            executable,
            root,
            &[OsString::from("--noop-fixture")],
        )?;
        let direct_root = root.join(format!("warm-direct-{index}"));
        let sandbox_root = root.join(format!("warm-sandbox-{index}"));
        let _ = run_direct_filesystem(executable, &direct_root, options.filesystem_iterations)?;
        let _ = run_sandbox_filesystem(
            &sandbox,
            executable,
            root,
            &sandbox_root,
            options.filesystem_iterations,
        )?;
    }

    let mut startup = Vec::with_capacity(options.samples);
    let mut control = Vec::with_capacity(options.samples);
    let mut sandboxed = Vec::with_capacity(options.samples);
    for index in 0..options.samples {
        let started = Instant::now();
        run_sandbox(
            &sandbox,
            executable,
            root,
            &[OsString::from("--noop-fixture")],
        )?;
        startup.push(started.elapsed().as_secs_f64() * 1_000.0);

        let direct_root = root.join(format!("direct-{index}"));
        let sandbox_root = root.join(format!("sandbox-{index}"));
        control.push(run_direct_filesystem(
            executable,
            &direct_root,
            options.filesystem_iterations,
        )?);
        sandboxed.push(run_sandbox_filesystem(
            &sandbox,
            executable,
            root,
            &sandbox_root,
            options.filesystem_iterations,
        )?);
    }

    Ok(format!(
        "{{\"schemaVersion\":1,\"warmupSamples\":{},\"startupMilliseconds\":{},\"filesystemControlMilliseconds\":{},\"filesystemSandboxMilliseconds\":{}}}",
        options.warmup,
        json_numbers(&startup),
        json_numbers(&control),
        json_numbers(&sandboxed)
    ))
}

fn run_direct_filesystem(executable: &Path, root: &Path, iterations: usize) -> Result<f64, ()> {
    let output = Command::new(executable)
        .args([
            OsString::from("--filesystem-fixture"),
            root.as_os_str().to_os_string(),
            OsString::from(iterations.to_string()),
        ])
        .output()
        .map_err(|_| ())?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(());
    }
    parse_nanoseconds(&output.stdout)
}

fn run_sandbox_filesystem(
    sandbox: &Sandbox,
    executable: &Path,
    cwd: &Path,
    workload_root: &Path,
    iterations: usize,
) -> Result<f64, ()> {
    let stdout = run_sandbox(
        sandbox,
        executable,
        cwd,
        &[
            OsString::from("--filesystem-fixture"),
            workload_root.as_os_str().to_os_string(),
            OsString::from(iterations.to_string()),
        ],
    )?;
    parse_nanoseconds(&stdout)
}

fn run_sandbox(
    sandbox: &Sandbox,
    executable: &Path,
    cwd: &Path,
    arguments: &[OsString],
) -> Result<Vec<u8>, ()> {
    let request = SandboxRequest {
        program: executable.to_path_buf(),
        arguments: arguments.to_vec(),
        cwd: cwd.to_path_buf(),
        environment: BTreeMap::new(),
        policy: SandboxPolicy::default(),
        timeout: Some(Duration::from_secs(30)),
    };
    let mut handle = sandbox.start(request).map_err(|_| ())?;
    let stdout = handle.take_stdout().map_err(|_| ())?;
    let stderr = handle.take_stderr().map_err(|_| ())?;
    let events = handle.take_events().map_err(|_| ())?;
    let (stdout, stderr, result) = std::thread::scope(|scope| {
        let stdout_reader = scope.spawn(|| stdout.flatten().collect::<Vec<_>>());
        let stderr_reader = scope.spawn(|| stderr.flatten().collect::<Vec<_>>());
        let event_reader = scope.spawn(|| events.count());
        let result = handle.wait();
        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();
        let _ = event_reader.join();
        (stdout, stderr, result)
    });
    if !stderr.is_empty()
        || !matches!(
            result.map_err(|_| ())?.terminal,
            ExecutionTerminal::Process(ref exit) if exit.exit_code == Some(0)
        )
    {
        return Err(());
    }
    Ok(stdout)
}

fn run_filesystem_fixture(arguments: &[OsString]) -> ExitCode {
    if arguments.len() != 2 {
        return ExitCode::from(2);
    }
    let root = PathBuf::from(&arguments[0]);
    let Some(iterations) = arguments[1]
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=MAX_FILESYSTEM_ITERATIONS).contains(value))
    else {
        return ExitCode::from(2);
    };
    if !root.is_absolute() || fs::create_dir(&root).is_err() {
        return ExitCode::FAILURE;
    }
    let result = filesystem_workload(&root, iterations);
    let cleanup = fs::remove_dir(&root);
    match (result, cleanup) {
        (Ok(elapsed), Ok(())) => {
            println!("{}", elapsed.as_nanos());
            ExitCode::SUCCESS
        }
        _ => ExitCode::FAILURE,
    }
}

fn filesystem_workload(root: &Path, iterations: usize) -> Result<Duration, ()> {
    let payload = [0x5a_u8; 4_096];
    let started = Instant::now();
    for index in 0..iterations {
        let source = root.join(format!("source-{index:08x}.bin"));
        let renamed = root.join(format!("renamed-{index:08x}.bin"));
        fs::write(&source, payload).map_err(|_| ())?;
        let metadata = fs::metadata(&source).map_err(|_| ())?;
        if metadata.len() != payload.len() as u64 {
            return Err(());
        }
        let mut contents = Vec::with_capacity(payload.len());
        fs::File::open(&source)
            .and_then(|mut file| file.read_to_end(&mut contents))
            .map_err(|_| ())?;
        if contents != payload {
            return Err(());
        }
        fs::rename(&source, &renamed).map_err(|_| ())?;
        fs::remove_file(renamed).map_err(|_| ())?;
    }
    Ok(started.elapsed())
}

fn parse_nanoseconds(output: &[u8]) -> Result<f64, ()> {
    let text = std::str::from_utf8(output).map_err(|_| ())?.trim();
    let nanoseconds = text.parse::<u64>().map_err(|_| ())?;
    if nanoseconds == 0 {
        return Err(());
    }
    Ok(Duration::from_nanos(nanoseconds).as_secs_f64() * 1_000.0)
}

fn json_numbers(values: &[f64]) -> String {
    let body = values
        .iter()
        .map(|value| format!("{value:.3}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn monotonic_nonce() -> u128 {
    Instant::now().elapsed().as_nanos() ^ u128::from(std::process::id())
}
