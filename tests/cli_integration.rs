use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_AGENT_FIXTURE: AtomicU64 = AtomicU64::new(0);
static SCENARIO_LOCK: Mutex<()> = Mutex::new(());

fn scenario_guard() -> MutexGuard<'static, ()> {
    SCENARIO_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn component_manifest_digest(component_root: &Path) -> String {
    let manifest = std::fs::read(component_root.join("bolt-sandbox-components.manifest"))
        .expect("component manifest must be readable");
    Sha256::digest(manifest)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}

#[test]
fn cli_003_binary_delegates_execution_and_preserves_streams_and_exit_code() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let digest = component_manifest_digest(&component_root);
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(digest)
        .arg("--timeout-ms")
        .arg("5000")
        .arg("--")
        .arg(component_root.join("bolt-sandbox-native-tests.exe"))
        .arg("--cli-fixture")
        .output()
        .expect("CLI must launch");

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"cli-out");
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");
    assert!(stderr.contains("cli-err"));
    assert!(stderr.contains("sandbox-event ready"));
    assert!(stderr.contains("sandbox-event process-exited"));
    assert!(!stderr.contains("bolt-sandbox-native-tests.exe"));
}

#[test]
fn net_001_cli_unrestricted_curl_reaches_local_http_server() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let curl = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot must be available"))
        .join(r"System32\curl.exe");
    assert!(curl.is_file(), "curl.exe is required for CLI compatibility");

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(&component_root))
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--network")
        .arg("unrestricted")
        .arg("--")
        .arg(curl)
        .args([
            "--noproxy",
            "*",
            "--max-time",
            "5",
            "--silent",
            "--show-error",
            "--output",
            "NUL",
            "--write-out",
            "http=%{http_code}",
        ])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("CLI curl fixture must launch");
    let request_served = server_thread.join().expect("server thread must join");
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");

    assert!(
        request_served,
        "sandboxed curl never reached the local server: exit={:?} stderr={stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"http=200");
    assert!(!stderr.contains("sandbox-event network-violation"));
}

#[test]
fn net_002_cli_denied_blocks_curl_after_afd_device_creation() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let curl = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot must be available"))
        .join(r"System32\curl.exe");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let server_thread =
        thread::spawn(move || wait_for_connection(&listener, Duration::from_secs(3)));
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(&component_root))
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--network")
        .arg("denied")
        .arg("--")
        .arg(curl)
        .args([
            "--noproxy",
            "*",
            "--max-time",
            "2",
            "--silent",
            "--show-error",
        ])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("denied CLI curl fixture must launch");
    let connected = server_thread.join().expect("server thread must join");

    assert!(!connected, "denied curl reached the local server");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");
    assert!(stderr.contains("sandbox-event network-violation"));
}

#[test]
fn net_003_cli_allow_list_proxies_nonblocking_curl_for_allowed_endpoint_and_port() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let curl = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot must be available"))
        .join(r"System32\curl.exe");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(&component_root))
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--network")
        .arg("allow-list")
        .arg("--allow-domain")
        .arg("localhost")
        .arg("--allow-cidr")
        .arg("127.0.0.1/32")
        .arg("--allow-port")
        .arg(port.to_string())
        .arg("--")
        .arg(curl)
        .args([
            "--ipv4",
            "--noproxy",
            "*",
            "--max-time",
            "5",
            "--silent",
            "--show-error",
            "--output",
            "NUL",
            "--write-out",
            "http=%{http_code}",
        ])
        .arg(format!("http://localhost:{port}/"))
        .output()
        .expect("allow-list CLI curl fixture must launch");
    let request_served = server_thread.join().expect("server thread must join");
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");

    assert!(
        request_served,
        "allow-listed curl never reached the local server: exit={:?} stderr={stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"http=200");
    assert!(!stderr.contains("sandbox-event network-violation"));
}

#[test]
fn net_004_cli_unrestricted_node_http_reaches_local_server() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(program_files) = std::env::var_os("ProgramFiles").map(PathBuf::from) else {
        return;
    };
    let node = program_files.join(r"nodejs\node.exe");
    if !node.is_file() {
        return;
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let script = "const http=require('http');const request=http.get(process.argv[1],{timeout:5000},response=>{console.log('node='+response.statusCode);response.resume();response.on('end',()=>process.exit(response.statusCode===200?0:3));});request.on('timeout',()=>request.destroy(new Error('timeout')));request.on('error',error=>{console.error('node-error='+(error.code||error.message));process.exit(2);});";
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(&component_root))
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--network")
        .arg("unrestricted")
        .arg("--")
        .arg(node)
        .args(["-e", script])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("Node CLI fixture must launch");
    let request_served = server_thread.join().expect("server thread must join");
    let stderr = String::from_utf8(output.stderr).expect("CLI diagnostics are UTF-8");

    assert!(
        request_served,
        "sandboxed Node never reached the local server: exit={:?} stderr={stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"node=200\n");
    assert!(!stderr.contains("sandbox-event network-violation"));
}

#[test]
fn net_005_cli_unrestricted_python_reads_its_runtime_and_reaches_local_server() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(python) = std::env::var_os("BOLT_TEST_PYTHON").map(PathBuf::from) else {
        return;
    };
    if !python.is_file() {
        return;
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let script = "import sys,urllib.request\nurl=sys.argv[1]\nopener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\ntry:\n response=opener.open(url,timeout=5)\n print('python='+str(response.status))\n response.close()\n sys.exit(0 if response.status==200 else 3)\nexcept Exception as error:\n print('python-error='+type(error).__name__+':'+str(error))\n sys.exit(2)";
    let output = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"))
        .arg("run")
        .arg("--component-root")
        .arg(&component_root)
        .arg("--cwd")
        .arg(&component_root)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(&component_root))
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--network")
        .arg("unrestricted")
        .arg("--")
        .arg(python)
        .args(["-c", script])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("Python CLI fixture must launch");
    let request_served = server_thread.join().expect("server thread must join");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8(output.stdout).expect("Python fixture output is UTF-8");

    assert!(
        request_served,
        "sandboxed Python never reached the local server: exit={:?} stderr={stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout.trim(), "python=200");
    assert!(!stderr.contains("sandbox-event network-violation"));
}

#[test]
fn agent_node_allow_list_and_denied_modes_enforce_local_http() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(node) = std::env::var_os("BOLT_TEST_NODE").map(PathBuf::from) else {
        return;
    };
    assert!(node.is_file(), "declared Node runtime must exist");
    let script = "const http=require('http');const request=http.get(process.argv[1],{timeout:3000},response=>{console.log('node='+response.statusCode);response.resume();response.on('end',()=>process.exit(response.statusCode===200?0:3));});request.on('timeout',()=>request.destroy(new Error('timeout')));request.on('error',error=>{console.error('node-error='+(error.code||error.message));process.exit(2);});";

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let allow_server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let allowed = sandbox_command(&component_root, &component_root)
        .args([
            "--network",
            "allow-list",
            "--allow-cidr",
            "127.0.0.1/32",
            "--allow-port",
        ])
        .arg(port.to_string())
        .arg("--")
        .arg(&node)
        .args(["-e", script])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("allow-listed Node must launch");
    let request_served = allow_server_thread.join().expect("allow server must join");
    assert!(
        request_served,
        "Node allow-list did not reach server: exit={:?} stderr={}",
        allowed.status.code(),
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(allowed.status.code(), Some(0));
    assert_eq!(allowed.stdout, b"node=200\n");

    let denied_listener = TcpListener::bind(("127.0.0.1", 0)).expect("denied listener must bind");
    denied_listener
        .set_nonblocking(true)
        .expect("denied listener must be nonblocking");
    let denied_port = denied_listener
        .local_addr()
        .expect("listener has address")
        .port();
    let denied_server =
        thread::spawn(move || wait_for_connection(&denied_listener, Duration::from_secs(3)));
    let denied = sandbox_command(&component_root, &component_root)
        .args(["--network", "denied", "--"])
        .arg(node)
        .args(["-e", script])
        .arg(format!("http://127.0.0.1:{denied_port}/"))
        .output()
        .expect("denied Node must launch");
    assert!(!denied_server.join().expect("denied server must join"));
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("network-violation"));
}

#[test]
fn agent_python_allow_list_and_denied_modes_enforce_local_http() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(python) = std::env::var_os("BOLT_TEST_PYTHON").map(PathBuf::from) else {
        return;
    };
    assert!(python.is_file(), "declared Python runtime must exist");
    let script = "import sys,urllib.request\nopener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\ntry:\n response=opener.open(sys.argv[1],timeout=3)\n print('python='+str(response.status))\n response.close()\n sys.exit(0 if response.status==200 else 3)\nexcept Exception as error:\n print('python-error='+type(error).__name__+':'+str(error))\n sys.exit(2)";

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let port = listener.local_addr().expect("listener has address").port();
    let allow_server_thread = thread::spawn(move || serve_one_http_request(&listener));
    let allowed = sandbox_command(&component_root, &component_root)
        .args([
            "--network",
            "allow-list",
            "--allow-cidr",
            "127.0.0.1/32",
            "--allow-port",
        ])
        .arg(port.to_string())
        .arg("--")
        .arg(&python)
        .args(["-c", script])
        .arg(format!("http://127.0.0.1:{port}/"))
        .output()
        .expect("allow-listed Python must launch");
    let request_served = allow_server_thread.join().expect("allow server must join");
    assert!(
        request_served,
        "Python allow-list did not reach server: exit={:?} stderr={}",
        allowed.status.code(),
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(allowed.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&allowed.stdout).trim(),
        "python=200"
    );

    let denied_listener = TcpListener::bind(("127.0.0.1", 0)).expect("denied listener must bind");
    denied_listener
        .set_nonblocking(true)
        .expect("denied listener must be nonblocking");
    let denied_port = denied_listener
        .local_addr()
        .expect("listener has address")
        .port();
    let denied_server =
        thread::spawn(move || wait_for_connection(&denied_listener, Duration::from_secs(3)));
    let denied = sandbox_command(&component_root, &component_root)
        .args(["--network", "denied", "--"])
        .arg(python)
        .args(["-c", script])
        .arg(format!("http://127.0.0.1:{denied_port}/"))
        .output()
        .expect("denied Python must launch");
    assert!(!denied_server.join().expect("denied server must join"));
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("network-violation"));
}

#[test]
fn agent_git_status_runs_in_task_workspace_without_network() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(git) = std::env::var_os("BOLT_TEST_GIT").map(PathBuf::from) else {
        return;
    };
    assert!(git.is_file(), "declared Git runtime must exist");
    let workspace = agent_fixture_directory("git");
    fs::create_dir_all(&workspace).expect("Git workspace must be created");
    let initialized = Command::new(&git)
        .args(["init", "--quiet"])
        .current_dir(&workspace)
        .status()
        .expect("Git fixture initialization must run");
    assert!(initialized.success());
    fs::write(workspace.join("agent.txt"), b"sandbox\n").expect("Git fixture must be written");

    let mut command = sandbox_command(&component_root, &workspace);
    for name in std::env::vars_os().map(|(name, _)| name) {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("CARGO_") || name.starts_with("RUST_"))
        {
            command.env_remove(name);
        }
    }
    command
        .env("PWD", &workspace)
        .env("HOME", &workspace)
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_CONFIG_SYSTEM", "NUL");
    let output = command
        .arg("--network")
        .arg("denied")
        .arg("--")
        .arg(&git)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
        .expect("sandboxed Git must launch");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let _ = fs::remove_dir_all(&workspace);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(stdout.contains("?? agent.txt"), "stdout={stdout}");
    assert!(!stderr.contains("sandbox-event network-violation"));
}

#[test]
fn agent_cargo_metadata_runs_offline_with_private_home() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let Some(cargo) = std::env::var_os("BOLT_TEST_CARGO").map(PathBuf::from) else {
        return;
    };
    assert!(cargo.is_file(), "declared Cargo runtime must exist");
    let workspace = agent_fixture_directory("cargo");
    fs::create_dir_all(workspace.join("src")).expect("Cargo workspace must be created");
    fs::write(
        workspace.join("Cargo.toml"),
        b"[package]\nname = \"agent-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest must be written");
    fs::write(workspace.join(r"src\main.rs"), b"fn main() {}\n")
        .expect("Cargo source must be written");
    let cargo_home = workspace.join(".cargo-home");
    fs::create_dir(&cargo_home).expect("task-private Cargo home must be created");
    let toolchain_bin = cargo
        .parent()
        .expect("Cargo must have a containing directory");
    let system32 =
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot must be available"))
            .join("System32");
    let minimal_path = std::env::join_paths([toolchain_bin, system32.as_path()])
        .expect("minimal toolchain PATH must encode");

    let mut command = sandbox_command(&component_root, &workspace);
    command
        .env("CARGO_HOME", &cargo_home)
        .env("HOME", &workspace)
        .env("PATH", &minimal_path);
    let output = command
        .arg("--network")
        .arg("denied")
        .arg("--")
        .arg(&cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
        ])
        .arg(workspace.join("Cargo.toml"))
        .output()
        .expect("sandboxed Cargo must launch");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(stdout.contains("agent-fixture"), "stdout={stdout}");
    assert!(!stderr.contains("sandbox-event network-violation"));

    let rustc = toolchain_bin.join("rustc.exe");
    assert!(
        rustc.is_file(),
        "declared Cargo toolchain must contain rustc"
    );
    let mut check = sandbox_command(&component_root, &workspace);
    for name in std::env::vars_os().map(|(name, _)| name) {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("CARGO_") || name.starts_with("RUST_"))
        {
            check.env_remove(name);
        }
    }
    check
        .env("CARGO_HOME", &cargo_home)
        .env("HOME", &workspace)
        .env("PATH", &minimal_path)
        .env("RUSTC", rustc);
    let checked = check
        .args(["--network", "denied", "--"])
        .arg(&cargo)
        .args(["check", "--offline", "--manifest-path"])
        .arg(workspace.join("Cargo.toml"))
        .output()
        .expect("sandboxed Cargo check must launch");
    let check_stderr = String::from_utf8_lossy(&checked.stderr);
    assert_eq!(checked.status.code(), Some(0), "stderr={check_stderr}");
    assert!(
        workspace.join(r"target\debug\.fingerprint").is_dir(),
        "Cargo check did not write task-private output"
    );
    assert!(!check_stderr.contains("sandbox-event network-violation"));
    let _ = fs::remove_dir_all(&workspace);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one ordered end-to-end matrix keeps every tool in the same Agent workspace"
)]
fn agent_workspace_toolchain_matrix_stays_inside_workspace() {
    let _guard = scenario_guard();
    let Some(component_root) = std::env::var_os("BOLT_NATIVE_COMPONENT_ROOT").map(PathBuf::from)
    else {
        return;
    };
    let required_tool = |name: &str| {
        let path = std::env::var_os(name).map_or_else(
            || panic!("{name} must be declared by the Agent scenario harness"),
            PathBuf::from,
        );
        assert!(path.is_file(), "{name} executable must exist: {path:?}");
        path
    };
    let shell = required_tool("BOLT_TEST_SHELL");
    let powershell = required_tool("BOLT_TEST_POWERSHELL");
    let python = required_tool("BOLT_TEST_PYTHON");
    let node = required_tool("BOLT_TEST_NODE");
    let git = required_tool("BOLT_TEST_GIT");
    let cargo = required_tool("BOLT_TEST_CARGO");
    let native_compiler = required_tool("BOLT_TEST_NATIVE_COMPILER");
    let native_compiler_kind = std::env::var("BOLT_TEST_NATIVE_COMPILER_KIND")
        .expect("native compiler kind must be declared");
    let system_language_roots = std::env::var_os("BOLT_TEST_SYSTEM_LANGUAGE_ROOTS")
        .map(|roots| {
            std::env::split_paths(&roots)
                .filter(|root| !root.as_os_str().is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        system_language_roots.iter().all(|root| root.is_absolute()),
        "system language roots must be absolute: {system_language_roots:?}"
    );
    let workspace = agent_fixture_directory("工具链 workspace");
    let private_home = workspace.join(".agent-home");
    let private_temp = workspace.join(".agent-temp");
    let git_template = workspace.join(".git-template");
    let cargo_home = workspace.join(".cargo-home");
    fs::create_dir_all(&private_home).expect("private home must be created");
    fs::create_dir_all(&private_temp).expect("private temp must be created");
    fs::create_dir_all(&git_template).expect("private Git template must be created");
    fs::create_dir_all(&cargo_home).expect("private Cargo home must be created");
    let powershell_script = workspace.join("powershell-agent.ps1");
    fs::write(
        &powershell_script,
        "$ErrorActionPreference='Stop'\nNew-Item -ItemType Directory -Force ps | Out-Null\nSet-Content -NoNewline -Path ps/result.txt -Value powershell\nWrite-Output BOLT_PS_RAN\n",
    )
    .expect("PowerShell Agent script must be written");
    let powershell_script_argument = powershell_script.to_string_lossy().into_owned();
    let mut host_metadata_roots = ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .collect::<Vec<_>>();
    host_metadata_roots.extend(
        workspace
            .ancestors()
            .skip(1)
            .filter(|ancestor| ancestor.parent().is_some())
            .map(Path::to_path_buf),
    );
    host_metadata_roots.sort();
    host_metadata_roots.dedup();

    let run =
        |label: &str, terminal: &str, program: &Path, args: &[&str], read_roots: &[PathBuf]| {
            let mut command = sandbox_command(&component_root, &workspace);
            if label == "Cargo check" {
                for name in std::env::vars_os().map(|(name, _)| name) {
                    if name
                        .to_str()
                        .is_some_and(|name| name.starts_with("CARGO_") || name.starts_with("RUST_"))
                    {
                        command.env_remove(name);
                    }
                }
                let toolchain_bin = cargo
                    .parent()
                    .expect("Cargo toolchain directory must exist");
                let toolchain_root = toolchain_bin
                    .parent()
                    .expect("Cargo toolchain root must exist");
                let system32 = PathBuf::from(
                    std::env::var_os("SystemRoot").expect("SystemRoot must be available"),
                )
                .join("System32");
                command
                    .arg("--read-only")
                    .arg(toolchain_root)
                    .env("CARGO_HOME", &cargo_home)
                    .env("RUSTC", toolchain_bin.join("rustc.exe"))
                    .env(
                        "PATH",
                        std::env::join_paths([toolchain_bin, system32.as_path()])
                            .expect("minimal Cargo PATH must encode"),
                    );
            }
            for root in read_roots {
                command.arg("--read-only").arg(root);
            }
            for root in &system_language_roots {
                command.arg("--read-only").arg(root);
            }
            for root in &host_metadata_roots {
                command.arg("--metadata-read").arg(root);
            }
            if label == "PowerShell" {
                command.env("DOTNET_EnableDiagnostics", "0");
            }
            command
                .args(["--terminal", terminal, "--network", "denied", "--"])
                .arg(program)
                .args(args)
                .env("HOME", &private_home)
                .env("USERPROFILE", &private_home)
                .env("TEMP", &private_temp)
                .env("TMP", &private_temp)
                .env("GIT_CONFIG_GLOBAL", "NUL")
                .env("GIT_CONFIG_SYSTEM", "NUL")
                .env("GIT_TEMPLATE_DIR", &git_template)
                .env("GIT_ATTR_NOSYSTEM", "1")
                .env("XDG_CONFIG_HOME", &private_home);
            let output = command
                .output()
                .unwrap_or_else(|error| panic!("{label} must launch once: {error}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                output.status.code(),
                Some(0),
                "{label} failed in workspace: stdout={stdout} stderr={stderr}"
            );
            assert!(
                !stderr.contains("sandbox-event network-violation"),
                "{label} unexpectedly attempted network access: {stderr}"
            );
            if label == "PowerShell" {
                assert!(
                    stdout.contains("BOLT_PS_RAN"),
                    "PowerShell script was not executed: stdout={stdout} stderr={stderr}"
                );
            }
        };

    run(
        "cmd",
        "pipes",
        &shell,
        &[
            "/d",
            "/s",
            "/c",
            "mkdir shell && echo shell>shell\\result.txt",
        ],
        &[],
    );
    run(
        "PowerShell",
        "pseudo-console",
        &powershell,
        &[
            "-NoLogo",
            "-NoProfile",
            "-File",
            &powershell_script_argument,
        ],
        &[],
    );
    run(
        "Python",
        "pipes",
        &python,
        &[
            "-I",
            "-c",
            "import pathlib,subprocess,sys; pathlib.Path('python').mkdir(); pathlib.Path('python/result.txt').write_text('python',encoding='utf-8'); subprocess.run([sys.executable,'-I','-c','import pathlib;pathlib.Path(r\"python/child.txt\").write_text(\"child\")'],check=True)",
        ],
        &[],
    );
    run(
        "Node",
        "pipes",
        &node,
        &[
            "-e",
            "const fs=require('fs'),cp=require('child_process');fs.mkdirSync('node');fs.writeFileSync('node/result.txt','node');const r=cp.spawnSync(process.execPath,['-e',\"require('fs').writeFileSync('node/child.txt','child')\"],{stdio:'inherit'});process.exit(r.status??1);",
        ],
        &[],
    );

    run("Git init", "pipes", &git, &["init", "--quiet"], &[]);
    fs::write(workspace.join("tracked.txt"), "tracked\n").expect("Git input must be written");
    run("Git add", "pipes", &git, &["add", "tracked.txt"], &[]);
    run(
        "Git status",
        "pipes",
        &git,
        &["status", "--porcelain", "--untracked-files=all"],
        &[],
    );

    let cargo_project = workspace.join("rust");
    fs::create_dir_all(cargo_project.join("src")).expect("Rust source directory must be created");
    fs::write(
        cargo_project.join("Cargo.toml"),
        "[package]\nname='agent-workspace'\nversion='0.1.0'\nedition='2024'\n",
    )
    .expect("Cargo manifest must be written");
    fs::write(cargo_project.join("src/main.rs"), "fn main() {}\n")
        .expect("Rust source must be written");
    run(
        "Cargo check",
        "pipes",
        &cargo,
        &[
            "check",
            "--offline",
            "--manifest-path",
            "rust/Cargo.toml",
            "--target-dir",
            "rust/target",
        ],
        &[],
    );

    fs::create_dir_all(workspace.join("native")).expect("native source directory must be created");
    fs::write(
        workspace.join("native/hello.c"),
        "#include <stdio.h>\nint main(void) { puts(\"native-ok\"); return 0; }\n",
    )
    .expect("native source must be written");
    let compiler_read_roots = std::env::var_os("BOLT_TEST_NATIVE_COMPILER_READ_ROOTS")
        .map(|roots| std::env::split_paths(&roots).collect::<Vec<_>>())
        .unwrap_or_default();
    match native_compiler_kind.as_str() {
        "msvc" => run(
            "MSVC",
            "pipes",
            &native_compiler,
            &[
                "/nologo",
                "/c",
                "/TC",
                "native/hello.c",
                "/Fo:native/hello.obj",
            ],
            &compiler_read_roots,
        ),
        "gcc" => run(
            "GCC",
            "pipes",
            &native_compiler,
            &["native/hello.c", "-o", "native/hello.exe"],
            &compiler_read_roots,
        ),
        other => panic!("unsupported native compiler kind: {other}"),
    }
    if native_compiler_kind == "msvc" {
        run(
            "MSVC linker",
            "pipes",
            &native_compiler.with_file_name("link.exe"),
            &["/nologo", "native/hello.obj", "/out:native/hello.exe"],
            &compiler_read_roots,
        );
    }
    run(
        "compiled native program",
        "pipes",
        &workspace.join("native/hello.exe"),
        &[],
        &[],
    );

    for relative in [
        "shell/result.txt",
        "ps/result.txt",
        "python/result.txt",
        "python/child.txt",
        "node/result.txt",
        "node/child.txt",
        "rust/target/debug/.fingerprint",
        "native/hello.exe",
    ] {
        assert!(
            workspace.join(relative).exists(),
            "Agent output must remain in workspace: {relative}"
        );
    }
    fs::remove_dir_all(&workspace).expect("Agent workspace fixture must be removed");
}

fn sandbox_command(component_root: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bolt-sandbox"));
    command
        .arg("run")
        .arg("--component-root")
        .arg(component_root)
        .arg("--cwd")
        .arg(cwd)
        .arg("--manifest-sha256")
        .arg(component_manifest_digest(component_root))
        .arg("--timeout-ms")
        .arg("10000");
    command
}

fn agent_fixture_directory(kind: &str) -> PathBuf {
    let id = NEXT_AGENT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository must have a parent")
        .join("agent-fixtures")
        .join(format!("{kind}-{}-{id}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).expect("stale Agent fixture must be removed");
    }
    path
}

fn serve_one_http_request(listener: &TcpListener) -> bool {
    let deadline = Instant::now() + Duration::from_secs(7);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if respond_ok(&mut stream) {
                    return true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return false,
        }
    }
    false
}

fn wait_for_connection(listener: &TcpListener, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return false,
        }
    }
    false
}

fn respond_ok(stream: &mut TcpStream) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = [0_u8; 4_096];
    if !matches!(stream.read(&mut request), Ok(bytes) if bytes != 0) {
        return false;
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .and_then(|()| stream.flush())
        .is_ok()
}

#[test]
fn net_030_fixture_server_ignores_an_aborted_probe_connection() {
    let _guard = scenario_guard();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be nonblocking");
    let address = listener.local_addr().expect("listener has address");
    let server = thread::spawn(move || serve_one_http_request(&listener));

    let probe = TcpStream::connect(address).expect("probe must connect");
    probe
        .shutdown(std::net::Shutdown::Both)
        .expect("probe shutdown must succeed");
    drop(probe);

    let mut client = TcpStream::connect(address).expect("client must connect");
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout must configure");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("request must write");
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);

    assert!(server.join().expect("server must join"));
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}
