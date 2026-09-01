use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

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

fn serve_one_http_request(listener: &TcpListener) -> bool {
    let deadline = Instant::now() + Duration::from_secs(7);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => return respond_ok(&mut stream),
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
    if stream.read(&mut request).is_err() {
        return false;
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .and_then(|()| stream.flush())
        .is_ok()
}
