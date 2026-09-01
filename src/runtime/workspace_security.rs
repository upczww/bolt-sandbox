use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use std::os::windows::process::CommandExt;

use super::{
    architecture::{ImageArchitecture, detect_image_architecture_from_reader},
    component_manifest::{read_manifest, verify_component},
    components::open_read_lease,
    workspace::WorkspaceError,
    workspace_security_protocol::{self, WorkspaceSecurityOperation, WorkspaceSecurityResult},
};

#[cfg(target_pointer_width = "64")]
const WORKSPACE_HELPER_NAME: &str = "bolt-sandbox-launcher.exe";
#[cfg(target_pointer_width = "32")]
const WORKSPACE_HELPER_NAME: &str = "bolt-sandbox-launcher-x86.exe";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) struct WorkspaceSecurityClient {
    component_root: PathBuf,
    expected_manifest_digest: Option<[u8; 32]>,
}

impl WorkspaceSecurityClient {
    pub(crate) fn new(component_root: &Path, expected_manifest_digest: Option<[u8; 32]>) -> Self {
        Self {
            component_root: component_root.to_path_buf(),
            expected_manifest_digest,
        }
    }

    pub(crate) fn copy(
        &self,
        source_root: &Path,
        destination_root: &Path,
        maximum_items: u32,
    ) -> Result<(), WorkspaceError> {
        self.execute(
            WorkspaceSecurityOperation::Copy,
            source_root,
            destination_root,
            maximum_items,
        )
    }

    pub(crate) fn verify(
        &self,
        source_root: &Path,
        destination_root: &Path,
        maximum_items: u32,
    ) -> Result<(), WorkspaceError> {
        self.execute(
            WorkspaceSecurityOperation::Verify,
            source_root,
            destination_root,
            maximum_items,
        )
    }

    pub(crate) fn copy_root(
        &self,
        source_root: &Path,
        destination_root: &Path,
    ) -> Result<(), WorkspaceError> {
        self.execute(
            WorkspaceSecurityOperation::CopyRoot,
            source_root,
            destination_root,
            1,
        )
    }

    fn execute(
        &self,
        operation: WorkspaceSecurityOperation,
        source_root: &Path,
        destination_root: &Path,
        maximum_items: u32,
    ) -> Result<(), WorkspaceError> {
        let (helper_path, helper_lease) = verified_workspace_helper(
            &self.component_root,
            self.expected_manifest_digest.as_ref(),
        )?;
        let encoded = workspace_security_protocol::encode_request(
            operation,
            source_root,
            destination_root,
            maximum_items,
        )
        .map_err(|_| WorkspaceError::InvalidRoot)?;
        let mut child = Command::new(&helper_path)
            .arg("--workspace-security")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| WorkspaceError::Io)?;
        let write_result = child
            .stdin
            .take()
            .ok_or(WorkspaceError::Io)?
            .write_all(&encoded);
        if write_result.is_err() {
            terminate_helper(&mut child);
            return Err(WorkspaceError::Io);
        }
        let mut stdout = child.stdout.take().ok_or_else(|| {
            terminate_helper(&mut child);
            WorkspaceError::Io
        })?;
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let result = workspace_security_protocol::decode_response(&mut stdout);
            let mut trailing = Vec::new();
            let trailing_result = stdout.read_to_end(&mut trailing);
            let _ = reply_sender.send((result, trailing_result, trailing));
        });
        let deadline = Instant::now() + HELPER_TIMEOUT;
        let Ok(response) = reply_receiver.recv_timeout(HELPER_TIMEOUT) else {
            terminate_helper(&mut child);
            let _ = reader.join();
            return Err(WorkspaceError::Io);
        };
        let exited = wait_until(&mut child, deadline);
        let reader_finished = reader.join().is_ok();
        drop(helper_lease);
        if !exited || !reader_finished || response.1.is_err() || !response.2.is_empty() {
            terminate_helper(&mut child);
            return Err(WorkspaceError::Io);
        }
        match response.0.map_err(|_| WorkspaceError::Io)? {
            WorkspaceSecurityResult::Success => Ok(()),
            WorkspaceSecurityResult::InvalidRoot => Err(WorkspaceError::InvalidRoot),
            WorkspaceSecurityResult::UnsupportedObject => Err(WorkspaceError::UnsupportedObject),
            WorkspaceSecurityResult::QuotaExceeded => Err(WorkspaceError::QuotaExceeded),
            WorkspaceSecurityResult::Mismatch => Err(WorkspaceError::Conflict),
            WorkspaceSecurityResult::SecurityQueryFailed
            | WorkspaceSecurityResult::SecurityApplyFailed
            | WorkspaceSecurityResult::ProtocolError => Err(WorkspaceError::Io),
        }
    }
}

pub(crate) fn verified_workspace_helper(
    component_root: &Path,
    expected_manifest_digest: Option<&[u8; 32]>,
) -> Result<(PathBuf, File), WorkspaceError> {
    let helper_path = component_root.join(WORKSPACE_HELPER_NAME);
    let manifest =
        read_manifest(component_root, expected_manifest_digest).map_err(|_| WorkspaceError::Io)?;
    let record = manifest
        .get(WORKSPACE_HELPER_NAME)
        .ok_or(WorkspaceError::Io)?;
    let mut helper_lease = open_read_lease(&helper_path).map_err(|_| WorkspaceError::Io)?;
    verify_component(&mut helper_lease, record).map_err(|_| WorkspaceError::Io)?;
    let architecture =
        detect_image_architecture_from_reader(&mut helper_lease).map_err(|_| WorkspaceError::Io)?;
    let expected_architecture = if cfg!(target_pointer_width = "64") {
        ImageArchitecture::X64
    } else {
        ImageArchitecture::X86
    };
    if architecture != expected_architecture {
        return Err(WorkspaceError::Io);
    }
    Ok((helper_path, helper_lease))
}

fn wait_until(child: &mut std::process::Child, deadline: Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

fn terminate_helper(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
