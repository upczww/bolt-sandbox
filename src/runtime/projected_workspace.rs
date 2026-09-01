use std::{
    fmt,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use std::os::windows::process::CommandExt;

use super::{
    projected_workspace_protocol::{
        self, ProjectedWorkspaceControl, ProjectedWorkspaceResponseKind, ProjectedWorkspaceResult,
    },
    workspace::WorkspaceError,
    workspace_security::verified_workspace_helper,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const START_TIMEOUT: Duration = Duration::from_secs(5);
const MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct ProjectedWorkspaceController {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    _helper_lease: File,
    materialization_root: PathBuf,
    active: bool,
}

impl fmt::Debug for ProjectedWorkspaceController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedWorkspaceController")
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl ProjectedWorkspaceController {
    pub(crate) fn start(
        component_root: &Path,
        expected_manifest_digest: Option<&[u8; 32]>,
        source_root: &Path,
        projection_root: &Path,
        maximum_items: u32,
        maximum_bytes: u64,
    ) -> Result<Self, WorkspaceError> {
        let (helper_path, helper_lease) =
            verified_workspace_helper(component_root, expected_manifest_digest)?;
        let encoded = projected_workspace_protocol::encode_request(
            source_root,
            projection_root,
            maximum_items,
            maximum_bytes,
        )
        .map_err(|_| WorkspaceError::InvalidRoot)?;
        let mut child = Command::new(helper_path)
            .arg("--projected-workspace")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| WorkspaceError::Io)?;
        let mut input = child.stdin.take().ok_or(WorkspaceError::Io)?;
        if input
            .write_all(&encoded)
            .and_then(|()| input.flush())
            .is_err()
        {
            terminate(&mut child);
            return Err(WorkspaceError::Io);
        }
        let output = child.stdout.take().ok_or_else(|| {
            terminate(&mut child);
            WorkspaceError::Io
        })?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = output;
            let result = projected_workspace_protocol::decode_response(
                &mut output,
                ProjectedWorkspaceResponseKind::Ready,
            );
            let _ = sender.send((result, output));
        });
        let Ok(ready) = receiver.recv_timeout(START_TIMEOUT) else {
            terminate(&mut child);
            let _ = reader.join();
            return Err(WorkspaceError::Io);
        };
        if reader.join().is_err() {
            terminate(&mut child);
            return Err(WorkspaceError::Io);
        }
        let result = ready.0.map_err(|_| WorkspaceError::Io)?;
        if result != ProjectedWorkspaceResult::Success {
            terminate(&mut child);
            return Err(map_result(result));
        }
        let mut materialized_name = projection_root.as_os_str().to_os_string();
        materialized_name.push(".materialized");
        Ok(Self {
            child,
            input: Some(input),
            output: Some(ready.1),
            _helper_lease: helper_lease,
            materialization_root: PathBuf::from(materialized_name),
            active: true,
        })
    }

    pub(crate) fn materialization_root(&self) -> &Path {
        &self.materialization_root
    }

    pub(crate) fn materialize(mut self) -> Result<(), WorkspaceError> {
        let control =
            projected_workspace_protocol::encode_control(ProjectedWorkspaceControl::Materialize);
        let input = self.input.as_mut().ok_or(WorkspaceError::Io)?;
        if input
            .write_all(&control)
            .and_then(|()| input.flush())
            .is_err()
        {
            terminate(&mut self.child);
            self.active = false;
            return Err(WorkspaceError::Io);
        }
        self.input.take();
        let output = self.output.take().ok_or(WorkspaceError::Io)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = output;
            let result = projected_workspace_protocol::decode_response(
                &mut output,
                ProjectedWorkspaceResponseKind::Finished,
            );
            let _ = sender.send(result);
        });
        let Ok(result) = receiver.recv_timeout(MATERIALIZE_TIMEOUT) else {
            terminate(&mut self.child);
            self.active = false;
            let _ = reader.join();
            return Err(WorkspaceError::Io);
        };
        let deadline = Instant::now() + EXIT_GRACE;
        let exited = wait_until(&mut self.child, deadline);
        self.active = false;
        if reader.join().is_err() || !exited {
            terminate(&mut self.child);
            return Err(WorkspaceError::Io);
        }
        match result.map_err(|_| WorkspaceError::Io)? {
            ProjectedWorkspaceResult::Success => Ok(()),
            other => Err(map_result(other)),
        }
    }
}

impl Drop for ProjectedWorkspaceController {
    fn drop(&mut self) {
        if self.active {
            self.discard_active();
        }
    }
}

impl ProjectedWorkspaceController {
    fn discard_active(&mut self) {
        let control =
            projected_workspace_protocol::encode_control(ProjectedWorkspaceControl::Discard);
        let wrote = self.input.as_mut().is_some_and(|input| {
            input
                .write_all(&control)
                .and_then(|()| input.flush())
                .is_ok()
        });
        self.input.take();
        let Some(output) = self.output.take() else {
            terminate(&mut self.child);
            self.active = false;
            return;
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = output;
            let result = projected_workspace_protocol::decode_response(
                &mut output,
                ProjectedWorkspaceResponseKind::Finished,
            );
            let _ = sender.send(result);
        });
        let response = receiver.recv_timeout(Duration::from_secs(1));
        let response_ok = matches!(response, Ok(Ok(ProjectedWorkspaceResult::Success)));
        let exited = wait_until(&mut self.child, Instant::now() + EXIT_GRACE);
        if !wrote || !response_ok || reader.join().is_err() || !exited {
            terminate(&mut self.child);
        }
        self.active = false;
    }
}

fn map_result(result: ProjectedWorkspaceResult) -> WorkspaceError {
    match result {
        ProjectedWorkspaceResult::Unavailable => WorkspaceError::Unavailable,
        ProjectedWorkspaceResult::InvalidRoot => WorkspaceError::InvalidRoot,
        ProjectedWorkspaceResult::UnsupportedObject => WorkspaceError::UnsupportedObject,
        ProjectedWorkspaceResult::QuotaExceeded => WorkspaceError::QuotaExceeded,
        ProjectedWorkspaceResult::Conflict => WorkspaceError::Conflict,
        ProjectedWorkspaceResult::Success
        | ProjectedWorkspaceResult::SecurityFailure
        | ProjectedWorkspaceResult::Io
        | ProjectedWorkspaceResult::ProtocolError => WorkspaceError::Io,
    }
}

fn wait_until(child: &mut Child, deadline: Instant) -> bool {
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

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
