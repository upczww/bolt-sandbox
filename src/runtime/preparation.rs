use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};

use super::architecture::{
    ImageArchitecture, ImageArchitectureError, detect_image_architecture_from_reader,
};
use super::components::{ComponentOpenError, OpenedComponents, open_components};
use crate::{
    SandboxError, SandboxRequest,
    ipc::identity::ExecutionIdentity,
    policy::compiler::{self, CompiledRecoveryPolicy, payload},
    request,
};

pub(super) struct PreparedLaunch {
    program: PathBuf,
    cwd: PathBuf,
    program_handle: File,
    architecture: ImageArchitecture,
    command_line: Vec<u16>,
    environment_block: Vec<u16>,
    policy_payload: Vec<u8>,
    stripped_credentials: usize,
    timeout: Option<Duration>,
    execution_identity: ExecutionIdentity,
    components: OpenedComponents,
    recovery: Option<PreparedRecovery>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PreparedRecovery {
    pub(super) directory: PathBuf,
    pub(super) maximum_bytes: u64,
    pub(super) maximum_items: u32,
}

impl PreparedLaunch {
    pub(super) fn program(&self) -> &Path {
        &self.program
    }

    pub(super) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub(super) const fn architecture(&self) -> ImageArchitecture {
        self.architecture
    }

    pub(super) fn command_line(&self) -> &[u16] {
        &self.command_line
    }

    pub(super) fn environment_block(&self) -> &[u16] {
        &self.environment_block
    }

    pub(super) fn policy_payload(&self) -> &[u8] {
        &self.policy_payload
    }

    pub(super) const fn stripped_credentials(&self) -> usize {
        self.stripped_credentials
    }

    pub(super) const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub(super) const fn program_handle(&self) -> &File {
        &self.program_handle
    }

    pub(super) fn ipc_endpoint_name(&self) -> &str {
        self.execution_identity.endpoint_name()
    }

    pub(super) const fn handshake_nonce(&self) -> &[u8; 16] {
        self.execution_identity.handshake_nonce()
    }

    pub(super) fn launcher_component_path(&self) -> &Path {
        self.components.launcher_path()
    }

    pub(super) fn hook_component_path(&self) -> &Path {
        self.components.hook_path()
    }

    pub(super) const fn launcher_component_handle(&self) -> &File {
        self.components.launcher_handle()
    }

    pub(super) const fn hook_component_handle(&self) -> &File {
        self.components.hook_handle()
    }

    pub(super) const fn recovery(&self) -> Option<&PreparedRecovery> {
        self.recovery.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LaunchPreparationError {
    Request(SandboxError),
    ProgramOpen,
    InvalidProgramImage,
    UnsupportedArchitecture { machine: u16 },
    Component(ComponentOpenError),
    PolicyPayload,
    ExecutionIdentity,
}

pub(super) fn prepare_launch(
    request_value: &SandboxRequest,
    credential_names: &[OsString],
    component_root: &Path,
) -> Result<PreparedLaunch, LaunchPreparationError> {
    prepare_launch_with_identity_factory(request_value, credential_names, component_root, || {
        ExecutionIdentity::generate().map_err(|_| LaunchPreparationError::ExecutionIdentity)
    })
}

fn prepare_launch_with_identity_factory(
    request_value: &SandboxRequest,
    credential_names: &[OsString],
    component_root: &Path,
    create_identity: impl FnOnce() -> Result<ExecutionIdentity, LaunchPreparationError>,
) -> Result<PreparedLaunch, LaunchPreparationError> {
    request_value
        .validate()
        .map_err(LaunchPreparationError::Request)?;

    let prepared_environment =
        request::prepare_environment(&request_value.environment, credential_names)
            .map_err(LaunchPreparationError::Request)?;
    let command_line =
        request::encode_command_line(&request_value.program, &request_value.arguments)
            .map_err(LaunchPreparationError::Request)?;
    let environment_block = request::encode_environment_block(&prepared_environment.variables)
        .map_err(LaunchPreparationError::Request)?;
    let compiled_policy = compiler::compile(&request_value.policy, &request_value.cwd)
        .map_err(LaunchPreparationError::Request)?;
    let recovery = match &compiled_policy.recovery {
        CompiledRecoveryPolicy::Disabled => None,
        CompiledRecoveryPolicy::Enabled(limits) => Some(PreparedRecovery {
            directory: limits.directory().to_path_buf(),
            maximum_bytes: limits.maximum_bytes(),
            maximum_items: limits.maximum_items(),
        }),
    };
    let policy_payload = payload::seal(&compiled_policy)
        .map_err(|_| LaunchPreparationError::PolicyPayload)?
        .into_bytes();

    let mut program_handle =
        File::open(&request_value.program).map_err(|_| LaunchPreparationError::ProgramOpen)?;
    let architecture = detect_image_architecture_from_reader(&mut program_handle)
        .map_err(map_architecture_error)?;
    let components =
        open_components(component_root, architecture).map_err(LaunchPreparationError::Component)?;
    let execution_identity = create_identity()?;

    Ok(PreparedLaunch {
        program: request_value.program.clone(),
        cwd: request_value.cwd.clone(),
        program_handle,
        architecture,
        command_line,
        environment_block,
        policy_payload,
        stripped_credentials: prepared_environment.diagnostic.stripped_credentials,
        timeout: request_value.timeout,
        execution_identity,
        components,
        recovery,
    })
}

const fn map_architecture_error(error: ImageArchitectureError) -> LaunchPreparationError {
    match error {
        ImageArchitectureError::UnsupportedMachine { machine } => {
            LaunchPreparationError::UnsupportedArchitecture { machine }
        }
        ImageArchitectureError::TruncatedDosHeader
        | ImageArchitectureError::InvalidDosSignature
        | ImageArchitectureError::PeHeaderOutOfRange
        | ImageArchitectureError::TruncatedCoffHeader
        | ImageArchitectureError::InvalidPeSignature
        | ImageArchitectureError::ReadFailure => LaunchPreparationError::InvalidProgramImage,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        ffi::{OsStr, OsString},
        fs,
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use super::*;
    use crate::{
        InvalidRequestReason, RequestField, SandboxError, SandboxPolicy, SandboxRequest,
        policy::compiler::payload, runtime::architecture::ImageArchitecture,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        program: PathBuf,
    }

    impl Fixture {
        fn x64() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "bolt-sandbox-preparation-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("fixture directory must be created");
            let program = root.join("fixture.exe");
            fs::write(&program, pe_image(0x8664)).expect("fixture image must be written");
            let fixture = Self { root, program };
            fixture.install_components();
            fixture
        }

        fn request(&self) -> SandboxRequest {
            SandboxRequest {
                program: self.program.clone(),
                arguments: vec![OsString::from("--value"), OsString::from("hello world")],
                cwd: self.root.clone(),
                environment: BTreeMap::from([
                    (OsString::from("VISIBLE"), OsString::from("yes")),
                    (OsString::from("SECRET_TOKEN"), OsString::from("canary")),
                ]),
                policy: SandboxPolicy::default(),
                timeout: Some(Duration::from_secs(5)),
            }
        }

        fn install_components(&self) {
            fs::write(
                self.root.join("bolt-sandbox-launcher.exe"),
                pe_image(0x8664),
            )
            .expect("launcher fixture must be written");
            fs::write(self.root.join("bolt-sandbox-x64.dll"), pe_image(0x8664))
                .expect("x64 hook fixture must be written");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn pe_image(machine: u16) -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        let mut image = vec![0; PE_OFFSET + 6];
        image[..2].copy_from_slice(b"MZ");
        image[0x3C..0x40].copy_from_slice(
            &u32::try_from(PE_OFFSET)
                .expect("offset must fit")
                .to_le_bytes(),
        );
        image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        image[PE_OFFSET + 4..PE_OFFSET + 6].copy_from_slice(&machine.to_le_bytes());
        image
    }

    fn block_contains(block: &[u16], text: &str) -> bool {
        let needle = OsStr::new(text).encode_wide().collect::<Vec<_>>();
        block.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn req_001_preparation_atomically_builds_all_launcher_inputs() {
        let fixture = Fixture::x64();
        let request = fixture.request();

        let prepared = prepare_launch(&request, &[OsString::from("secret_token")], &fixture.root)
            .expect("valid request must prepare");

        assert_eq!(prepared.architecture(), ImageArchitecture::X64);
        assert_eq!(prepared.stripped_credentials(), 1);
        assert!(block_contains(prepared.environment_block(), "VISIBLE=yes"));
        assert!(!block_contains(
            prepared.environment_block(),
            "SECRET_TOKEN"
        ));
        assert!(!block_contains(prepared.environment_block(), "canary"));
        assert_eq!(prepared.timeout(), request.timeout);
        assert_eq!(prepared.command_line().last(), Some(&0));
        assert!(payload::verify(prepared.policy_payload()).is_ok());
        assert!(prepared.program_handle().metadata().is_ok());
        assert!(
            prepared
                .ipc_endpoint_name()
                .starts_with(r"\\.\pipe\bolt-sandbox-")
        );
        assert_eq!(prepared.handshake_nonce().len(), 16);
    }

    #[test]
    fn req_007_invalid_request_returns_no_partial_launch_preparation() {
        let fixture = Fixture::x64();
        let mut request = fixture.request();
        request.timeout = Some(Duration::ZERO);

        assert!(matches!(
            prepare_launch(&request, &[], &fixture.root),
            Err(LaunchPreparationError::Request(
                SandboxError::InvalidRequest {
                    field: RequestField::Timeout,
                    reason: InvalidRequestReason::OutOfRange,
                }
            ))
        ));
    }

    #[test]
    fn proc_029_unsupported_target_architecture_prevents_preparation() {
        let fixture = Fixture::x64();
        fs::write(&fixture.program, pe_image(0xAA64)).expect("fixture image must be replaced");

        assert!(matches!(
            prepare_launch(&fixture.request(), &[], &fixture.root),
            Err(LaunchPreparationError::UnsupportedArchitecture { machine: 0xAA64 })
        ));
    }

    #[test]
    fn req_001_prepared_paths_are_the_validated_request_paths() {
        let fixture = Fixture::x64();
        let request = fixture.request();
        let prepared =
            prepare_launch(&request, &[], &fixture.root).expect("valid request must prepare");

        assert_eq!(prepared.program(), Path::new(&request.program));
        assert_eq!(prepared.cwd(), Path::new(&request.cwd));
    }

    #[test]
    fn ipc_017_entropy_failure_returns_no_partial_launch_preparation() {
        let fixture = Fixture::x64();

        let result =
            prepare_launch_with_identity_factory(&fixture.request(), &[], &fixture.root, || {
                Err(LaunchPreparationError::ExecutionIdentity)
            });

        assert!(matches!(
            result,
            Err(LaunchPreparationError::ExecutionIdentity)
        ));
    }

    #[test]
    fn req_007_invalid_request_does_not_consume_execution_entropy() {
        let fixture = Fixture::x64();
        let mut request = fixture.request();
        request.timeout = Some(Duration::ZERO);
        let entropy_consumed = std::cell::Cell::new(false);

        let result = prepare_launch_with_identity_factory(&request, &[], &fixture.root, || {
            entropy_consumed.set(true);
            Err(LaunchPreparationError::ExecutionIdentity)
        });

        assert!(matches!(result, Err(LaunchPreparationError::Request(_))));
        assert!(!entropy_consumed.get());
    }

    #[test]
    fn req_001_preparation_atomically_owns_architecture_matched_components() {
        let fixture = Fixture::x64();
        fixture.install_components();

        let prepared = prepare_launch(&fixture.request(), &[], &fixture.root)
            .expect("valid request and components must prepare atomically");

        assert_eq!(
            prepared.launcher_component_path(),
            fixture.root.join("bolt-sandbox-launcher.exe")
        );
        assert_eq!(
            prepared.hook_component_path(),
            fixture.root.join("bolt-sandbox-x64.dll")
        );
        assert!(prepared.launcher_component_handle().metadata().is_ok());
        assert!(prepared.hook_component_handle().metadata().is_ok());
    }

    #[test]
    fn pkg_001_missing_component_does_not_consume_execution_entropy() {
        let fixture = Fixture::x64();
        fs::remove_file(fixture.root.join("bolt-sandbox-launcher.exe"))
            .expect("launcher fixture must be removed");
        let entropy_consumed = std::cell::Cell::new(false);

        let result =
            prepare_launch_with_identity_factory(&fixture.request(), &[], &fixture.root, || {
                entropy_consumed.set(true);
                Err(LaunchPreparationError::ExecutionIdentity)
            });

        assert!(matches!(result, Err(LaunchPreparationError::Component(_))));
        assert!(!entropy_consumed.get());
    }
}
