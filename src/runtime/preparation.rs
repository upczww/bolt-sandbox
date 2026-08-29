use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};

use super::architecture::{
    ImageArchitecture, ImageArchitectureError, detect_image_architecture_from_reader,
};
use crate::{
    SandboxError, SandboxRequest,
    policy::compiler::{self, payload},
    request,
};

#[derive(Debug)]
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LaunchPreparationError {
    Request(SandboxError),
    ProgramOpen,
    InvalidProgramImage,
    UnsupportedArchitecture { machine: u16 },
    PolicyPayload,
}

pub(super) fn prepare_launch(
    request_value: &SandboxRequest,
    credential_names: &[OsString],
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
    let policy_payload = payload::seal(&compiled_policy)
        .map_err(|_| LaunchPreparationError::PolicyPayload)?
        .into_bytes();

    let mut program_handle =
        File::open(&request_value.program).map_err(|_| LaunchPreparationError::ProgramOpen)?;
    let architecture = detect_image_architecture_from_reader(&mut program_handle)
        .map_err(map_architecture_error)?;

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
            Self { root, program }
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
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.program);
            let _ = fs::remove_dir(&self.root);
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

        let prepared = prepare_launch(&request, &[OsString::from("secret_token")])
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
    }

    #[test]
    fn req_007_invalid_request_returns_no_partial_launch_preparation() {
        let fixture = Fixture::x64();
        let mut request = fixture.request();
        request.timeout = Some(Duration::ZERO);

        assert!(matches!(
            prepare_launch(&request, &[]),
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
            prepare_launch(&fixture.request(), &[]),
            Err(LaunchPreparationError::UnsupportedArchitecture { machine: 0xAA64 })
        ));
    }

    #[test]
    fn req_001_prepared_paths_are_the_validated_request_paths() {
        let fixture = Fixture::x64();
        let request = fixture.request();
        let prepared = prepare_launch(&request, &[]).expect("valid request must prepare");

        assert_eq!(prepared.program(), Path::new(&request.program));
        assert_eq!(prepared.cwd(), Path::new(&request.cwd));
    }
}
