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
    }

    #[test]
    fn req_007_invalid_request_returns_no_partial_launch_preparation() {
        let fixture = Fixture::x64();
        let mut request = fixture.request();
        request.timeout = Some(Duration::ZERO);

        assert_eq!(
            prepare_launch(&request, &[]),
            Err(LaunchPreparationError::Request(
                SandboxError::InvalidRequest {
                    field: RequestField::Timeout,
                    reason: InvalidRequestReason::OutOfRange,
                }
            ))
        );
    }

    #[test]
    fn proc_029_unsupported_target_architecture_prevents_preparation() {
        let fixture = Fixture::x64();
        fs::write(&fixture.program, pe_image(0xAA64)).expect("fixture image must be replaced");

        assert_eq!(
            prepare_launch(&fixture.request(), &[]),
            Err(LaunchPreparationError::UnsupportedArchitecture { machine: 0xAA64 })
        );
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
