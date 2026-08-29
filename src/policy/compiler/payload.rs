#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::policy::{
        ChildProcessPolicy, FilesystemPolicy, NetworkAllowList, NetworkPolicy, RegistryPolicy,
        SandboxPolicy,
    };

    const CWD: &str = r"C:\workspace";

    fn compile_policy(policy: &SandboxPolicy) -> super::super::CompiledPolicy {
        super::super::compile(policy, Path::new(CWD)).expect("test policy must compile")
    }

    fn equivalent_policy(reverse: bool) -> SandboxPolicy {
        let (read_only, domains, registry) = if reverse {
            (
                vec![
                    PathBuf::from(r"c:\DATA\Beta"),
                    PathBuf::from(r"C:\data\alpha"),
                ],
                vec!["EXAMPLE.ORG".to_owned(), "*.Example.COM".to_owned()],
                vec![
                    r"hklm\Software\Beta".to_owned(),
                    r"HKEY_LOCAL_MACHINE\software\Alpha".to_owned(),
                ],
            )
        } else {
            (
                vec![
                    PathBuf::from(r"c:\DATA\ALPHA"),
                    PathBuf::from(r"C:\data\beta"),
                ],
                vec!["*.example.com".to_owned(), "example.org".to_owned()],
                vec![
                    r"HKLM\SOFTWARE\ALPHA".to_owned(),
                    r"hkey_local_machine\Software\BETA".to_owned(),
                ],
            )
        };

        SandboxPolicy {
            filesystem: FilesystemPolicy {
                read_only,
                ..FilesystemPolicy::default()
            },
            registry: RegistryPolicy {
                read_only: registry,
                ..RegistryPolicy::default()
            },
            network: NetworkPolicy::AllowList(NetworkAllowList {
                domains,
                ..NetworkAllowList::default()
            }),
            child_processes: ChildProcessPolicy::Deny,
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn req_010_equivalent_policies_have_identical_payload_bytes_and_digest() {
        let first =
            seal(&compile_policy(&equivalent_policy(false))).expect("first policy must serialize");
        let second = seal(&compile_policy(&equivalent_policy(true)))
            .expect("equivalent policy must serialize");

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn req_011_unknown_policy_payload_version_is_rejected_before_integrity() {
        let mut encoded = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize")
            .into_bytes();
        let unsupported = POLICY_PAYLOAD_VERSION + 1;
        encoded[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&unsupported.to_le_bytes());

        assert_eq!(
            verify(&encoded),
            Err(PolicyPayloadError::UnsupportedVersion {
                expected: POLICY_PAYLOAD_VERSION,
                actual: unsupported,
            })
        );
    }

    #[test]
    fn pol_010_modified_compiled_payload_fails_integrity_check() {
        let mut encoded = seal(&compile_policy(&equivalent_policy(false)))
            .expect("policy must serialize")
            .into_bytes();
        *encoded.last_mut().expect("payload body must not be empty") ^= 0x80;

        assert_eq!(verify(&encoded), Err(PolicyPayloadError::IntegrityMismatch));
    }

    #[test]
    fn pol_010_truncated_and_oversized_payloads_fail_closed() {
        assert_eq!(
            verify(&[0; HEADER_LENGTH - 1]),
            Err(PolicyPayloadError::TruncatedHeader)
        );

        let mut encoded = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize")
            .into_bytes();
        let oversized =
            u32::try_from(MAX_POLICY_BODY_LENGTH + 1).expect("policy payload limit must fit u32");
        encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&oversized.to_le_bytes());

        assert_eq!(verify(&encoded), Err(PolicyPayloadError::PayloadTooLarge));
    }

    #[test]
    fn pol_010_verified_payload_borrows_the_immutable_body() {
        let sealed = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize");
        let verified = verify(sealed.as_bytes()).expect("sealed policy must verify");

        assert_eq!(verified.version(), POLICY_PAYLOAD_VERSION);
        assert_eq!(verified.body(), &sealed.as_bytes()[HEADER_LENGTH..]);
    }
}
