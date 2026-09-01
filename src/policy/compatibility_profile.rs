#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        MAX_PROFILE_LENGTH, MAX_PROFILE_RULES, ProfileError, ResolutionContext, parse_profile,
        resolve_profile,
    };

    fn context() -> ResolutionContext {
        ResolutionContext {
            system_root: Some(PathBuf::from(r"C:\Windows")),
            program_dir: Some(PathBuf::from(r"C:\Tools\Python")),
            program_files: Some(PathBuf::from(r"C:\Program Files")),
            program_files_x86: Some(PathBuf::from(r"C:\Program Files (x86)")),
            program_data: Some(PathBuf::from(r"C:\ProgramData")),
            local_app_data: Some(PathBuf::from(r"C:\Users\agent\AppData\Local")),
            cargo_home: Some(PathBuf::from(r"C:\Users\agent\.cargo")),
            rustup_home: Some(PathBuf::from(r"C:\Users\agent\.rustup")),
            cwd: PathBuf::from(r"C:\work\task"),
            mandatory_filesystem_denies: vec![PathBuf::from(r"C:\Users\agent\.ssh")],
        }
    }

    #[test]
    fn compat_001_lf_crlf_comments_and_order_have_one_canonical_result() {
        let lf = b"BSC1\n# baseline\nfs-ro|required|system-root|.\nfs-ro|optional|program-files|Common Files\\SSL\\openssl.cnf\nreg-ro|required|registry|HKLM\\SOFTWARE\\Microsoft\\Cryptography\n";
        let crlf = b"# baseline\r\nBSC1\r\nfs-ro|required|system-root|.\r\nfs-ro|optional|program-files|Common Files\\SSL\\openssl.cnf\r\nreg-ro|required|registry|HKLM\\SOFTWARE\\Microsoft\\Cryptography\r\n";
        assert_eq!(parse_profile(lf), parse_profile(crlf));
        assert!(parse_profile(lf).is_ok());
    }

    #[test]
    fn compat_002_invalid_encoding_header_and_grammar_fail_closed() {
        for input in [
            Vec::new(),
            vec![0xFF, 0xFE],
            b"\xEF\xBB\xBFBSC1\n".to_vec(),
            b"BSC2\n".to_vec(),
            b"BSC1\nfs-ro|required|system-root\n".to_vec(),
            b"BSC1\nfs-rw|required|system-root|.\n".to_vec(),
            b"BSC1\nfs-ro|maybe|system-root|.\n".to_vec(),
            b"BSC1\nfs-ro|required|unknown|.\n".to_vec(),
            b"BSC1\nreg-ro|required|system-root|HKLM\\SOFTWARE\n".to_vec(),
        ] {
            assert!(parse_profile(&input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn compat_003_profile_length_and_rule_count_are_bounded_before_resolution() {
        let oversized = vec![b'x'; MAX_PROFILE_LENGTH + 1];
        assert_eq!(parse_profile(&oversized), Err(ProfileError::TooLarge));

        let mut too_many = String::from("BSC1\n");
        for index in 0..=MAX_PROFILE_RULES {
            too_many.push_str(&format!(
                "fs-ro|optional|program-files|runtime\\file-{index}\n"
            ));
        }
        assert_eq!(
            parse_profile(too_many.as_bytes()),
            Err(ProfileError::TooManyRules)
        );
    }

    #[test]
    fn compat_004_required_missing_base_fails_and_optional_missing_base_skips() {
        let profile = parse_profile(
            b"BSC1\nfs-ro|required|system-root|.\nfs-ro|optional|cargo-home|registry\\src\n",
        )
        .expect("profile must parse");
        let mut roots = context();
        roots.cargo_home = None;
        let resolved = resolve_profile(&profile, &roots).expect("optional base must skip");
        assert_eq!(resolved.filesystem_read_only, vec![PathBuf::from(r"C:\Windows")]);

        roots.system_root = None;
        assert_eq!(
            resolve_profile(&profile, &roots),
            Err(ProfileError::RequiredBaseMissing)
        );
    }

    #[test]
    fn compat_005_relative_escape_glob_nul_and_alternate_stream_are_rejected() {
        for suffix in [
            r"..\secret",
            r"runtime\..\secret",
            r"runtime\*",
            "runtime\0secret",
            r"runtime\file.txt:secret",
            r"\\?\C:\Windows",
        ] {
            let encoded = format!("BSC1\nfs-ro|required|program-files|{suffix}\n");
            assert!(parse_profile(encoded.as_bytes()).is_err(), "accepted {suffix}");
        }
    }

    #[test]
    fn compat_006_roots_and_mandatory_sensitive_ancestors_are_rejected() {
        let root = parse_profile(b"BSC1\nfs-ro|required|absolute|C:\\\n")
            .expect("absolute syntax must parse before resolution");
        assert_eq!(resolve_profile(&root, &context()), Err(ProfileError::UnsafePath));

        let user_profile = parse_profile(
            b"BSC1\nfs-ro|required|absolute|C:\\Users\\agent\n",
        )
        .expect("absolute syntax must parse before resolution");
        assert_eq!(
            resolve_profile(&user_profile, &context()),
            Err(ProfileError::UnsafePath)
        );
    }

    #[test]
    fn compat_007_program_directory_inside_cwd_is_skipped_and_root_is_rejected() {
        let profile = parse_profile(b"BSC1\nfs-ro|required|program-dir|.\n")
            .expect("profile must parse");
        let mut roots = context();
        roots.program_dir = Some(PathBuf::from(r"C:\work\task\bin"));
        assert!(
            resolve_profile(&profile, &roots)
                .expect("workspace program must skip")
                .filesystem_read_only
                .is_empty()
        );

        roots.program_dir = Some(PathBuf::from(r"C:\"));
        assert_eq!(
            resolve_profile(&profile, &roots),
            Err(ProfileError::UnsafePath)
        );
    }

    #[test]
    fn compat_008_normalized_filesystem_and_registry_duplicates_are_rejected() {
        let filesystem = parse_profile(
            b"BSC1\nfs-ro|required|program-files|Runtime\nfs-ro|required|program-files|runtime\\.\n",
        )
        .expect("profile must parse");
        assert_eq!(
            resolve_profile(&filesystem, &context()),
            Err(ProfileError::DuplicateRule)
        );

        let registry = parse_profile(
            b"BSC1\nreg-ro|required|registry|HKLM\\SOFTWARE\\Vendor\nreg-ro|required|registry|hklm\\software\\vendor\\\n",
        )
        .expect("profile must parse");
        assert_eq!(
            resolve_profile(&registry, &context()),
            Err(ProfileError::DuplicateRule)
        );
    }

    #[test]
    fn compat_009_registry_roots_relative_keys_and_non_registry_bases_fail_closed() {
        for key in ["HKLM", "HKCU", r"SOFTWARE\\Vendor", r"HKCR\\Vendor"] {
            let encoded = format!("BSC1\nreg-ro|required|registry|{key}\n");
            let result = parse_profile(encoded.as_bytes())
                .and_then(|profile| resolve_profile(&profile, &context()));
            assert!(result.is_err(), "accepted {key}");
        }
    }

    #[test]
    fn compat_010_resolved_profile_contains_only_read_only_authority() {
        let profile = parse_profile(
            b"BSC1\nfs-ro|required|program-dir|.\nreg-ro|required|registry|HKLM\\SOFTWARE\\Microsoft\\Cryptography\n",
        )
        .expect("profile must parse");
        let resolved = resolve_profile(&profile, &context()).expect("profile must resolve");
        assert_eq!(
            resolved.filesystem_read_only,
            vec![PathBuf::from(r"C:\Tools\Python")]
        );
        assert_eq!(
            resolved.registry_read_only,
            vec![String::from(r"HKLM\SOFTWARE\Microsoft\Cryptography")]
        );
    }
}
