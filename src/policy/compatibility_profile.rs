use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

pub(crate) const PROFILE_NAME: &str = "bolt-sandbox-compatibility.profile";
pub(crate) const MAX_PROFILE_LENGTH: usize = 64 * 1_024;
pub(crate) const MAX_PROFILE_RULES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleKind {
    FilesystemReadOnly,
    RegistryReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Requiredness {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Base {
    SystemRoot,
    ProgramDirectory,
    ProgramFiles,
    ProgramFilesX86,
    ProgramData,
    LocalAppData,
    CargoHome,
    RustupHome,
    Absolute,
    Registry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileRule {
    kind: RuleKind,
    requiredness: Requiredness,
    base: Base,
    suffix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompatibilityProfile {
    rules: Vec<ProfileRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedProfile {
    pub(crate) filesystem_read_only: Vec<PathBuf>,
    pub(crate) registry_read_only: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolutionContext {
    pub(crate) system_root: Option<PathBuf>,
    pub(crate) program_dir: Option<PathBuf>,
    pub(crate) program_files: Option<PathBuf>,
    pub(crate) program_files_x86: Option<PathBuf>,
    pub(crate) program_data: Option<PathBuf>,
    pub(crate) local_app_data: Option<PathBuf>,
    pub(crate) cargo_home: Option<PathBuf>,
    pub(crate) rustup_home: Option<PathBuf>,
    pub(crate) cwd: PathBuf,
    pub(crate) mandatory_filesystem_denies: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileError {
    TooLarge,
    TooManyRules,
    InvalidEncoding,
    InvalidHeader,
    InvalidSyntax,
    RequiredBaseMissing,
    UnsafePath,
    DuplicateRule,
}

pub(crate) fn parse_profile(input: &[u8]) -> Result<CompatibilityProfile, ProfileError> {
    if input.len() > MAX_PROFILE_LENGTH {
        return Err(ProfileError::TooLarge);
    }
    if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(ProfileError::InvalidEncoding);
    }
    let text = std::str::from_utf8(input).map_err(|_| ProfileError::InvalidEncoding)?;
    let mut significant = text
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    if significant.next() != Some("BSC1") {
        return Err(ProfileError::InvalidHeader);
    }
    let mut rules = Vec::new();
    for line in significant {
        if rules.len() == MAX_PROFILE_RULES {
            return Err(ProfileError::TooManyRules);
        }
        let mut fields = line.split('|');
        let kind = match fields.next() {
            Some("fs-ro") => RuleKind::FilesystemReadOnly,
            Some("reg-ro") => RuleKind::RegistryReadOnly,
            _ => return Err(ProfileError::InvalidSyntax),
        };
        let requiredness = match fields.next() {
            Some("required") => Requiredness::Required,
            Some("optional") => Requiredness::Optional,
            _ => return Err(ProfileError::InvalidSyntax),
        };
        let base = match fields.next() {
            Some("system-root") => Base::SystemRoot,
            Some("program-dir") => Base::ProgramDirectory,
            Some("program-files") => Base::ProgramFiles,
            Some("program-files-x86") => Base::ProgramFilesX86,
            Some("program-data") => Base::ProgramData,
            Some("local-app-data") => Base::LocalAppData,
            Some("cargo-home") => Base::CargoHome,
            Some("rustup-home") => Base::RustupHome,
            Some("absolute") => Base::Absolute,
            Some("registry") => Base::Registry,
            _ => return Err(ProfileError::InvalidSyntax),
        };
        let suffix = fields.next().ok_or(ProfileError::InvalidSyntax)?;
        if fields.next().is_some()
            || suffix.is_empty()
            || (kind == RuleKind::FilesystemReadOnly && base == Base::Registry)
            || (kind == RuleKind::RegistryReadOnly && base != Base::Registry)
            || !validate_suffix(kind, base, suffix)
        {
            return Err(ProfileError::InvalidSyntax);
        }
        rules.push(ProfileRule {
            kind,
            requiredness,
            base,
            suffix: suffix.to_owned(),
        });
    }
    if rules.is_empty() {
        return Err(ProfileError::InvalidSyntax);
    }
    Ok(CompatibilityProfile { rules })
}

fn validate_suffix(kind: RuleKind, base: Base, suffix: &str) -> bool {
    if suffix.contains(['\0', '/', '*', '?']) || suffix.starts_with(r"\\?\") {
        return false;
    }
    if kind == RuleKind::RegistryReadOnly {
        return !suffix.contains(':');
    }
    if base == Base::Absolute {
        return !suffix.contains('*') && !suffix.contains('?');
    }
    if suffix.contains(':') || Path::new(suffix).is_absolute() {
        return false;
    }
    Path::new(suffix).components().all(|component| {
        !matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    })
}

pub(crate) fn resolve_profile(
    profile: &CompatibilityProfile,
    context: &ResolutionContext,
) -> Result<ResolvedProfile, ProfileError> {
    let mut filesystem_read_only = Vec::new();
    let mut registry_read_only = Vec::new();
    let mut filesystem_keys = BTreeSet::new();
    let mut registry_keys = BTreeSet::new();
    for rule in &profile.rules {
        match rule.kind {
            RuleKind::FilesystemReadOnly => {
                let Some(path) = resolve_filesystem_rule(rule, context)? else {
                    continue;
                };
                if is_root(&path)
                    || context
                        .mandatory_filesystem_denies
                        .iter()
                        .any(|deny| is_same_or_ancestor(&path, deny))
                {
                    return Err(ProfileError::UnsafePath);
                }
                let key = windows_path_key(&path);
                if !filesystem_keys.insert(key) {
                    return Err(ProfileError::DuplicateRule);
                }
                filesystem_read_only.push(path);
            }
            RuleKind::RegistryReadOnly => {
                let key = normalize_registry_key(&rule.suffix)?;
                let comparison = key.to_lowercase();
                if !registry_keys.insert(comparison) {
                    return Err(ProfileError::DuplicateRule);
                }
                registry_read_only.push(key);
            }
        }
    }
    Ok(ResolvedProfile {
        filesystem_read_only,
        registry_read_only,
    })
}

fn resolve_filesystem_rule(
    rule: &ProfileRule,
    context: &ResolutionContext,
) -> Result<Option<PathBuf>, ProfileError> {
    if rule.base == Base::Absolute {
        let path = normalize_absolute_path(Path::new(&rule.suffix))?;
        return Ok(Some(path));
    }
    let base = match rule.base {
        Base::SystemRoot => context.system_root.as_ref(),
        Base::ProgramDirectory => context.program_dir.as_ref(),
        Base::ProgramFiles => context.program_files.as_ref(),
        Base::ProgramFilesX86 => context.program_files_x86.as_ref(),
        Base::ProgramData => context.program_data.as_ref(),
        Base::LocalAppData => context.local_app_data.as_ref(),
        Base::CargoHome => context.cargo_home.as_ref(),
        Base::RustupHome => context.rustup_home.as_ref(),
        Base::Absolute | Base::Registry => None,
    };
    let Some(base) = base else {
        return match rule.requiredness {
            Requiredness::Required => Err(ProfileError::RequiredBaseMissing),
            Requiredness::Optional => Ok(None),
        };
    };
    let base = normalize_absolute_path(base)?;
    if rule.base == Base::ProgramDirectory && is_same_or_ancestor(&context.cwd, &base) {
        return Ok(None);
    }
    let joined = if rule.suffix == "." {
        base.clone()
    } else {
        base.join(&rule.suffix)
    };
    let normalized = normalize_absolute_path(&joined)?;
    if !is_same_or_ancestor(&base, &normalized) {
        return Err(ProfileError::UnsafePath);
    }
    Ok(Some(normalized))
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, ProfileError> {
    let encoded = path.to_string_lossy();
    if !path.is_absolute()
        || encoded.starts_with(r"\\?\")
        || encoded.starts_with(r"\\.\")
        || encoded.starts_with(r"\Device\")
    {
        return Err(ProfileError::UnsafePath);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(ProfileError::UnsafePath),
        }
    }
    if !normalized.is_absolute() {
        return Err(ProfileError::UnsafePath);
    }
    Ok(normalized)
}

fn is_root(path: &Path) -> bool {
    path.parent().is_none()
}

fn windows_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_lowercase()
}

fn is_same_or_ancestor(ancestor: &Path, path: &Path) -> bool {
    let ancestor = windows_path_key(ancestor);
    let path = windows_path_key(path);
    path == ancestor
        || path
            .strip_prefix(&ancestor)
            .is_some_and(|suffix| suffix.starts_with('\\') || suffix.starts_with('/'))
}

fn normalize_registry_key(input: &str) -> Result<String, ProfileError> {
    if input.contains(['/', '\0', ':', '*', '?']) {
        return Err(ProfileError::UnsafePath);
    }
    let trimmed = input.trim_end_matches('\\');
    let mut components = trimmed.split('\\');
    let root = components.next().ok_or(ProfileError::UnsafePath)?;
    let root = if root.eq_ignore_ascii_case("HKLM") {
        "HKLM"
    } else if root.eq_ignore_ascii_case("HKCU") {
        "HKCU"
    } else {
        return Err(ProfileError::UnsafePath);
    };
    let rest = components.collect::<Vec<_>>();
    if rest.is_empty()
        || rest
            .iter()
            .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(ProfileError::UnsafePath);
    }
    Ok(format!("{root}\\{}", rest.join("\\")))
}

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
        assert_eq!(
            resolved.filesystem_read_only,
            vec![PathBuf::from(r"C:\Windows")]
        );

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
            assert!(
                parse_profile(encoded.as_bytes()).is_err(),
                "accepted {suffix}"
            );
        }
    }

    #[test]
    fn compat_006_roots_and_mandatory_sensitive_ancestors_are_rejected() {
        let root = parse_profile(b"BSC1\nfs-ro|required|absolute|C:\\\n")
            .expect("absolute syntax must parse before resolution");
        assert_eq!(
            resolve_profile(&root, &context()),
            Err(ProfileError::UnsafePath)
        );

        let user_profile = parse_profile(b"BSC1\nfs-ro|required|absolute|C:\\Users\\agent\n")
            .expect("absolute syntax must parse before resolution");
        assert_eq!(
            resolve_profile(&user_profile, &context()),
            Err(ProfileError::UnsafePath)
        );
    }

    #[test]
    fn compat_007_program_directory_inside_cwd_is_skipped_and_root_is_rejected() {
        let profile =
            parse_profile(b"BSC1\nfs-ro|required|program-dir|.\n").expect("profile must parse");
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
