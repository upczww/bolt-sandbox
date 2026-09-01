use std::{
    fs::{File, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use super::architecture::{ImageArchitecture, detect_image_architecture_from_reader};
use super::component_manifest::{ManifestError, read_manifest, verify_component};

const LAUNCHER_NAME: &str = "bolt-sandbox-launcher.exe";
const X86_LAUNCHER_NAME: &str = "bolt-sandbox-launcher-x86.exe";
const X86_HOOK_NAME: &str = "bolt-sandbox-x86.dll";
const X64_HOOK_NAME: &str = "bolt-sandbox-x64.dll";
const FILE_SHARE_READ: u32 = 1;

pub(super) fn open_read_lease(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

pub(super) struct OpenedComponents {
    launcher_path: PathBuf,
    hook_path: PathBuf,
    launcher_handle: File,
    hook_handle: File,
}

impl OpenedComponents {
    pub(super) fn launcher_path(&self) -> &Path {
        &self.launcher_path
    }

    pub(super) fn hook_path(&self) -> &Path {
        &self.hook_path
    }

    pub(super) const fn launcher_handle(&self) -> &File {
        &self.launcher_handle
    }

    pub(super) const fn hook_handle(&self) -> &File {
        &self.hook_handle
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ComponentOpenError {
    RootNotAbsolute,
    LauncherOpen,
    HookOpen,
    InvalidLauncherImage,
    InvalidHookImage,
    LauncherArchitectureMismatch,
    HookArchitectureMismatch,
    ManifestOpen,
    InvalidManifest,
    LauncherHashMismatch,
    HookHashMismatch,
    ManifestHashMismatch,
}

pub(super) fn open_components(
    root: &Path,
    target_architecture: ImageArchitecture,
) -> Result<OpenedComponents, ComponentOpenError> {
    open_components_with_manifest_digest(root, target_architecture, None)
}

pub(super) fn open_components_with_manifest_digest(
    root: &Path,
    target_architecture: ImageArchitecture,
    expected_manifest_digest: Option<&[u8; 32]>,
) -> Result<OpenedComponents, ComponentOpenError> {
    if !root.is_absolute() {
        return Err(ComponentOpenError::RootNotAbsolute);
    }

    let launcher_path = root.join(match target_architecture {
        ImageArchitecture::X86 => X86_LAUNCHER_NAME,
        ImageArchitecture::X64 => LAUNCHER_NAME,
    });
    let hook_path = root.join(match target_architecture {
        ImageArchitecture::X86 => X86_HOOK_NAME,
        ImageArchitecture::X64 => X64_HOOK_NAME,
    });
    let mut launcher_handle =
        open_read_lease(&launcher_path).map_err(|_| ComponentOpenError::LauncherOpen)?;
    let mut hook_handle = open_read_lease(&hook_path).map_err(|_| ComponentOpenError::HookOpen)?;
    let manifest =
        read_manifest(root, expected_manifest_digest).map_err(map_manifest_open_error)?;
    let launcher_name = launcher_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ComponentOpenError::InvalidManifest)?;
    let hook_name = hook_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ComponentOpenError::InvalidManifest)?;
    let launcher_record = manifest
        .get(launcher_name)
        .ok_or(ComponentOpenError::InvalidManifest)?;
    let hook_record = manifest
        .get(hook_name)
        .ok_or(ComponentOpenError::InvalidManifest)?;
    verify_component(&mut launcher_handle, launcher_record)
        .map_err(|_| ComponentOpenError::LauncherHashMismatch)?;
    verify_component(&mut hook_handle, hook_record)
        .map_err(|_| ComponentOpenError::HookHashMismatch)?;

    let launcher_architecture = detect_image_architecture_from_reader(&mut launcher_handle)
        .map_err(|_| ComponentOpenError::InvalidLauncherImage)?;
    if launcher_architecture != target_architecture {
        return Err(ComponentOpenError::LauncherArchitectureMismatch);
    }
    let hook_architecture = detect_image_architecture_from_reader(&mut hook_handle)
        .map_err(|_| ComponentOpenError::InvalidHookImage)?;
    if hook_architecture != target_architecture {
        return Err(ComponentOpenError::HookArchitectureMismatch);
    }

    Ok(OpenedComponents {
        launcher_path,
        hook_path,
        launcher_handle,
        hook_handle,
    })
}

const fn map_manifest_open_error(error: ManifestError) -> ComponentOpenError {
    match error {
        ManifestError::Open => ComponentOpenError::ManifestOpen,
        ManifestError::DigestMismatch => ComponentOpenError::ManifestHashMismatch,
        ManifestError::Read
        | ManifestError::Invalid
        | ManifestError::LengthMismatch
        | ManifestError::HashMismatch => ComponentOpenError::InvalidManifest,
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "bolt-sandbox-components-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("fixture root must be created");
            fs::write(root.join(LAUNCHER_NAME), pe_image(0x8664))
                .expect("launcher fixture must be written");
            fs::write(root.join(X86_LAUNCHER_NAME), pe_image(0x014C))
                .expect("x86 launcher fixture must be written");
            fs::write(root.join(X86_HOOK_NAME), pe_image(0x014C))
                .expect("x86 hook fixture must be written");
            fs::write(root.join(X64_HOOK_NAME), pe_image(0x8664))
                .expect("x64 hook fixture must be written");
            write_manifest(&root);
            Self { root }
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

    fn write_manifest(root: &Path) {
        let names = [
            LAUNCHER_NAME,
            X86_LAUNCHER_NAME,
            X86_HOOK_NAME,
            X64_HOOK_NAME,
        ];
        let mut manifest = Vec::from(*b"BCM1");
        manifest.extend_from_slice(&1_u16.to_le_bytes());
        manifest.extend_from_slice(&16_u16.to_le_bytes());
        manifest.extend_from_slice(
            &u16::try_from(names.len())
                .expect("record count fits")
                .to_le_bytes(),
        );
        manifest.extend_from_slice(&crate::ipc::framing::PROTOCOL_VERSION.to_le_bytes());
        manifest.extend_from_slice(&[0; 4]);
        for name in names {
            let bytes = fs::read(root.join(name)).expect("component must be readable");
            manifest.extend_from_slice(
                &u16::try_from(name.len())
                    .expect("name length fits")
                    .to_le_bytes(),
            );
            manifest.extend_from_slice(&0_u16.to_le_bytes());
            manifest.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            manifest.extend_from_slice(&Sha256::digest(&bytes));
            manifest.extend_from_slice(name.as_bytes());
        }
        fs::write(root.join("bolt-sandbox-components.manifest"), manifest)
            .expect("manifest must be written");
    }

    #[test]
    fn proc_028_target_architecture_selects_only_the_matching_hook() {
        let fixture = Fixture::new();

        let x86 = open_components(&fixture.root, ImageArchitecture::X86)
            .expect("x86 components must open");
        let x64 = open_components(&fixture.root, ImageArchitecture::X64)
            .expect("x64 components must open");

        assert_eq!(x86.launcher_path(), fixture.root.join(X86_LAUNCHER_NAME));
        assert_eq!(x86.hook_path(), fixture.root.join(X86_HOOK_NAME));
        assert_eq!(x64.hook_path(), fixture.root.join(X64_HOOK_NAME));
    }

    #[test]
    fn pkg_009_opened_handles_are_bound_to_the_inspected_component_files() {
        let fixture = Fixture::new();
        let components = open_components(&fixture.root, ImageArchitecture::X64)
            .expect("valid components must open");
        let original = fixture.root.join("original-x64.dll");

        assert!(fs::rename(components.hook_path(), &original).is_err());
        assert!(components.launcher_handle().metadata().is_ok());
        assert!(components.hook_handle().metadata().is_ok());
        drop(components);
        fs::rename(fixture.root.join(X64_HOOK_NAME), &original)
            .expect("component may be moved only after the lease is released");
    }

    #[test]
    fn pkg_001_missing_or_wrong_architecture_components_fail_closed() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join(X86_LAUNCHER_NAME))
            .expect("x86 launcher must be removed");
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X86),
            Err(ComponentOpenError::LauncherOpen)
        ));
        fs::write(fixture.root.join(X86_LAUNCHER_NAME), pe_image(0x014C))
            .expect("x86 launcher fixture must be restored");

        fs::remove_file(fixture.root.join(X86_HOOK_NAME)).expect("x86 hook must be removed");
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X86),
            Err(ComponentOpenError::HookOpen)
        ));

        fs::write(fixture.root.join(X86_HOOK_NAME), pe_image(0x8664))
            .expect("wrong architecture hook must be written");
        write_manifest(&fixture.root);
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X86),
            Err(ComponentOpenError::HookArchitectureMismatch)
        ));

        fs::write(fixture.root.join(LAUNCHER_NAME), pe_image(0x014C))
            .expect("wrong architecture launcher must be written");
        write_manifest(&fixture.root);
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X64),
            Err(ComponentOpenError::LauncherArchitectureMismatch)
        ));
    }

    #[test]
    fn sec_002_manifest_hash_rejects_same_architecture_hook_tampering() {
        let fixture = Fixture::new();
        let hook = fixture.root.join(X64_HOOK_NAME);
        let mut tampered = fs::read(&hook).expect("hook must be readable");
        tampered.push(0xA5);
        fs::write(&hook, tampered).expect("tampered hook must be written");

        assert_eq!(
            open_components(&fixture.root, ImageArchitecture::X64).err(),
            Some(ComponentOpenError::HookHashMismatch)
        );
    }

    #[test]
    fn sec_001_host_manifest_digest_rejects_self_consistent_replacement() {
        let fixture = Fixture::new();
        let manifest_path = fixture
            .root
            .join(crate::runtime::component_manifest::MANIFEST_NAME);
        let expected: [u8; 32] =
            Sha256::digest(fs::read(&manifest_path).expect("manifest must be readable")).into();
        let hook = fixture.root.join(X64_HOOK_NAME);
        let mut tampered = fs::read(&hook).expect("hook must be readable");
        tampered.push(0x5A);
        fs::write(&hook, tampered).expect("tampered hook must be written");
        write_manifest(&fixture.root);

        assert_eq!(
            open_components_with_manifest_digest(
                &fixture.root,
                ImageArchitecture::X64,
                Some(&expected),
            )
            .err(),
            Some(ComponentOpenError::ManifestHashMismatch)
        );
    }

    #[test]
    fn pkg_011_relative_component_root_is_rejected_before_lookup() {
        assert!(matches!(
            open_components(Path::new("relative-components"), ImageArchitecture::X64),
            Err(ComponentOpenError::RootNotAbsolute)
        ));
    }
}
