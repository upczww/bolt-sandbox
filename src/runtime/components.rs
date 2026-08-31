use std::{
    fs::File,
    path::{Path, PathBuf},
};

use super::architecture::{ImageArchitecture, detect_image_architecture_from_reader};

const LAUNCHER_NAME: &str = "bolt-sandbox-launcher.exe";
const X86_LAUNCHER_NAME: &str = "bolt-sandbox-launcher-x86.exe";
const X86_HOOK_NAME: &str = "bolt-sandbox-x86.dll";
const X64_HOOK_NAME: &str = "bolt-sandbox-x64.dll";

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
}

pub(super) fn open_components(
    root: &Path,
    target_architecture: ImageArchitecture,
) -> Result<OpenedComponents, ComponentOpenError> {
    if !root.is_absolute() {
        return Err(ComponentOpenError::RootNotAbsolute);
    }

    let launcher_path = root.join(LAUNCHER_NAME);
    let hook_path = root.join(match target_architecture {
        ImageArchitecture::X86 => X86_HOOK_NAME,
        ImageArchitecture::X64 => X64_HOOK_NAME,
    });
    let mut launcher_handle =
        File::open(&launcher_path).map_err(|_| ComponentOpenError::LauncherOpen)?;
    let mut hook_handle = File::open(&hook_path).map_err(|_| ComponentOpenError::HookOpen)?;

    let launcher_architecture = detect_image_architecture_from_reader(&mut launcher_handle)
        .map_err(|_| ComponentOpenError::InvalidLauncherImage)?;
    if launcher_architecture != ImageArchitecture::X64 {
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Seek, SeekFrom},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::runtime::architecture::detect_image_architecture_from_reader;

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

    #[test]
    fn proc_028_target_architecture_selects_only_the_matching_hook() {
        let fixture = Fixture::new();

        let x86 = open_components(&fixture.root, ImageArchitecture::X86)
            .expect("x86 components must open");
        let x64 = open_components(&fixture.root, ImageArchitecture::X64)
            .expect("x64 components must open");

        assert_eq!(
            x86.launcher_path(),
            fixture.root.join(X86_LAUNCHER_NAME)
        );
        assert_eq!(x86.hook_path(), fixture.root.join(X86_HOOK_NAME));
        assert_eq!(x64.hook_path(), fixture.root.join(X64_HOOK_NAME));
    }

    #[test]
    fn pkg_009_opened_handles_are_bound_to_the_inspected_component_files() {
        let fixture = Fixture::new();
        let mut components = open_components(&fixture.root, ImageArchitecture::X64)
            .expect("valid components must open");
        let original = fixture.root.join("original-x64.dll");

        fs::rename(components.hook_path(), &original).expect("open file must remain renameable");
        fs::write(components.hook_path(), pe_image(0x014C))
            .expect("lookalike replacement must be written");

        let handle = &mut components.hook_handle;
        handle
            .seek(SeekFrom::Start(0))
            .expect("retained handle must remain seekable");
        assert_eq!(
            detect_image_architecture_from_reader(handle),
            Ok(ImageArchitecture::X64)
        );
        assert!(components.launcher_handle().metadata().is_ok());
        assert!(components.hook_handle().metadata().is_ok());
    }

    #[test]
    fn pkg_001_missing_or_wrong_architecture_components_fail_closed() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join(X86_HOOK_NAME)).expect("x86 hook must be removed");
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X86),
            Err(ComponentOpenError::HookOpen)
        ));

        fs::write(fixture.root.join(X86_HOOK_NAME), pe_image(0x8664))
            .expect("wrong architecture hook must be written");
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X86),
            Err(ComponentOpenError::HookArchitectureMismatch)
        ));

        fs::write(fixture.root.join(LAUNCHER_NAME), pe_image(0x014C))
            .expect("wrong architecture launcher must be written");
        assert!(matches!(
            open_components(&fixture.root, ImageArchitecture::X64),
            Err(ComponentOpenError::LauncherArchitectureMismatch)
        ));
    }

    #[test]
    fn pkg_011_relative_component_root_is_rejected_before_lookup() {
        assert!(matches!(
            open_components(Path::new("relative-components"), ImageArchitecture::X64),
            Err(ComponentOpenError::RootNotAbsolute)
        ));
    }
}
