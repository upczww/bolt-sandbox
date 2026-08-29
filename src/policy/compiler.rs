use std::path::{Path, PathBuf};

use super::SandboxPolicy;

pub(crate) fn compile(policy: &SandboxPolicy, cwd: &Path) -> CompiledPolicy {
    let mut read_write = policy.filesystem.read_write.clone();
    if !read_write.iter().any(|root| root == cwd) {
        read_write.push(cwd.to_path_buf());
    }

    let compiled = CompiledPolicy {
        filesystem: CompiledFilesystemPolicy { read_write },
    };
    debug_assert!(compiled.filesystem.allows_read_write(cwd));
    compiled
}

pub(crate) struct CompiledPolicy {
    pub(crate) filesystem: CompiledFilesystemPolicy,
}

pub(crate) struct CompiledFilesystemPolicy {
    read_write: Vec<PathBuf>,
}

impl CompiledFilesystemPolicy {
    pub(crate) fn allows_read_write(&self, path: &Path) -> bool {
        self.read_write.iter().any(|root| path.starts_with(root))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn pol_001_default_policy_grants_cwd_read_write_recursively() {
        let cwd = Path::new(r"C:\work\project");

        let compiled = compile(&SandboxPolicy::default(), cwd);

        assert!(compiled.filesystem.allows_read_write(cwd));
        assert!(
            compiled
                .filesystem
                .allows_read_write(Path::new(r"C:\work\project\src\lib.rs"))
        );
    }

    #[test]
    fn pol_002_default_cwd_grant_does_not_grant_parent() {
        let cwd = Path::new(r"C:\work\project");

        let compiled = compile(&SandboxPolicy::default(), cwd);

        assert!(!compiled.filesystem.allows_read_write(Path::new(r"C:\work")));
        assert!(
            !compiled
                .filesystem
                .allows_read_write(Path::new(r"C:\work\sibling"))
        );
    }
}
