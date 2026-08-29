#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::SandboxPolicy;

    #[test]
    fn pol_001_default_policy_grants_cwd_read_write_recursively() {
        let cwd = Path::new(r"C:\work\project");

        let compiled = compile(&SandboxPolicy::default(), cwd);

        assert!(compiled.filesystem.allows_read_write(cwd));
        assert!(compiled
            .filesystem
            .allows_read_write(Path::new(r"C:\work\project\src\lib.rs")));
    }

    #[test]
    fn pol_002_default_cwd_grant_does_not_grant_parent() {
        let cwd = Path::new(r"C:\work\project");

        let compiled = compile(&SandboxPolicy::default(), cwd);

        assert!(!compiled
            .filesystem
            .allows_read_write(Path::new(r"C:\work")));
        assert!(!compiled
            .filesystem
            .allows_read_write(Path::new(r"C:\work\sibling")));
    }
}
