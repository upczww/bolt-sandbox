#[cfg(test)]
mod tests {
    use super::{DirectWorkspaceBackend, WorkspaceBackend, WorkspaceKind};

    #[test]
    fn ws_001_direct_backend_preserves_source_and_execution_root() {
        let root = std::env::current_dir().expect("test cwd must exist");
        let prepared = DirectWorkspaceBackend
            .prepare(&root)
            .expect("validated direct workspace must prepare");

        assert_eq!(prepared.kind(), WorkspaceKind::Direct);
        assert_eq!(prepared.source_root(), root);
        assert_eq!(prepared.execution_root(), root);
    }
}
