use std::{
    ffi::{OsStr, OsString},
    path::{Component, Path},
};

use super::SandboxPolicy;

pub(crate) fn compile(policy: &SandboxPolicy, cwd: &Path) -> CompiledPolicy {
    let mut filesystem = CompiledFilesystemPolicy::default();
    filesystem.add_rule(cwd, FilesystemRuleKind::ReadWrite);
    filesystem.add_rules(
        &policy.filesystem.read_write,
        FilesystemRuleKind::ReadWrite,
    );
    filesystem.add_rules(
        &policy.filesystem.read_only,
        FilesystemRuleKind::ReadOnly,
    );
    filesystem.add_rules(&policy.filesystem.deny, FilesystemRuleKind::Deny);
    filesystem.add_rules(
        &policy.filesystem.metadata_read,
        FilesystemRuleKind::MetadataRead,
    );
    filesystem.add_rules(
        &policy.filesystem.inherit_user,
        FilesystemRuleKind::InheritUser,
    );

    let compiled = CompiledPolicy { filesystem };
    debug_assert!(compiled.filesystem.allows_read_write(cwd));
    compiled
}

pub(crate) struct CompiledPolicy {
    pub(crate) filesystem: CompiledFilesystemPolicy,
}

#[derive(Default)]
pub(crate) struct CompiledFilesystemPolicy {
    rules: Vec<FilesystemRule>,
}

impl CompiledFilesystemPolicy {
    fn add_rules(&mut self, paths: &[std::path::PathBuf], kind: FilesystemRuleKind) {
        for path in paths {
            self.add_rule(path, kind);
        }
    }

    fn add_rule(&mut self, path: &Path, kind: FilesystemRuleKind) {
        let root = NormalizedPath::from_path(path);
        if self
            .rules
            .iter()
            .any(|rule| rule.kind == kind && rule.root == root)
        {
            return;
        }
        self.rules.push(FilesystemRule { root, kind });
    }

    pub(crate) fn allows_read_write(&self, path: &Path) -> bool {
        self.decide(path, FilesystemAccess::Write) == FilesystemDecision::Allow
    }

    pub(crate) fn decide(
        &self,
        path: &Path,
        access: FilesystemAccess,
    ) -> FilesystemDecision {
        let path = NormalizedPath::from_path(path);
        let matching_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.root.contains(&path))
            .collect();

        if matching_rules
            .iter()
            .any(|rule| rule.kind == FilesystemRuleKind::Deny)
        {
            return FilesystemDecision::Deny;
        }

        let Some(maximum_depth) = matching_rules.iter().map(|rule| rule.root.depth()).max() else {
            return FilesystemDecision::Deny;
        };

        let mut decision = FilesystemDecision::Allow;
        for rule in matching_rules
            .into_iter()
            .filter(|rule| rule.root.depth() == maximum_depth)
        {
            match rule.kind.decision(access) {
                FilesystemDecision::Deny => return FilesystemDecision::Deny,
                FilesystemDecision::InheritUser => {
                    decision = FilesystemDecision::InheritUser;
                }
                FilesystemDecision::Allow => {}
            }
        }
        decision
    }

    #[cfg(test)]
    fn read_write_rule_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.kind == FilesystemRuleKind::ReadWrite)
            .count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilesystemAccess {
    Read,
    Write,
    Metadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilesystemDecision {
    Allow,
    Deny,
    InheritUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilesystemRuleKind {
    ReadWrite,
    ReadOnly,
    Deny,
    MetadataRead,
    InheritUser,
}

impl FilesystemRuleKind {
    fn decision(self, access: FilesystemAccess) -> FilesystemDecision {
        match (self, access) {
            (Self::Deny, _) => FilesystemDecision::Deny,
            (Self::ReadWrite, _) => FilesystemDecision::Allow,
            (Self::ReadOnly, FilesystemAccess::Read | FilesystemAccess::Metadata)
            | (Self::MetadataRead, FilesystemAccess::Metadata) => FilesystemDecision::Allow,
            (Self::ReadOnly | Self::MetadataRead, FilesystemAccess::Write | FilesystemAccess::Read) => {
                FilesystemDecision::Deny
            }
            (Self::InheritUser, _) => FilesystemDecision::InheritUser,
        }
    }
}

struct FilesystemRule {
    root: NormalizedPath,
    kind: FilesystemRuleKind,
}

#[derive(Debug)]
struct NormalizedPath {
    components: Vec<NormalizedComponent>,
}

impl NormalizedPath {
    fn from_path(path: &Path) -> Self {
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => components.push(NormalizedComponent::Prefix(
                    prefix.as_os_str().to_os_string(),
                )),
                Component::RootDir => components.push(NormalizedComponent::Root),
                Component::CurDir => {}
                Component::ParentDir => {
                    if matches!(components.last(), Some(NormalizedComponent::Normal(_))) {
                        components.pop();
                    }
                }
                Component::Normal(value) => {
                    components.push(NormalizedComponent::Normal(value.to_os_string()));
                }
            }
        }
        Self { components }
    }

    fn contains(&self, candidate: &Self) -> bool {
        self.components.len() <= candidate.components.len()
            && self
                .components
                .iter()
                .zip(&candidate.components)
                .all(|(left, right)| left == right)
    }

    fn depth(&self) -> usize {
        self.components.len()
    }
}

impl PartialEq for NormalizedPath {
    fn eq(&self, other: &Self) -> bool {
        self.components.len() == other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(left, right)| left == right)
    }
}

impl Eq for NormalizedPath {}

#[derive(Debug)]
enum NormalizedComponent {
    Prefix(OsString),
    Root,
    Normal(OsString),
}

impl PartialEq for NormalizedComponent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Prefix(left), Self::Prefix(right))
            | (Self::Normal(left), Self::Normal(right)) => {
                os_str_eq_ignore_ascii_case(left, right)
            }
            (Self::Root, Self::Root) => true,
            _ => false,
        }
    }
}

impl Eq for NormalizedComponent {}

fn os_str_eq_ignore_ascii_case(left: &OsStr, right: &OsStr) -> bool {
    left == right
        || left
            .to_str()
            .zip(right.to_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn policy_with_filesystem(configure: impl FnOnce(&mut super::super::FilesystemPolicy)) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default();
        configure(&mut policy.filesystem);
        policy
    }

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

    #[test]
    fn pol_003_deny_overrides_cwd_read_write_grant() {
        let cwd = Path::new(r"C:\work\project");
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.deny.push(cwd.join("secrets"));
        });

        let compiled = compile(&policy, cwd);

        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\work\project\secrets\token.txt"),
                FilesystemAccess::Read,
            ),
            FilesystemDecision::Deny
        );
        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\work\project\secrets\token.txt"),
                FilesystemAccess::Write,
            ),
            FilesystemDecision::Deny
        );
    }

    #[test]
    fn pol_004_more_specific_read_write_overrides_read_only_grant() {
        let cwd = Path::new(r"C:\work\project");
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_only.push(PathBuf::from(r"C:\sdk"));
            filesystem
                .read_write
                .push(PathBuf::from(r"C:\sdk\cache"));
        });

        let compiled = compile(&policy, cwd);

        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\sdk\cache\artifact.bin"),
                FilesystemAccess::Write,
            ),
            FilesystemDecision::Allow
        );
        assert_eq!(
            compiled
                .filesystem
                .decide(Path::new(r"C:\sdk\bin\tool.exe"), FilesystemAccess::Read),
            FilesystemDecision::Allow
        );
        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\sdk\bin\tool.exe"),
                FilesystemAccess::Write,
            ),
            FilesystemDecision::Deny
        );
    }

    #[test]
    fn pol_012_equivalent_ascii_case_and_dot_paths_share_one_rule() {
        let cwd = Path::new(r"C:\Work\Project");
        let policy = policy_with_filesystem(|filesystem| {
            filesystem
                .read_write
                .push(PathBuf::from(r"c:\work\.\project\src\..\src"));
            filesystem
                .read_write
                .push(PathBuf::from(r"C:\WORK\PROJECT\src"));
        });

        let compiled = compile(&policy, cwd);

        assert_eq!(compiled.filesystem.read_write_rule_count(), 2);
        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\work\project\SRC\lib.rs"),
                FilesystemAccess::Write,
            ),
            FilesystemDecision::Allow
        );
    }

    #[test]
    fn fs_007_path_outside_every_grant_is_denied() {
        let compiled = compile(
            &SandboxPolicy::default(),
            Path::new(r"C:\work\project"),
        );

        assert_eq!(
            compiled
                .filesystem
                .decide(Path::new(r"C:\outside\file.txt"), FilesystemAccess::Read),
            FilesystemDecision::Deny
        );
    }
}
