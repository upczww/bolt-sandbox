use std::{
    ffi::{OsStr, OsString},
    net::IpAddr,
    path::{Component, Path},
};

use super::{IpCidr, NetworkPolicy, PortRange, SandboxPolicy};
use crate::{InvalidRequestReason, RequestField, SandboxError};

pub(crate) fn compile(policy: &SandboxPolicy, cwd: &Path) -> Result<CompiledPolicy, SandboxError> {
    compile_with_mandatory_denies(policy, cwd, &[])
}

pub(crate) fn compile_with_mandatory_denies(
    policy: &SandboxPolicy,
    cwd: &Path,
    mandatory_denies: &[std::path::PathBuf],
) -> Result<CompiledPolicy, SandboxError> {
    let mut filesystem = CompiledFilesystemPolicy::default();
    filesystem.add_rule(cwd, FilesystemRuleKind::ReadWrite)?;
    filesystem.add_rules(&policy.filesystem.read_write, FilesystemRuleKind::ReadWrite)?;
    filesystem.add_rules(&policy.filesystem.read_only, FilesystemRuleKind::ReadOnly)?;
    filesystem.add_rules(&policy.filesystem.deny, FilesystemRuleKind::Deny)?;
    filesystem.add_rules(mandatory_denies, FilesystemRuleKind::Deny)?;
    filesystem.add_rules(
        &policy.filesystem.metadata_read,
        FilesystemRuleKind::MetadataRead,
    )?;
    filesystem.add_rules(
        &policy.filesystem.inherit_user,
        FilesystemRuleKind::InheritUser,
    )?;

    let network = compile_network_policy(&policy.network)?;
    let compiled = CompiledPolicy {
        filesystem,
        network,
    };
    debug_assert!(compiled.filesystem.allows_read_write(cwd));
    debug_assert_eq!(
        compiled.filesystem.decide(cwd, FilesystemAccess::Read),
        FilesystemDecision::Allow
    );
    debug_assert_eq!(
        compiled.filesystem.decide(cwd, FilesystemAccess::Metadata),
        FilesystemDecision::Allow
    );
    Ok(compiled)
}

pub(crate) struct CompiledPolicy {
    pub(crate) filesystem: CompiledFilesystemPolicy,
    #[allow(
        dead_code,
        reason = "compiled network policy is consumed by the network runtime in a later phase"
    )]
    pub(crate) network: CompiledNetworkPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "compiled network mode is consumed by the network runtime in a later phase"
)]
pub(crate) enum CompiledNetworkMode {
    Unrestricted,
    Denied,
    AllowList,
}

#[allow(
    dead_code,
    reason = "compiled network decisions are consumed by the network runtime in a later phase"
)]
pub(crate) enum CompiledNetworkPolicy {
    Unrestricted,
    Denied,
    AllowList(CompiledNetworkAllowList),
}

#[allow(
    dead_code,
    reason = "compiled network decisions are consumed by the network runtime in a later phase"
)]
impl CompiledNetworkPolicy {
    pub(crate) const fn mode(&self) -> CompiledNetworkMode {
        match self {
            Self::Unrestricted => CompiledNetworkMode::Unrestricted,
            Self::Denied => CompiledNetworkMode::Denied,
            Self::AllowList(_) => CompiledNetworkMode::AllowList,
        }
    }

    pub(crate) fn allows_domain(&self, domain: &str) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Denied => false,
            Self::AllowList(allow_list) => allow_list.allows_domain(domain),
        }
    }

    pub(crate) fn allows_address(&self, address: IpAddr) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Denied => false,
            Self::AllowList(allow_list) => allow_list
                .addresses
                .iter()
                .any(|cidr| cidr_contains(*cidr, address)),
        }
    }

    pub(crate) fn allows_port(&self, port: u16) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Denied => false,
            Self::AllowList(allow_list) => allow_list
                .ports
                .iter()
                .any(|range| (range.start..=range.end).contains(&port)),
        }
    }
}

#[allow(
    dead_code,
    reason = "compiled allow-list fields are consumed by the network runtime in a later phase"
)]
pub(crate) struct CompiledNetworkAllowList {
    domains: Vec<CompiledDomainRule>,
    addresses: Vec<IpCidr>,
    ports: Vec<PortRange>,
}

struct CompiledDomainRule {
    ascii_domain: String,
    wildcard: bool,
}

#[allow(
    dead_code,
    reason = "compiled domain matching is consumed by the network runtime in a later phase"
)]
impl CompiledNetworkAllowList {
    fn allows_domain(&self, domain: &str) -> bool {
        let Ok(candidate) = canonical_domain(domain, false) else {
            return false;
        };

        self.domains.iter().any(|rule| {
            if rule.wildcard {
                candidate
                    .strip_suffix(&rule.ascii_domain)
                    .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
            } else {
                candidate == rule.ascii_domain
            }
        })
    }
}

fn compile_network_policy(policy: &NetworkPolicy) -> Result<CompiledNetworkPolicy, SandboxError> {
    match policy {
        NetworkPolicy::Unrestricted => Ok(CompiledNetworkPolicy::Unrestricted),
        NetworkPolicy::Denied => Ok(CompiledNetworkPolicy::Denied),
        NetworkPolicy::AllowList(allow_list) => {
            let mut domains = Vec::with_capacity(allow_list.domains.len());
            for input in &allow_list.domains {
                let wildcard = input.starts_with("*.");
                let base = input.strip_prefix("*.").unwrap_or(input);
                domains.push(CompiledDomainRule {
                    ascii_domain: canonical_domain(base, true)?,
                    wildcard,
                });
            }
            domains.sort_by(|left, right| {
                left.ascii_domain
                    .cmp(&right.ascii_domain)
                    .then(left.wildcard.cmp(&right.wildcard))
            });
            domains.dedup_by(|left, right| {
                left.ascii_domain == right.ascii_domain && left.wildcard == right.wildcard
            });

            let addresses = compile_cidrs(&allow_list.addresses)?;
            let ports = compile_port_ranges(&allow_list.ports)?;
            Ok(CompiledNetworkPolicy::AllowList(CompiledNetworkAllowList {
                domains,
                addresses,
                ports,
            }))
        }
    }
}

fn canonical_domain(domain: &str, allow_wildcard_input: bool) -> Result<String, SandboxError> {
    if domain.is_empty()
        || domain.ends_with('.')
        || domain.contains("//")
        || domain.contains('/')
        || domain.contains('\\')
        || domain.contains(':')
        || domain.contains('*')
        || (!allow_wildcard_input && domain.starts_with("*."))
    {
        return Err(invalid_network_policy(
            InvalidRequestReason::InvalidCharacter,
        ));
    }

    let mut ascii = idna::domain_to_ascii_strict(domain)
        .map_err(|_| invalid_network_policy(InvalidRequestReason::InvalidCharacter))?;
    ascii.make_ascii_lowercase();
    if ascii.len() > 253
        || ascii
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        || ascii.parse::<IpAddr>().is_ok()
    {
        return Err(invalid_network_policy(
            InvalidRequestReason::InvalidCharacter,
        ));
    }
    Ok(ascii)
}

fn compile_cidrs(cidrs: &[IpCidr]) -> Result<Vec<IpCidr>, SandboxError> {
    let mut compiled = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        if !cidr_is_canonical(*cidr) {
            return Err(invalid_network_policy(
                InvalidRequestReason::InvalidCharacter,
            ));
        }
        compiled.push(*cidr);
    }
    compiled.sort_unstable();
    compiled.dedup();
    Ok(compiled)
}

fn cidr_is_canonical(cidr: IpCidr) -> bool {
    match cidr.address {
        IpAddr::V4(address) if cidr.prefix_length <= 32 => {
            let mask = prefix_mask_v4(cidr.prefix_length);
            u32::from(address) & mask == u32::from(address)
        }
        IpAddr::V6(address) if cidr.prefix_length <= 128 => {
            let mask = prefix_mask_v6(cidr.prefix_length);
            u128::from(address) & mask == u128::from(address)
        }
        IpAddr::V4(_) | IpAddr::V6(_) => false,
    }
}

#[allow(
    dead_code,
    reason = "CIDR decisions are consumed by the network runtime in a later phase"
)]
fn cidr_contains(cidr: IpCidr, candidate: IpAddr) -> bool {
    match (cidr.address, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            let mask = prefix_mask_v4(cidr.prefix_length);
            u32::from(network) == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            let mask = prefix_mask_v6(cidr.prefix_length);
            u128::from(network) == u128::from(candidate) & mask
        }
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

fn prefix_mask_v4(prefix_length: u8) -> u32 {
    u32::MAX
        .checked_shl(u32::from(32 - prefix_length))
        .unwrap_or(0)
}

fn prefix_mask_v6(prefix_length: u8) -> u128 {
    u128::MAX
        .checked_shl(u32::from(128 - prefix_length))
        .unwrap_or(0)
}

fn compile_port_ranges(ranges: &[PortRange]) -> Result<Vec<PortRange>, SandboxError> {
    let mut compiled = ranges.to_vec();
    for range in &compiled {
        if range.start == 0 || range.start > range.end {
            return Err(invalid_network_policy(
                InvalidRequestReason::InvalidCharacter,
            ));
        }
    }
    compiled.sort_unstable();
    compiled.dedup();
    if compiled.windows(2).any(|pair| pair[1].start <= pair[0].end) {
        return Err(invalid_network_policy(
            InvalidRequestReason::ConflictingRules,
        ));
    }
    Ok(compiled)
}

#[derive(Default)]
pub(crate) struct CompiledFilesystemPolicy {
    rules: Vec<FilesystemRule>,
}

impl CompiledFilesystemPolicy {
    fn add_rules(
        &mut self,
        paths: &[std::path::PathBuf],
        kind: FilesystemRuleKind,
    ) -> Result<(), SandboxError> {
        for path in paths {
            self.add_rule(path, kind)?;
        }
        Ok(())
    }

    fn add_rule(&mut self, path: &Path, kind: FilesystemRuleKind) -> Result<(), SandboxError> {
        let root = NormalizedPath::from_path(path)?;
        for existing in self.rules.iter().filter(|rule| rule.root == root) {
            if existing.kind == kind {
                return Ok(());
            }
            if existing.kind != FilesystemRuleKind::Deny && kind != FilesystemRuleKind::Deny {
                return Err(invalid_filesystem_policy(
                    InvalidRequestReason::ConflictingRules,
                ));
            }
        }
        self.rules.push(FilesystemRule { root, kind });
        Ok(())
    }

    pub(crate) fn allows_read_write(&self, path: &Path) -> bool {
        self.decide(path, FilesystemAccess::Write) == FilesystemDecision::Allow
    }

    pub(crate) fn decide(&self, path: &Path, access: FilesystemAccess) -> FilesystemDecision {
        let Ok(path) = NormalizedPath::from_path(path) else {
            return FilesystemDecision::Deny;
        };
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

    #[cfg(test)]
    fn deny_rule_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.kind == FilesystemRuleKind::Deny)
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
        match self {
            Self::Deny => FilesystemDecision::Deny,
            Self::ReadWrite => FilesystemDecision::Allow,
            Self::ReadOnly => match access {
                FilesystemAccess::Read | FilesystemAccess::Metadata => FilesystemDecision::Allow,
                FilesystemAccess::Write => FilesystemDecision::Deny,
            },
            Self::MetadataRead => match access {
                FilesystemAccess::Metadata => FilesystemDecision::Allow,
                FilesystemAccess::Read | FilesystemAccess::Write => FilesystemDecision::Deny,
            },
            Self::InheritUser => FilesystemDecision::InheritUser,
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
    fn from_path(path: &Path) -> Result<Self, SandboxError> {
        if !path.is_absolute() {
            return Err(invalid_filesystem_policy(
                InvalidRequestReason::MustBeAbsolute,
            ));
        }

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
                    } else {
                        return Err(invalid_filesystem_policy(InvalidRequestReason::EscapesRoot));
                    }
                }
                Component::Normal(value) => {
                    components.push(NormalizedComponent::Normal(value.to_os_string()));
                }
            }
        }
        Ok(Self { components })
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
            | (Self::Normal(left), Self::Normal(right)) => os_str_eq_ignore_ascii_case(left, right),
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

fn invalid_filesystem_policy(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::FilesystemPolicy,
        reason,
    }
}

const fn invalid_network_policy(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::NetworkPolicy,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::{Path, PathBuf},
    };

    use super::*;
    use crate::{
        InvalidRequestReason, IpCidr, NetworkAllowList, NetworkPolicy, PortRange, RequestField,
        SandboxError,
    };

    fn policy_with_filesystem(
        configure: impl FnOnce(&mut super::super::FilesystemPolicy),
    ) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default();
        configure(&mut policy.filesystem);
        policy
    }

    fn policy_with_network(network: NetworkPolicy) -> SandboxPolicy {
        SandboxPolicy {
            network,
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn pol_001_default_policy_grants_cwd_read_write_recursively() {
        let cwd = Path::new(r"C:\work\project");

        let compiled =
            compile(&SandboxPolicy::default(), cwd).expect("default policy must compile");

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

        let compiled =
            compile(&SandboxPolicy::default(), cwd).expect("default policy must compile");

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

        let compiled = compile(&policy, cwd).expect("deny overlap must compile");

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
            filesystem.read_write.push(PathBuf::from(r"C:\sdk\cache"));
        });

        let compiled = compile(&policy, cwd).expect("different-depth grants must compile");

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
            compiled
                .filesystem
                .decide(Path::new(r"C:\sdk\bin\tool.exe"), FilesystemAccess::Write,),
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

        let compiled = compile(&policy, cwd).expect("equivalent rules must compile");

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
        let compiled = compile(&SandboxPolicy::default(), Path::new(r"C:\work\project"))
            .expect("default policy must compile");

        assert_eq!(
            compiled
                .filesystem
                .decide(Path::new(r"C:\outside\file.txt"), FilesystemAccess::Read),
            FilesystemDecision::Deny
        );
    }

    #[test]
    fn pol_013_relative_filesystem_rule_is_rejected() {
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_write.push(PathBuf::from("relative"));
        });

        let result = compile(&policy, Path::new(r"C:\work\project"));

        assert!(matches!(
            result,
            Err(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::MustBeAbsolute,
            })
        ));
    }

    #[test]
    fn pol_013_parent_component_cannot_escape_volume_root() {
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_only.push(PathBuf::from(r"C:\..\outside"));
        });

        let result = compile(&policy, Path::new(r"C:\work\project"));

        assert!(matches!(
            result,
            Err(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::EscapesRoot,
            })
        ));
    }

    #[test]
    fn pol_012_conflicting_grants_for_same_normalized_root_are_rejected() {
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_only.push(PathBuf::from(r"C:\SDK\.\cache"));
            filesystem.read_write.push(PathBuf::from(r"c:\sdk\cache"));
        });

        let result = compile(&policy, Path::new(r"C:\work\project"));

        assert!(matches!(
            result,
            Err(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::ConflictingRules,
            })
        ));
    }

    #[test]
    fn pol_007_mandatory_deny_overrides_untrusted_broad_grant() {
        let cwd = Path::new(r"C:\work\project");
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_write.push(PathBuf::from(r"C:\Users\Alice"));
        });

        let compiled =
            compile_with_mandatory_denies(&policy, cwd, &[PathBuf::from(r"C:\Users\Alice\.ssh")])
                .expect("mandatory deny must coexist with broad grant");

        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\Users\Alice\.ssh\id_ed25519"),
                FilesystemAccess::Read,
            ),
            FilesystemDecision::Deny
        );
        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\Users\Alice\workspace\source.rs"),
                FilesystemAccess::Write,
            ),
            FilesystemDecision::Allow
        );
    }

    #[test]
    fn pol_024_mandatory_deny_aliases_are_canonicalized_once() {
        let compiled = compile_with_mandatory_denies(
            &SandboxPolicy::default(),
            Path::new(r"C:\work\project"),
            &[
                PathBuf::from(r"C:\Users\Alice\.ssh"),
                PathBuf::from(r"c:\users\alice\.\.SSH"),
            ],
        )
        .expect("equivalent mandatory denies must compile");

        assert_eq!(compiled.filesystem.deny_rule_count(), 1);
    }

    #[test]
    fn pol_015_default_network_mode_compiles_explicitly() {
        let compiled = compile(&SandboxPolicy::default(), Path::new(r"C:\work\project"))
            .expect("default policy must compile");

        assert_eq!(compiled.network.mode(), CompiledNetworkMode::Unrestricted);
    }

    #[test]
    fn pol_017_018_019_allow_list_compiles_canonical_decisions() {
        let policy = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
            domains: vec!["Example.COM".into(), "*.münich.example".into()],
            addresses: vec![
                IpCidr {
                    address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    prefix_length: 24,
                },
                IpCidr {
                    address: IpAddr::V6("2001:db8::".parse().expect("valid IPv6")),
                    prefix_length: 32,
                },
            ],
            ports: vec![
                PortRange {
                    start: 443,
                    end: 443,
                },
                PortRange {
                    start: 8_000,
                    end: 8_080,
                },
            ],
        }));

        let compiled =
            compile(&policy, Path::new(r"C:\work\project")).expect("valid allow list must compile");

        assert!(compiled.network.allows_domain("example.com"));
        assert!(compiled.network.allows_domain("shop.münich.example"));
        assert!(!compiled.network.allows_domain("münich.example"));
        assert!(!compiled.network.allows_domain("evil-example.com"));
        assert!(
            compiled
                .network
                .allows_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)))
        );
        assert!(
            !compiled
                .network
                .allows_address(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 0)))
        );
        assert!(compiled.network.allows_port(443));
        assert!(compiled.network.allows_port(8_080));
        assert!(!compiled.network.allows_port(8_081));
    }

    #[test]
    fn pol_017_malformed_domain_rules_are_rejected() {
        for domain in [
            "",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "example.com.",
            "*example.com",
            "*.example..com",
        ] {
            let policy = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
                domains: vec![domain.into()],
                ..NetworkAllowList::default()
            }));

            assert!(matches!(
                compile(&policy, Path::new(r"C:\work\project")),
                Err(SandboxError::InvalidRequest {
                    field: RequestField::NetworkPolicy,
                    reason: InvalidRequestReason::InvalidCharacter,
                })
            ));
        }
    }

    #[test]
    fn pol_018_noncanonical_or_invalid_cidr_is_rejected() {
        for cidr in [
            IpCidr {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                prefix_length: 24,
            },
            IpCidr {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 33,
            },
            IpCidr {
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 129,
            },
        ] {
            let policy = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
                addresses: vec![cidr],
                ..NetworkAllowList::default()
            }));

            assert!(matches!(
                compile(&policy, Path::new(r"C:\work\project")),
                Err(SandboxError::InvalidRequest {
                    field: RequestField::NetworkPolicy,
                    reason: InvalidRequestReason::InvalidCharacter,
                })
            ));
        }
    }

    #[test]
    fn pol_019_invalid_or_overlapping_port_ranges_are_rejected() {
        for ports in [
            vec![PortRange { start: 0, end: 80 }],
            vec![PortRange {
                start: 100,
                end: 99,
            }],
            vec![
                PortRange {
                    start: 8000,
                    end: 8100,
                },
                PortRange {
                    start: 8050,
                    end: 8200,
                },
            ],
        ] {
            let policy = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
                ports,
                ..NetworkAllowList::default()
            }));

            assert!(compile(&policy, Path::new(r"C:\work\project")).is_err());
        }
    }
}
