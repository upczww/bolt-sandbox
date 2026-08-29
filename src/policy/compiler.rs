use std::{
    ffi::{OsStr, OsString},
    net::IpAddr,
    path::{Component, Path},
};

use super::{IpCidr, NetworkAllowList, NetworkPolicy, PortRange, RegistryPolicy, SandboxPolicy};
use crate::{InvalidRequestReason, RequestField, SandboxError};

const MAX_NETWORK_RULES_PER_CATEGORY: usize = 1_024;
const MAX_TOTAL_NETWORK_RULES: usize = 2_048;

pub(crate) fn compile(policy: &SandboxPolicy, cwd: &Path) -> Result<CompiledPolicy, SandboxError> {
    compile_with_mandatory_denies(policy, cwd, &[])
}

pub(crate) fn compile_with_mandatory_denies(
    policy: &SandboxPolicy,
    cwd: &Path,
    mandatory_denies: &[std::path::PathBuf],
) -> Result<CompiledPolicy, SandboxError> {
    compile_with_security_denies(policy, cwd, mandatory_denies, &[])
}

pub(crate) fn compile_with_security_denies(
    policy: &SandboxPolicy,
    cwd: &Path,
    mandatory_filesystem_denies: &[std::path::PathBuf],
    mandatory_registry_denies: &[String],
) -> Result<CompiledPolicy, SandboxError> {
    let mut filesystem = CompiledFilesystemPolicy::default();
    filesystem.add_rule(cwd, FilesystemRuleKind::ReadWrite)?;
    filesystem.add_rules(&policy.filesystem.read_write, FilesystemRuleKind::ReadWrite)?;
    filesystem.add_rules(&policy.filesystem.read_only, FilesystemRuleKind::ReadOnly)?;
    filesystem.add_rules(&policy.filesystem.deny, FilesystemRuleKind::Deny)?;
    filesystem.add_rules(mandatory_filesystem_denies, FilesystemRuleKind::Deny)?;
    filesystem.add_rules(
        &policy.filesystem.metadata_read,
        FilesystemRuleKind::MetadataRead,
    )?;
    filesystem.add_rules(
        &policy.filesystem.inherit_user,
        FilesystemRuleKind::InheritUser,
    )?;

    let network = compile_network_policy(&policy.network)?;
    let registry = compile_registry_policy(&policy.registry, mandatory_registry_denies)?;
    let compiled = CompiledPolicy {
        filesystem,
        network,
        registry,
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
    #[allow(
        dead_code,
        reason = "compiled registry policy is consumed by the registry runtime in a later phase"
    )]
    pub(crate) registry: CompiledRegistryPolicy,
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
#[derive(Debug, Eq, PartialEq)]
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
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledNetworkAllowList {
    domains: Vec<CompiledDomainRule>,
    addresses: Vec<IpCidr>,
    ports: Vec<PortRange>,
}

#[derive(Debug, Eq, PartialEq)]
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
            validate_network_rule_counts(allow_list)?;
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

fn validate_network_rule_counts(allow_list: &NetworkAllowList) -> Result<(), SandboxError> {
    if allow_list.domains.len() > MAX_NETWORK_RULES_PER_CATEGORY
        || allow_list.addresses.len() > MAX_NETWORK_RULES_PER_CATEGORY
        || allow_list.ports.len() > MAX_NETWORK_RULES_PER_CATEGORY
    {
        return Err(invalid_network_policy(InvalidRequestReason::TooManyItems));
    }

    let total = allow_list
        .domains
        .len()
        .checked_add(allow_list.addresses.len())
        .and_then(|count| count.checked_add(allow_list.ports.len()))
        .ok_or_else(|| invalid_network_policy(InvalidRequestReason::TooManyItems))?;
    if total > MAX_TOTAL_NETWORK_RULES {
        return Err(invalid_network_policy(InvalidRequestReason::TooManyItems));
    }
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "registry access classes are consumed by the registry runtime in a later phase"
)]
pub(crate) enum RegistryAccess {
    Read,
    Write,
    Enumerate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryDecision {
    Allow,
    Deny,
    InheritUser,
}

#[allow(
    dead_code,
    reason = "compiled registry decisions are consumed by the registry runtime in a later phase"
)]
pub(crate) struct CompiledRegistryPolicy {
    rules: Vec<RegistryRule>,
}

#[allow(
    dead_code,
    reason = "compiled registry decisions are consumed by the registry runtime in a later phase"
)]
impl CompiledRegistryPolicy {
    pub(crate) fn decide(&self, key: &str, access: RegistryAccess) -> RegistryDecision {
        let Ok(key) = NormalizedRegistryKey::parse(key) else {
            return RegistryDecision::Deny;
        };
        let matching_rules = self
            .rules
            .iter()
            .filter(|rule| rule.root.contains(&key))
            .collect::<Vec<_>>();
        if matching_rules
            .iter()
            .any(|rule| rule.kind == RegistryRuleKind::NoAccess)
        {
            return RegistryDecision::Deny;
        }

        let Some(maximum_depth) = matching_rules.iter().map(|rule| rule.root.depth()).max() else {
            return RegistryDecision::Deny;
        };
        matching_rules
            .into_iter()
            .find(|rule| rule.root.depth() == maximum_depth)
            .map_or(RegistryDecision::Deny, |rule| rule.kind.decision(access))
    }

    #[cfg(test)]
    fn read_only_rule_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.kind == RegistryRuleKind::ReadOnly)
            .count()
    }
}

fn compile_registry_policy(
    policy: &RegistryPolicy,
    mandatory_denies: &[String],
) -> Result<CompiledRegistryPolicy, SandboxError> {
    let mut compiled = RegistryPolicyBuilder::default();
    compiled.add_rules(&policy.read_write, RegistryRuleKind::ReadWrite)?;
    compiled.add_rules(&policy.read_only, RegistryRuleKind::ReadOnly)?;
    compiled.add_rules(&policy.no_access, RegistryRuleKind::NoAccess)?;
    compiled.add_rules(mandatory_denies, RegistryRuleKind::NoAccess)?;
    compiled.add_rules(&policy.inherit_user, RegistryRuleKind::InheritUser)?;
    compiled
        .rules
        .sort_by(|left, right| left.root.cmp(&right.root).then(left.kind.cmp(&right.kind)));
    Ok(CompiledRegistryPolicy {
        rules: compiled.rules,
    })
}

#[derive(Default)]
struct RegistryPolicyBuilder {
    rules: Vec<RegistryRule>,
}

impl RegistryPolicyBuilder {
    fn add_rules(&mut self, keys: &[String], kind: RegistryRuleKind) -> Result<(), SandboxError> {
        for key in keys {
            self.add_rule(key, kind)?;
        }
        Ok(())
    }

    fn add_rule(&mut self, key: &str, kind: RegistryRuleKind) -> Result<(), SandboxError> {
        let root = NormalizedRegistryKey::parse(key)?;
        for existing in self.rules.iter().filter(|rule| rule.root == root) {
            if existing.kind == kind {
                return Ok(());
            }
            if existing.kind != RegistryRuleKind::NoAccess && kind != RegistryRuleKind::NoAccess {
                return Err(invalid_registry_policy(
                    InvalidRequestReason::ConflictingRules,
                ));
            }
        }
        self.rules.push(RegistryRule { root, kind });
        Ok(())
    }
}

struct RegistryRule {
    root: NormalizedRegistryKey,
    kind: RegistryRuleKind,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RegistryRuleKind {
    NoAccess,
    ReadOnly,
    InheritUser,
    ReadWrite,
}

impl RegistryRuleKind {
    const fn decision(self, access: RegistryAccess) -> RegistryDecision {
        match self {
            Self::NoAccess => RegistryDecision::Deny,
            Self::ReadOnly => match access {
                RegistryAccess::Read | RegistryAccess::Enumerate => RegistryDecision::Allow,
                RegistryAccess::Write => RegistryDecision::Deny,
            },
            Self::InheritUser => RegistryDecision::InheritUser,
            Self::ReadWrite => RegistryDecision::Allow,
        }
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NormalizedRegistryKey {
    hive: RegistryHive,
    components: Vec<String>,
}

impl NormalizedRegistryKey {
    fn parse(input: &str) -> Result<Self, SandboxError> {
        if input.is_empty()
            || input
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | ':' | '\0'))
        {
            return Err(invalid_registry_policy(
                InvalidRequestReason::InvalidCharacter,
            ));
        }

        let parts = input
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_uppercase)
            .collect::<Vec<_>>();
        let Some(root) = parts.first().map(String::as_str) else {
            return Err(invalid_registry_policy(
                InvalidRequestReason::InvalidCharacter,
            ));
        };

        let (hive, component_offset) = match root {
            "HKCR" | "HKEY_CLASSES_ROOT" => (RegistryHive::ClassesRoot, 1),
            "HKCU" | "HKEY_CURRENT_USER" => (RegistryHive::CurrentUser, 1),
            "HKLM" | "HKEY_LOCAL_MACHINE" => (RegistryHive::LocalMachine, 1),
            "HKU" | "HKEY_USERS" => (RegistryHive::Users, 1),
            "HKCC" | "HKEY_CURRENT_CONFIG" => (RegistryHive::CurrentConfig, 1),
            "REGISTRY" if parts.get(1).is_some_and(|part| part == "MACHINE") => {
                (RegistryHive::LocalMachine, 2)
            }
            "REGISTRY" if parts.get(1).is_some_and(|part| part == "USER") && parts.len() > 2 => {
                (RegistryHive::Users, 2)
            }
            _ => {
                return Err(invalid_registry_policy(
                    InvalidRequestReason::InvalidCharacter,
                ));
            }
        };

        Ok(Self {
            hive,
            components: parts[component_offset..].to_vec(),
        })
    }

    fn contains(&self, candidate: &Self) -> bool {
        self.hive == candidate.hive
            && self.components.len() <= candidate.components.len()
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RegistryHive {
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    CurrentConfig,
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

const fn invalid_registry_policy(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::RegistryPolicy,
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

    #[test]
    fn pol_022_network_category_limits_accept_maximum_and_reject_maximum_plus_one() {
        let domains = (0..=MAX_NETWORK_RULES_PER_CATEGORY)
            .map(|index| format!("d{index}.example"))
            .collect::<Vec<_>>();
        let addresses = (0..=MAX_NETWORK_RULES_PER_CATEGORY)
            .map(|index| IpCidr {
                address: IpAddr::V4(Ipv4Addr::from(
                    0x0A00_0000_u32 + u32::try_from(index).expect("test index must fit u32"),
                )),
                prefix_length: 32,
            })
            .collect::<Vec<_>>();
        let maximum_port =
            u16::try_from(MAX_NETWORK_RULES_PER_CATEGORY).expect("rule limit must fit u16");
        let ports = (1..=(maximum_port + 1))
            .map(|port| PortRange {
                start: port,
                end: port,
            })
            .collect::<Vec<_>>();

        for (at_maximum, over_maximum) in [
            (
                NetworkAllowList {
                    domains: domains[..MAX_NETWORK_RULES_PER_CATEGORY].to_vec(),
                    ..NetworkAllowList::default()
                },
                NetworkAllowList {
                    domains,
                    ..NetworkAllowList::default()
                },
            ),
            (
                NetworkAllowList {
                    addresses: addresses[..MAX_NETWORK_RULES_PER_CATEGORY].to_vec(),
                    ..NetworkAllowList::default()
                },
                NetworkAllowList {
                    addresses,
                    ..NetworkAllowList::default()
                },
            ),
            (
                NetworkAllowList {
                    ports: ports[..MAX_NETWORK_RULES_PER_CATEGORY].to_vec(),
                    ..NetworkAllowList::default()
                },
                NetworkAllowList {
                    ports,
                    ..NetworkAllowList::default()
                },
            ),
        ] {
            assert!(
                compile(
                    &policy_with_network(NetworkPolicy::AllowList(at_maximum)),
                    Path::new(r"C:\work\project"),
                )
                .is_ok()
            );
            assert_eq!(
                compile(
                    &policy_with_network(NetworkPolicy::AllowList(over_maximum)),
                    Path::new(r"C:\work\project"),
                )
                .err(),
                Some(SandboxError::InvalidRequest {
                    field: RequestField::NetworkPolicy,
                    reason: InvalidRequestReason::TooManyItems,
                })
            );
        }
    }

    #[test]
    fn pol_022_total_network_rule_limit_is_checked_before_deduplication() {
        let addresses = (0..MAX_NETWORK_RULES_PER_CATEGORY)
            .map(|index| IpCidr {
                address: IpAddr::V4(Ipv4Addr::from(
                    0x0A00_0000_u32 + u32::try_from(index).expect("test index must fit u32"),
                )),
                prefix_length: 32,
            })
            .collect::<Vec<_>>();
        let at_maximum = NetworkAllowList {
            domains: vec!["example.com".into(); MAX_NETWORK_RULES_PER_CATEGORY],
            addresses: addresses.clone(),
            ..NetworkAllowList::default()
        };
        let over_maximum = NetworkAllowList {
            domains: vec!["example.com".into(); MAX_NETWORK_RULES_PER_CATEGORY],
            addresses,
            ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
        };

        assert!(
            compile(
                &policy_with_network(NetworkPolicy::AllowList(at_maximum)),
                Path::new(r"C:\work\project"),
            )
            .is_ok()
        );
        assert_eq!(
            compile(
                &policy_with_network(NetworkPolicy::AllowList(over_maximum)),
                Path::new(r"C:\work\project"),
            )
            .err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::NetworkPolicy,
                reason: InvalidRequestReason::TooManyItems,
            })
        );
    }

    #[test]
    fn req_010_equivalent_network_rules_compile_deterministically() {
        let first = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
            domains: vec!["Example.COM".into(), "münich.example".into()],
            addresses: vec![
                IpCidr {
                    address: "2001:db8::".parse().expect("valid IPv6"),
                    prefix_length: 32,
                },
                IpCidr {
                    address: "192.0.2.0".parse().expect("valid IPv4"),
                    prefix_length: 24,
                },
            ],
            ports: vec![
                PortRange {
                    start: 8_000,
                    end: 8_080,
                },
                PortRange {
                    start: 443,
                    end: 443,
                },
            ],
        }));
        let second = policy_with_network(NetworkPolicy::AllowList(NetworkAllowList {
            domains: vec!["xn--mnich-kva.example".into(), "example.com".into()],
            addresses: vec![
                IpCidr {
                    address: "192.0.2.0".parse().expect("valid IPv4"),
                    prefix_length: 24,
                },
                IpCidr {
                    address: "2001:db8::".parse().expect("valid IPv6"),
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

        let first =
            compile(&first, Path::new(r"C:\work\project")).expect("first policy must compile");
        let second =
            compile(&second, Path::new(r"C:\work\project")).expect("second policy must compile");

        assert_eq!(first.network, second.network);
    }

    #[test]
    fn reg_001_to_007_registry_grants_and_default_deny_are_explicit() {
        let mut policy = SandboxPolicy::default();
        policy
            .registry
            .read_only
            .push(r"HKCU\Software\ReadOnly".into());
        policy
            .registry
            .read_write
            .push(r"HKCU\Software\ReadWrite".into());
        policy
            .registry
            .inherit_user
            .push(r"HKCU\Software\Compatibility".into());
        policy
            .registry
            .no_access
            .push(r"HKCU\Software\ReadWrite\Denied".into());

        let compiled = compile(&policy, Path::new(r"C:\work\project"))
            .expect("valid registry policy must compile");

        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\ReadOnly\Value", RegistryAccess::Read),
            RegistryDecision::Allow
        );
        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\ReadOnly\Value", RegistryAccess::Write,),
            RegistryDecision::Deny
        );
        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\ReadWrite\Value", RegistryAccess::Write,),
            RegistryDecision::Allow
        );
        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\Compatibility\Value", RegistryAccess::Read,),
            RegistryDecision::InheritUser
        );
        assert_eq!(
            compiled.registry.decide(
                r"HKCU\Software\ReadWrite\Denied\Value",
                RegistryAccess::Read,
            ),
            RegistryDecision::Deny
        );
        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\Outside", RegistryAccess::Read),
            RegistryDecision::Deny
        );
    }

    #[test]
    fn pol_008_mandatory_registry_deny_overrides_broad_grant() {
        let mut policy = SandboxPolicy::default();
        policy.registry.read_write.push(r"HKCU\Software".into());

        let compiled = compile_with_security_denies(
            &policy,
            Path::new(r"C:\work\project"),
            &[],
            &[r"HKCU\Software\BoltBroker\Credentials".into()],
        )
        .expect("mandatory registry deny must compile");

        assert_eq!(
            compiled.registry.decide(
                r"HKCU\Software\BoltBroker\Credentials\Token",
                RegistryAccess::Read,
            ),
            RegistryDecision::Deny
        );
        assert_eq!(
            compiled
                .registry
                .decide(r"HKCU\Software\OrdinaryApp\Setting", RegistryAccess::Write,),
            RegistryDecision::Allow
        );
    }

    #[test]
    fn reg_010_registry_aliases_and_redundant_separators_share_one_rule() {
        let mut policy = SandboxPolicy::default();
        policy
            .registry
            .read_only
            .push(r"HKEY_LOCAL_MACHINE\Software\\Vendor".into());
        policy
            .registry
            .read_only
            .push(r"HKLM\SOFTWARE\vendor".into());

        let compiled = compile(&policy, Path::new(r"C:\work\project"))
            .expect("equivalent registry aliases must compile");

        assert_eq!(compiled.registry.read_only_rule_count(), 1);
        assert_eq!(
            compiled.registry.decide(
                r"\Registry\Machine\Software\VENDOR\Product",
                RegistryAccess::Read,
            ),
            RegistryDecision::Allow
        );
    }

    #[test]
    fn pol_020_malformed_registry_roots_are_rejected() {
        for key in [
            "",
            r"UNKNOWN\Software",
            r"HKCU:\Software",
            "HKCU\0Software",
            r"\Registry\User",
        ] {
            let mut policy = SandboxPolicy::default();
            policy.registry.read_only.push(key.into());

            assert!(matches!(
                compile(&policy, Path::new(r"C:\work\project")),
                Err(SandboxError::InvalidRequest {
                    field: RequestField::RegistryPolicy,
                    reason: InvalidRequestReason::InvalidCharacter,
                })
            ));
        }
    }
}
