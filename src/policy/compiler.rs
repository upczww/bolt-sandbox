use std::{
    ffi::{OsStr, OsString},
    net::IpAddr,
    os::windows::ffi::OsStrExt,
    path::{Component, Path},
};

use super::{
    ChildProcessPolicy, FilesystemPolicy, IpCidr, NetworkAllowList, NetworkPolicy, PortRange,
    RecoveryPolicy, RegistryPolicy, SandboxPolicy,
};
use crate::{InvalidRequestReason, RequestField, SandboxError};

pub(crate) mod payload;

const MAX_NETWORK_RULES_PER_CATEGORY: usize = 1_024;
const MAX_TOTAL_NETWORK_RULES: usize = 2_048;
const MAX_FILESYSTEM_RULES_PER_CATEGORY: usize = 1_024;
const MAX_TOTAL_FILESYSTEM_RULES: usize = 2_048;
const MAX_FILESYSTEM_PATH_CODE_UNITS: usize = 32_767;
const MAX_REGISTRY_RULES_PER_CATEGORY: usize = 1_024;
const MAX_TOTAL_REGISTRY_RULES: usize = 2_048;
const DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS: &[&str] = &[
    r"HKCU\SOFTWARE\Classes",
    r"HKLM\SOFTWARE\Classes",
    r"HKLM\SOFTWARE\dotnet\Setup\InstalledVersions",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Nls",
    r"HKLM\SOFTWARE\Microsoft\AMSI",
    r"HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore",
    r"HKCU\SOFTWARE\Policies\Microsoft\PowerShellCore",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Srp",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones",
];
const DEFAULT_REGISTRY_EXACT_READ_ONLY_COMPATIBILITY_GRANTS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion",
];
const DEFAULT_REGISTRY_HIDDEN_COMPATIBILITY_KEYS: &[&str] = &[r"HKCU\Environment"];
const DEFAULT_REGISTRY_COMPATIBILITY_GRANTS: &[&str] = &[
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    r"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2",
    r"HKLM\SYSTEM\CurrentControlSet\Services\WinSock",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock",
    r"HKLM\SOFTWARE\Microsoft\OLE",
    r"HKLM\SOFTWARE\Microsoft\AppModel\Lookaside\machine",
    r"HKLM\SOFTWARE\Microsoft\AppModel\Lookaside\user",
    r"HKLM\SOFTWARE\Microsoft\Wow64\x86\xtajit",
    r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
    r"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Containers",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide",
    r"HKLM\SOFTWARE\Microsoft\LanguageOverlay\OverlayPackages",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
    r"HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\MpeHttpExt\Payload",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\TenantRestrictions\Payload",
    r"HKLM\SOFTWARE\Microsoft\Rpc",
    r"HKLM\SYSTEM\CurrentControlSet\Services\CCG",
    r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
    r"HKLM\SYSTEM\Setup",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\Sorting\Ids",
    r"HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Service",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Hvsi",
    r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SspiCache",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    r"HKLM\SOFTWARE\Microsoft\OLEAUT",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum",
    r"HKLM\SOFTWARE\Microsoft\COM3",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
    r"HKLM\SOFTWARE\Microsoft\WindowsRuntime",
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    r"HKLM\ZoneMap\Ranges",
    r"HKCU\ZoneMap\Ranges",
    r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Main",
    r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Main",
    r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Security",
    r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Security",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
    r"HKLM\OSDATA\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Objects",
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Appx",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Partners\COM\RundownIIDsOfInterest",
    r"HKLM\SYSTEM\CurrentControlSet\Control\MUI\StringCacheSettings",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
];
const MAX_COMPILED_REGISTRY_RULES: usize = MAX_TOTAL_REGISTRY_RULES
    + DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS.len()
    + DEFAULT_REGISTRY_EXACT_READ_ONLY_COMPATIBILITY_GRANTS.len()
    + DEFAULT_REGISTRY_HIDDEN_COMPATIBILITY_KEYS.len()
    + DEFAULT_REGISTRY_COMPATIBILITY_GRANTS.len();
const MAX_REGISTRY_KEY_CODE_UNITS: usize = 255;

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
    validate_filesystem_policy_limits(&policy.filesystem)?;
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
    let recovery = compile_recovery_policy(&policy.recovery)?;
    if let CompiledRecoveryPolicy::Enabled(limits) = &recovery {
        filesystem.add_rule(limits.directory(), FilesystemRuleKind::Deny)?;
    }
    let compiled = CompiledPolicy {
        filesystem,
        network,
        registry,
        child_processes: policy.child_processes,
        recovery,
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

fn validate_filesystem_policy_limits(policy: &FilesystemPolicy) -> Result<(), SandboxError> {
    let category_counts = [
        policy.read_write.len(),
        policy.read_only.len(),
        policy.deny.len(),
        policy.metadata_read.len(),
        policy.inherit_user.len(),
    ];
    if category_counts
        .iter()
        .any(|count| *count > MAX_FILESYSTEM_RULES_PER_CATEGORY)
        || category_counts
            .into_iter()
            .try_fold(0_usize, usize::checked_add)
            .is_none_or(|count| count > MAX_TOTAL_FILESYSTEM_RULES)
    {
        return Err(invalid_filesystem_policy(
            InvalidRequestReason::TooManyItems,
        ));
    }
    Ok(())
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
    pub(crate) child_processes: ChildProcessPolicy,
    #[allow(
        dead_code,
        reason = "compiled recovery policy is consumed by the trusted Rust recovery coordinator"
    )]
    pub(crate) recovery: CompiledRecoveryPolicy,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CompiledRecoveryPolicy {
    Disabled,
    Enabled(CompiledRecoveryLimits),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledRecoveryLimits {
    directory: std::path::PathBuf,
    maximum_bytes: u64,
    maximum_items: u32,
}

impl CompiledRecoveryLimits {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    pub(crate) const fn maximum_items(&self) -> u32 {
        self.maximum_items
    }
}

#[allow(
    dead_code,
    reason = "recovery quota is instantiated by the trusted recovery coordinator later"
)]
impl CompiledRecoveryLimits {
    fn quota(&self) -> RecoveryQuota {
        RecoveryQuota {
            maximum_bytes: self.maximum_bytes,
            maximum_items: self.maximum_items,
            used_bytes: 0,
            used_items: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "recovery quota errors are consumed by the trusted recovery coordinator later"
)]
pub(crate) enum RecoveryQuotaError {
    ByteLimit,
    ItemLimit,
    CounterOverflow,
}

#[allow(
    dead_code,
    reason = "recovery quota is consumed by the trusted recovery coordinator later"
)]
pub(crate) struct RecoveryQuota {
    maximum_bytes: u64,
    maximum_items: u32,
    used_bytes: u64,
    used_items: u32,
}

#[allow(
    dead_code,
    reason = "recovery quota is consumed by the trusted recovery coordinator later"
)]
impl RecoveryQuota {
    pub(crate) fn reserve(&mut self, byte_count: u64) -> Result<(), RecoveryQuotaError> {
        let next_items = self
            .used_items
            .checked_add(1)
            .ok_or(RecoveryQuotaError::CounterOverflow)?;
        let next_bytes = self
            .used_bytes
            .checked_add(byte_count)
            .ok_or(RecoveryQuotaError::CounterOverflow)?;
        if next_items > self.maximum_items {
            return Err(RecoveryQuotaError::ItemLimit);
        }
        if next_bytes > self.maximum_bytes {
            return Err(RecoveryQuotaError::ByteLimit);
        }
        self.used_items = next_items;
        self.used_bytes = next_bytes;
        Ok(())
    }
}

fn compile_recovery_policy(
    policy: &RecoveryPolicy,
) -> Result<CompiledRecoveryPolicy, SandboxError> {
    let RecoveryPolicy::Enabled(limits) = policy else {
        return Ok(CompiledRecoveryPolicy::Disabled);
    };
    if !limits.directory.is_absolute() {
        return Err(invalid_recovery_policy(
            InvalidRequestReason::MustBeAbsolute,
        ));
    }
    if limits
        .directory
        .as_os_str()
        .encode_wide()
        .any(|code_unit| code_unit == 0)
    {
        return Err(invalid_recovery_policy(
            InvalidRequestReason::InvalidCharacter,
        ));
    }
    if limits.maximum_bytes == 0 || limits.maximum_items == 0 {
        return Err(invalid_recovery_policy(InvalidRequestReason::OutOfRange));
    }
    Ok(CompiledRecoveryPolicy::Enabled(CompiledRecoveryLimits {
        directory: limits.directory.clone(),
        maximum_bytes: limits.maximum_bytes,
        maximum_items: limits.maximum_items,
    }))
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
    NotFound,
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
            .filter(|rule| match rule.kind {
                RegistryRuleKind::ReadOnlyKey | RegistryRuleKind::HideKey => rule.root == key,
                _ => rule.root.contains(&key),
            })
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
    validate_registry_rule_counts(policy, mandatory_denies)?;
    let mut compiled = RegistryPolicyBuilder::default();
    compiled.add_rules(&policy.read_write, RegistryRuleKind::ReadWrite)?;
    compiled.add_rules(&policy.read_only, RegistryRuleKind::ReadOnly)?;
    compiled.add_rules(&policy.no_access, RegistryRuleKind::NoAccess)?;
    compiled.add_rules(mandatory_denies, RegistryRuleKind::NoAccess)?;
    compiled.add_compatibility_rules(
        DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS,
        RegistryRuleKind::ReadOnly,
    )?;
    compiled.add_compatibility_rules(
        DEFAULT_REGISTRY_EXACT_READ_ONLY_COMPATIBILITY_GRANTS,
        RegistryRuleKind::ReadOnlyKey,
    )?;
    compiled.add_compatibility_rules(
        DEFAULT_REGISTRY_HIDDEN_COMPATIBILITY_KEYS,
        RegistryRuleKind::HideKey,
    )?;
    compiled.add_compatibility_rules(
        DEFAULT_REGISTRY_COMPATIBILITY_GRANTS,
        RegistryRuleKind::InheritUser,
    )?;
    compiled.add_rules(&policy.inherit_user, RegistryRuleKind::InheritUser)?;
    compiled
        .rules
        .sort_by(|left, right| left.root.cmp(&right.root).then(left.kind.cmp(&right.kind)));
    Ok(CompiledRegistryPolicy {
        rules: compiled.rules,
    })
}

fn validate_registry_rule_counts(
    policy: &RegistryPolicy,
    mandatory_denies: &[String],
) -> Result<(), SandboxError> {
    let no_access_count = policy
        .no_access
        .len()
        .checked_add(mandatory_denies.len())
        .ok_or_else(|| invalid_registry_policy(InvalidRequestReason::TooManyItems))?;
    if no_access_count > MAX_REGISTRY_RULES_PER_CATEGORY
        || policy.read_only.len() > MAX_REGISTRY_RULES_PER_CATEGORY
        || policy.inherit_user.len() > MAX_REGISTRY_RULES_PER_CATEGORY
        || policy.read_write.len() > MAX_REGISTRY_RULES_PER_CATEGORY
    {
        return Err(invalid_registry_policy(InvalidRequestReason::TooManyItems));
    }

    let total = no_access_count
        .checked_add(policy.read_only.len())
        .and_then(|count| count.checked_add(policy.inherit_user.len()))
        .and_then(|count| count.checked_add(policy.read_write.len()))
        .ok_or_else(|| invalid_registry_policy(InvalidRequestReason::TooManyItems))?;
    if total > MAX_TOTAL_REGISTRY_RULES {
        return Err(invalid_registry_policy(InvalidRequestReason::TooManyItems));
    }
    Ok(())
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

    fn add_compatibility_rules(
        &mut self,
        keys: &[&str],
        kind: RegistryRuleKind,
    ) -> Result<(), SandboxError> {
        for key in keys {
            let root = NormalizedRegistryKey::parse(key)?;
            if self.rules.iter().any(|rule| rule.root == root) {
                continue;
            }
            if kind == RegistryRuleKind::InheritUser
                && self.rules.iter().any(|rule| {
                    rule.kind == RegistryRuleKind::ReadOnly && rule.root.contains(&root)
                })
            {
                continue;
            }
            self.rules.push(RegistryRule { root, kind });
        }
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
    ReadOnlyKey,
    HideKey,
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
            Self::ReadOnlyKey => match access {
                RegistryAccess::Read | RegistryAccess::Enumerate => RegistryDecision::Allow,
                RegistryAccess::Write => RegistryDecision::Deny,
            },
            Self::HideKey => match access {
                RegistryAccess::Read | RegistryAccess::Enumerate => RegistryDecision::NotFound,
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

        let mut components = parts[component_offset..].to_vec();
        normalize_wow64_registry_view(hive, &mut components);
        let normalized = Self { hive, components };
        if normalized.encoded_length() > MAX_REGISTRY_KEY_CODE_UNITS {
            return Err(invalid_registry_policy(InvalidRequestReason::TooLarge));
        }
        Ok(normalized)
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

    fn encoded_length(&self) -> usize {
        self.hive.canonical_name().encode_utf16().count()
            + self
                .components
                .iter()
                .map(|component| 1 + component.encode_utf16().count())
                .sum::<usize>()
    }
}

fn normalize_wow64_registry_view(hive: RegistryHive, components: &mut Vec<String>) {
    let redirected_index = match hive {
        RegistryHive::ClassesRoot
            if components
                .first()
                .is_some_and(|value| value == "WOW6432NODE") =>
        {
            Some(0)
        }
        RegistryHive::LocalMachine
            if components.first().is_some_and(|value| value == "SOFTWARE")
                && components
                    .get(1)
                    .is_some_and(|value| value == "WOW6432NODE") =>
        {
            Some(1)
        }
        RegistryHive::LocalMachine | RegistryHive::CurrentUser
            if components.first().is_some_and(|value| value == "SOFTWARE")
                && components.get(1).is_some_and(|value| value == "CLASSES")
                && components
                    .get(2)
                    .is_some_and(|value| value == "WOW6432NODE") =>
        {
            Some(2)
        }
        _ => None,
    };
    if let Some(index) = redirected_index {
        components.remove(index);
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

impl RegistryHive {
    const fn canonical_name(self) -> &'static str {
        match self {
            Self::ClassesRoot => "HKEY_CLASSES_ROOT",
            Self::CurrentUser => "HKEY_CURRENT_USER",
            Self::LocalMachine => "HKEY_LOCAL_MACHINE",
            Self::Users => "HKEY_USERS",
            Self::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct FilesystemRule {
    root: NormalizedPath,
    kind: FilesystemRuleKind,
}

#[derive(Clone, Debug)]
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
        if path
            .as_os_str()
            .encode_wide()
            .any(|code_unit| code_unit == 0)
        {
            return Err(invalid_filesystem_policy(
                InvalidRequestReason::InvalidCharacter,
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
        let normalized = Self { components };
        if normalized
            .encoded_length()
            .is_none_or(|length| length > MAX_FILESYSTEM_PATH_CODE_UNITS)
        {
            return Err(invalid_filesystem_policy(InvalidRequestReason::TooLarge));
        }
        Ok(normalized)
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

    fn encoded_length(&self) -> Option<usize> {
        let mut length = 0_usize;
        let mut previous_was_normal = false;
        for component in &self.components {
            match component {
                NormalizedComponent::Prefix(value) => {
                    length = length.checked_add(value.encode_wide().count())?;
                    previous_was_normal = false;
                }
                NormalizedComponent::Root => {
                    length = length.checked_add(1)?;
                    previous_was_normal = false;
                }
                NormalizedComponent::Normal(value) => {
                    if previous_was_normal {
                        length = length.checked_add(1)?;
                    }
                    length = length.checked_add(value.encode_wide().count())?;
                    previous_was_normal = true;
                }
            }
        }
        Some(length)
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

#[derive(Clone, Debug)]
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

const fn invalid_recovery_policy(reason: InvalidRequestReason) -> SandboxError {
    SandboxError::InvalidRequest {
        field: RequestField::RecoveryPolicy,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::windows::ffi::OsStringExt,
        path::{Path, PathBuf},
    };

    use super::*;
    use crate::{
        InvalidRequestReason, IpCidr, NetworkAllowList, NetworkPolicy, PortRange, RecoveryLimits,
        RecoveryPolicy, RequestField, SandboxError,
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
    fn pol_013_embedded_nul_in_filesystem_rule_fails_closed() {
        let path = PathBuf::from(OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'a'),
            0,
            u16::from(b'b'),
        ]));
        let policy = policy_with_filesystem(|filesystem| filesystem.read_only.push(path));

        assert_eq!(
            compile(&policy, Path::new(r"C:\work")).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::InvalidCharacter,
            })
        );
    }

    #[test]
    fn pol_022_filesystem_category_limits_are_checked_before_deduplication() {
        let repeated = vec![PathBuf::from(r"C:\same"); MAX_FILESYSTEM_RULES_PER_CATEGORY + 1];

        for configure in [
            |policy: &mut super::super::FilesystemPolicy, paths| {
                policy.read_write = paths;
            },
            |policy: &mut super::super::FilesystemPolicy, paths| {
                policy.read_only = paths;
            },
            |policy: &mut super::super::FilesystemPolicy, paths| {
                policy.deny = paths;
            },
            |policy: &mut super::super::FilesystemPolicy, paths| {
                policy.metadata_read = paths;
            },
            |policy: &mut super::super::FilesystemPolicy, paths| {
                policy.inherit_user = paths;
            },
        ] {
            let at_maximum = policy_with_filesystem(|policy| {
                configure(
                    policy,
                    repeated[..MAX_FILESYSTEM_RULES_PER_CATEGORY].to_vec(),
                );
            });
            assert!(compile(&at_maximum, Path::new(r"C:\work")).is_ok());

            let over_maximum = policy_with_filesystem(|policy| {
                configure(policy, repeated.clone());
            });
            assert_eq!(
                compile(&over_maximum, Path::new(r"C:\work")).err(),
                Some(SandboxError::InvalidRequest {
                    field: RequestField::FilesystemPolicy,
                    reason: InvalidRequestReason::TooManyItems,
                })
            );
        }
    }

    #[test]
    fn pol_022_total_filesystem_rule_limit_has_exact_boundary() {
        let make_policy = |read_write_count, read_only_count, deny_count| {
            policy_with_filesystem(|policy| {
                policy.read_write = vec![PathBuf::from(r"C:\rw"); read_write_count];
                policy.read_only = vec![PathBuf::from(r"C:\ro"); read_only_count];
                policy.deny = vec![PathBuf::from(r"C:\deny"); deny_count];
            })
        };

        assert!(compile(&make_policy(683, 683, 682), Path::new(r"C:\work"),).is_ok());
        assert_eq!(
            compile(&make_policy(683, 683, 683), Path::new(r"C:\work"),).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::TooManyItems,
            })
        );
    }

    #[test]
    fn pol_022_normalized_filesystem_path_length_has_exact_utf16_boundary() {
        let maximum = PathBuf::from(format!(
            r"C:\{}",
            "a".repeat(MAX_FILESYSTEM_PATH_CODE_UNITS - 3)
        ));
        let over_maximum = PathBuf::from(format!(
            r"C:\{}",
            "a".repeat(MAX_FILESYSTEM_PATH_CODE_UNITS - 2)
        ));

        let accepted = policy_with_filesystem(|policy| policy.read_only.push(maximum));
        assert!(compile(&accepted, Path::new(r"C:\work")).is_ok());

        let rejected = policy_with_filesystem(|policy| policy.read_only.push(over_maximum));
        assert_eq!(
            compile(&rejected, Path::new(r"C:\work")).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::FilesystemPolicy,
                reason: InvalidRequestReason::TooLarge,
            })
        );
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
    fn fs_049_all_sensitive_categories_override_broad_grants() {
        let cwd = Path::new(r"C:\work\project");
        let policy = policy_with_filesystem(|filesystem| {
            filesystem.read_write.push(PathBuf::from(r"C:\Users\Alice"));
        });
        let mandatory_denies = [
            PathBuf::from(r"C:\Users\Alice\.ssh"),
            PathBuf::from(r"C:\Users\Alice\.gnupg"),
            PathBuf::from(r"C:\Users\Alice\AppData\Local\Browser\CredentialStore"),
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming\ApplicationSecrets"),
            PathBuf::from(r"C:\Users\Alice\AppData\Local\Bolt\BrokerState"),
        ];
        let compiled = compile_with_mandatory_denies(&policy, cwd, &mandatory_denies)
            .expect("all mandatory sensitive categories must compile");

        for denied_root in &mandatory_denies {
            assert_eq!(
                compiled
                    .filesystem
                    .decide(&denied_root.join("protected.bin"), FilesystemAccess::Read),
                FilesystemDecision::Deny,
                "mandatory category must remain denied: {}",
                denied_root.display()
            );
            assert_eq!(
                compiled
                    .filesystem
                    .decide(&denied_root.join("protected.bin"), FilesystemAccess::Write),
                FilesystemDecision::Deny,
                "mandatory category must reject writes: {}",
                denied_root.display()
            );
        }
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

        assert_eq!(
            compiled.registry.read_only_rule_count(),
            DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS.len() + 1
        );
        assert_eq!(
            compiled.registry.decide(
                r"\Registry\Machine\Software\VENDOR\Product",
                RegistryAccess::Read,
            ),
            RegistryDecision::Allow
        );
    }

    #[test]
    fn reg_011_wow64_views_share_one_policy_identity() {
        let mut policy = SandboxPolicy::default();
        policy
            .registry
            .read_only
            .push(r"HKLM\Software\Vendor".into());
        policy
            .registry
            .read_only
            .push(r"HKLM\Software\Wow6432Node\Vendor".into());

        let compiled = compile(&policy, Path::new(r"C:\work\project"))
            .expect("equivalent WOW64 registry views must compile");

        assert_eq!(
            compiled.registry.read_only_rule_count(),
            DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS.len() + 1
        );
        assert_eq!(
            compiled.registry.decide(
                r"HKLM\Software\Wow6432Node\Vendor\Product",
                RegistryAccess::Read,
            ),
            RegistryDecision::Allow
        );
        assert_eq!(
            compiled.registry.decide(
                r"HKLM\Software\Wow6432Node\Vendor\Product",
                RegistryAccess::Write,
            ),
            RegistryDecision::Deny
        );
    }

    fn assert_default_registry_metadata_rules(compiled: &CompiledPolicy) {
        for classes_root in [r"HKCU\SOFTWARE\Classes", r"HKLM\SOFTWARE\Classes"] {
            assert_eq!(
                compiled
                    .registry
                    .decide(classes_root, RegistryAccess::Read,),
                RegistryDecision::Allow
            );
            assert_eq!(
                compiled
                    .registry
                    .decide(classes_root, RegistryAccess::Write,),
                RegistryDecision::Deny
            );
        }
        for runtime_metadata_root in [
            r"HKLM\SOFTWARE\dotnet\Setup\InstalledVersions",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Nls",
            r"HKLM\SOFTWARE\Microsoft\AMSI",
            r"HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore",
            r"HKCU\SOFTWARE\Policies\Microsoft\PowerShellCore",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
            r"HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Srp",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server",
        ] {
            assert_eq!(
                compiled
                    .registry
                    .decide(runtime_metadata_root, RegistryAccess::Read),
                RegistryDecision::Allow
            );
            assert_eq!(
                compiled
                    .registry
                    .decide(runtime_metadata_root, RegistryAccess::Write),
                RegistryDecision::Deny
            );
        }
        for exact_metadata_key in DEFAULT_REGISTRY_EXACT_READ_ONLY_COMPATIBILITY_GRANTS {
            assert_eq!(
                compiled
                    .registry
                    .decide(exact_metadata_key, RegistryAccess::Read),
                RegistryDecision::Allow
            );
            assert_eq!(
                compiled
                    .registry
                    .decide(exact_metadata_key, RegistryAccess::Write),
                RegistryDecision::Deny
            );
            assert_eq!(
                compiled.registry.decide(
                    &format!(r"{exact_metadata_key}\UnlistedSensitive"),
                    RegistryAccess::Read,
                ),
                RegistryDecision::Deny
            );
        }
        for hidden_key in DEFAULT_REGISTRY_HIDDEN_COMPATIBILITY_KEYS {
            assert_eq!(
                compiled.registry.decide(hidden_key, RegistryAccess::Read),
                RegistryDecision::NotFound
            );
            assert_eq!(
                compiled
                    .registry
                    .decide(hidden_key, RegistryAccess::Enumerate),
                RegistryDecision::NotFound
            );
            assert_eq!(
                compiled.registry.decide(hidden_key, RegistryAccess::Write),
                RegistryDecision::Deny
            );
            assert_eq!(
                compiled.registry.decide(
                    &format!(r"{hidden_key}\UnlistedSensitive"),
                    RegistryAccess::Read,
                ),
                RegistryDecision::Deny
            );
        }
    }

    #[test]
    fn reg_default_compatibility_grants_are_explicit_and_narrow() {
        let compiled = compile(&SandboxPolicy::default(), Path::new(r"C:\work\project"))
            .expect("default compatibility registry grants must compile");

        for &key in DEFAULT_REGISTRY_COMPATIBILITY_GRANTS {
            let normalized_key = key.to_ascii_uppercase();
            let read_only_metadata = DEFAULT_REGISTRY_READ_ONLY_COMPATIBILITY_GRANTS
                .iter()
                .any(|root| normalized_key.starts_with(&root.to_ascii_uppercase()));
            assert_eq!(
                compiled.registry.decide(key, RegistryAccess::Read),
                if read_only_metadata {
                    RegistryDecision::Allow
                } else {
                    RegistryDecision::InheritUser
                },
                "read: {key}"
            );
            assert_eq!(
                compiled.registry.decide(key, RegistryAccess::Write),
                if read_only_metadata {
                    RegistryDecision::Deny
                } else {
                    RegistryDecision::InheritUser
                },
                "write: {key}"
            );
        }
        assert_default_registry_metadata_rules(&compiled);
        assert_eq!(
            compiled.registry.decide(
                r"HKLM\SOFTWARE\Microsoft\AppModel\Unrelated",
                RegistryAccess::Read,
            ),
            RegistryDecision::Deny
        );

        let mut explicitly_denied = SandboxPolicy::default();
        explicitly_denied
            .registry
            .no_access
            .push(r"HKLM\SOFTWARE\Microsoft\Rpc".into());
        let explicitly_denied = compile(&explicitly_denied, Path::new(r"C:\work\project"))
            .expect("an explicit deny must replace the compatibility grant");
        assert_eq!(
            explicitly_denied.registry.decide(
                r"HKLM\SOFTWARE\Microsoft\Rpc\SecurityService",
                RegistryAccess::Read,
            ),
            RegistryDecision::Deny
        );

        let mandatorily_denied = compile_with_security_denies(
            &SandboxPolicy::default(),
            Path::new(r"C:\work\project"),
            &[],
            &[r"HKLM\SOFTWARE\Microsoft\Rpc".into()],
        )
        .expect("a mandatory deny must replace the compatibility grant");
        assert_eq!(
            mandatorily_denied.registry.decide(
                r"HKLM\SOFTWARE\Microsoft\Rpc\SecurityService",
                RegistryAccess::Read,
            ),
            RegistryDecision::Deny
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

    #[test]
    fn pol_022_registry_category_limits_accept_maximum_and_reject_maximum_plus_one() {
        for kind in [
            RegistryRuleKind::NoAccess,
            RegistryRuleKind::ReadOnly,
            RegistryRuleKind::InheritUser,
            RegistryRuleKind::ReadWrite,
        ] {
            let at_maximum =
                policy_with_repeated_registry_rule(kind, MAX_REGISTRY_RULES_PER_CATEGORY);
            let over_maximum =
                policy_with_repeated_registry_rule(kind, MAX_REGISTRY_RULES_PER_CATEGORY + 1);

            assert!(compile(&at_maximum, Path::new(r"C:\work\project")).is_ok());
            assert_eq!(
                compile(&over_maximum, Path::new(r"C:\work\project")).err(),
                Some(SandboxError::InvalidRequest {
                    field: RequestField::RegistryPolicy,
                    reason: InvalidRequestReason::TooManyItems,
                })
            );
        }
    }

    #[test]
    fn pol_022_total_registry_limit_is_checked_before_deduplication() {
        let mut at_maximum = SandboxPolicy::default();
        at_maximum.registry.read_only =
            vec![r"HKCU\Software\Read".into(); MAX_REGISTRY_RULES_PER_CATEGORY];
        at_maximum.registry.read_write =
            vec![r"HKCU\Software\Write".into(); MAX_REGISTRY_RULES_PER_CATEGORY];
        let mut over_maximum = at_maximum.clone();
        over_maximum
            .registry
            .no_access
            .push(r"HKCU\Software\Denied".into());

        assert!(compile(&at_maximum, Path::new(r"C:\work\project")).is_ok());
        assert_eq!(
            compile(&over_maximum, Path::new(r"C:\work\project")).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::RegistryPolicy,
                reason: InvalidRequestReason::TooManyItems,
            })
        );
    }

    #[test]
    fn pol_022_registry_key_length_maximum_and_maximum_plus_one() {
        let prefix = r"HKEY_CURRENT_USER\";
        let component_length = MAX_REGISTRY_KEY_CODE_UNITS - prefix.encode_utf16().count();
        let at_maximum = format!("{prefix}{}", "K".repeat(component_length));
        let over_maximum = format!("{at_maximum}K");

        let mut policy = SandboxPolicy::default();
        policy.registry.read_only.push(at_maximum);
        assert!(compile(&policy, Path::new(r"C:\work\project")).is_ok());

        policy.registry.read_only.clear();
        policy.registry.read_only.push(over_maximum);
        assert_eq!(
            compile(&policy, Path::new(r"C:\work\project")).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::RegistryPolicy,
                reason: InvalidRequestReason::TooLarge,
            })
        );
    }

    fn policy_with_repeated_registry_rule(kind: RegistryRuleKind, count: usize) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default();
        let rules = match kind {
            RegistryRuleKind::NoAccess => &mut policy.registry.no_access,
            RegistryRuleKind::ReadOnly => &mut policy.registry.read_only,
            RegistryRuleKind::ReadOnlyKey => {
                unreachable!("exact read-only rules are trusted compatibility rules")
            }
            RegistryRuleKind::HideKey => {
                unreachable!("hidden keys are trusted compatibility rules")
            }
            RegistryRuleKind::InheritUser => &mut policy.registry.inherit_user,
            RegistryRuleKind::ReadWrite => &mut policy.registry.read_write,
        };
        *rules = vec![r"HKCU\Software\Repeated".into(); count];
        policy
    }

    fn recovery_policy(maximum_bytes: u64, maximum_items: u32) -> SandboxPolicy {
        SandboxPolicy {
            recovery: RecoveryPolicy::Enabled(RecoveryLimits {
                directory: PathBuf::from(r"C:\trusted-recovery"),
                maximum_bytes,
                maximum_items,
            }),
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn pol_023_disabled_and_maximum_recovery_quotas_compile_explicitly() {
        let disabled = compile(&SandboxPolicy::default(), Path::new(r"C:\work"))
            .expect("disabled recovery must compile");
        assert!(matches!(
            disabled.recovery,
            CompiledRecoveryPolicy::Disabled
        ));

        let maximum = compile(&recovery_policy(u64::MAX, u32::MAX), Path::new(r"C:\work"))
            .expect("representable maximum quotas must compile");
        assert!(matches!(
            maximum.recovery,
            CompiledRecoveryPolicy::Enabled(CompiledRecoveryLimits {
                maximum_bytes: u64::MAX,
                maximum_items: u32::MAX,
                ..
            })
        ));
    }

    #[test]
    fn pol_023_zero_quotas_and_relative_directory_are_rejected() {
        for policy in [recovery_policy(0, 1), recovery_policy(1, 0)] {
            assert_eq!(
                compile(&policy, Path::new(r"C:\work")).err(),
                Some(SandboxError::InvalidRequest {
                    field: RequestField::RecoveryPolicy,
                    reason: InvalidRequestReason::OutOfRange,
                })
            );
        }

        let mut relative = recovery_policy(1, 1);
        let RecoveryPolicy::Enabled(limits) = &mut relative.recovery else {
            unreachable!();
        };
        limits.directory = PathBuf::from("relative-recovery");
        assert_eq!(
            compile(&relative, Path::new(r"C:\work")).err(),
            Some(SandboxError::InvalidRequest {
                field: RequestField::RecoveryPolicy,
                reason: InvalidRequestReason::MustBeAbsolute,
            })
        );
    }

    #[test]
    fn pol_023_runtime_quota_enforces_bytes_items_and_checked_overflow() {
        let compiled = compile(&recovery_policy(10, 2), Path::new(r"C:\work"))
            .expect("valid recovery policy must compile");
        let CompiledRecoveryPolicy::Enabled(limits) = compiled.recovery else {
            panic!("recovery must be enabled");
        };
        let mut quota = limits.quota();

        assert_eq!(quota.reserve(7), Ok(()));
        assert_eq!(quota.reserve(3), Ok(()));
        assert_eq!(quota.reserve(0), Err(RecoveryQuotaError::ItemLimit));

        let compiled = compile(&recovery_policy(u64::MAX, 2), Path::new(r"C:\work"))
            .expect("maximum recovery policy must compile");
        let CompiledRecoveryPolicy::Enabled(limits) = compiled.recovery else {
            panic!("recovery must be enabled");
        };
        let mut quota = limits.quota();
        assert_eq!(quota.reserve(u64::MAX), Ok(()));
        assert_eq!(quota.reserve(1), Err(RecoveryQuotaError::CounterOverflow));
    }

    #[test]
    fn rec_015_recovery_namespace_deny_overrides_broad_request_grant() {
        let mut policy = recovery_policy(1_024, 4);
        policy.filesystem.read_write.push(PathBuf::from(r"C:\"));

        let compiled =
            compile(&policy, Path::new(r"C:\work")).expect("valid recovery policy must compile");

        assert_eq!(
            compiled.filesystem.decide(
                Path::new(r"C:\trusted-recovery\artifact.bin"),
                FilesystemAccess::Write
            ),
            FilesystemDecision::Deny
        );
    }
}
