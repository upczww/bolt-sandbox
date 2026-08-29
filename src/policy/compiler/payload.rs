use std::{net::IpAddr, os::windows::ffi::OsStrExt};

use sha2::{Digest, Sha256};

use super::{
    CompiledNetworkPolicy, CompiledPolicy, FilesystemRuleKind, NormalizedComponent, RegistryHive,
    RegistryRuleKind,
};
use crate::policy::ChildProcessPolicy;

const MAGIC: [u8; 4] = *b"BLP1";
pub(super) const POLICY_PAYLOAD_VERSION: u16 = 1;
pub(super) const VERSION_OFFSET: usize = 4;
const HEADER_LENGTH_OFFSET: usize = 6;
pub(super) const LENGTH_OFFSET: usize = 8;
const DIGEST_OFFSET: usize = 12;
const DIGEST_LENGTH: usize = 32;
pub(super) const HEADER_LENGTH: usize = DIGEST_OFFSET + DIGEST_LENGTH;
const HEADER_LENGTH_WIRE: u16 = 44;
pub(super) const MAX_POLICY_BODY_LENGTH: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PolicyPayloadError {
    TruncatedHeader,
    InvalidMagic,
    InvalidHeaderLength,
    UnsupportedVersion { expected: u16, actual: u16 },
    PayloadTooLarge,
    TruncatedPayload,
    TrailingBytes,
    IntegrityMismatch,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "sealed policy is passed to the native launcher in a later phase"
)]
pub(super) struct SealedPolicy {
    bytes: Vec<u8>,
}

#[allow(
    dead_code,
    reason = "sealed policy is passed to the native launcher in a later phase"
)]
impl SealedPolicy {
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn digest(&self) -> &[u8] {
        &self.bytes[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH]
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedPolicy<'a> {
    version: u16,
    body: &'a [u8],
}

#[allow(
    dead_code,
    reason = "verified policy is consumed by the native startup parser in a later phase"
)]
impl VerifiedPolicy<'_> {
    pub(super) const fn version(&self) -> u16 {
        self.version
    }

    pub(super) const fn body(&self) -> &[u8] {
        self.body
    }
}

#[allow(
    dead_code,
    reason = "policy sealing is connected to the native launcher in a later phase"
)]
pub(super) fn seal(policy: &CompiledPolicy) -> Result<SealedPolicy, PolicyPayloadError> {
    let body = encode_body(policy)?;
    let body_length = u32::try_from(body.len()).map_err(|_| PolicyPayloadError::PayloadTooLarge)?;
    let mut bytes = vec![0; HEADER_LENGTH];
    bytes[..MAGIC.len()].copy_from_slice(&MAGIC);
    bytes[VERSION_OFFSET..VERSION_OFFSET + 2]
        .copy_from_slice(&POLICY_PAYLOAD_VERSION.to_le_bytes());
    bytes[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 2]
        .copy_from_slice(&HEADER_LENGTH_WIRE.to_le_bytes());
    bytes[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&body_length.to_le_bytes());
    bytes.extend_from_slice(&body);

    let digest = policy_digest(&bytes[..DIGEST_OFFSET], &bytes[HEADER_LENGTH..]);
    bytes[DIGEST_OFFSET..HEADER_LENGTH].copy_from_slice(&digest);
    Ok(SealedPolicy { bytes })
}

#[allow(
    dead_code,
    reason = "policy verification is connected to native startup in a later phase"
)]
pub(super) fn verify(encoded: &[u8]) -> Result<VerifiedPolicy<'_>, PolicyPayloadError> {
    if encoded.len() < HEADER_LENGTH {
        return Err(PolicyPayloadError::TruncatedHeader);
    }
    if encoded[..MAGIC.len()] != MAGIC {
        return Err(PolicyPayloadError::InvalidMagic);
    }

    let version = read_u16(encoded, VERSION_OFFSET);
    if version != POLICY_PAYLOAD_VERSION {
        return Err(PolicyPayloadError::UnsupportedVersion {
            expected: POLICY_PAYLOAD_VERSION,
            actual: version,
        });
    }
    if usize::from(read_u16(encoded, HEADER_LENGTH_OFFSET)) != HEADER_LENGTH {
        return Err(PolicyPayloadError::InvalidHeaderLength);
    }

    let body_length = read_u32(encoded, LENGTH_OFFSET) as usize;
    if body_length > MAX_POLICY_BODY_LENGTH {
        return Err(PolicyPayloadError::PayloadTooLarge);
    }
    let expected_length = HEADER_LENGTH
        .checked_add(body_length)
        .ok_or(PolicyPayloadError::PayloadTooLarge)?;
    if encoded.len() < expected_length {
        return Err(PolicyPayloadError::TruncatedPayload);
    }
    if encoded.len() > expected_length {
        return Err(PolicyPayloadError::TrailingBytes);
    }

    let body = &encoded[HEADER_LENGTH..];
    let actual_digest = policy_digest(&encoded[..DIGEST_OFFSET], body);
    if encoded[DIGEST_OFFSET..HEADER_LENGTH] != actual_digest {
        return Err(PolicyPayloadError::IntegrityMismatch);
    }
    Ok(VerifiedPolicy { version, body })
}

fn policy_digest(header_prefix: &[u8], body: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(header_prefix);
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_body(policy: &CompiledPolicy) -> Result<Vec<u8>, PolicyPayloadError> {
    let mut writer = BoundedWriter::default();
    writer.write_u8(match policy.child_processes {
        ChildProcessPolicy::Inherit => 0,
        ChildProcessPolicy::Deny => 1,
    })?;
    encode_filesystem(policy, &mut writer)?;
    encode_network(policy, &mut writer)?;
    encode_registry(policy, &mut writer)?;
    Ok(writer.bytes)
}

fn encode_filesystem(
    policy: &CompiledPolicy,
    writer: &mut BoundedWriter,
) -> Result<(), PolicyPayloadError> {
    let mut records = policy
        .filesystem
        .rules
        .iter()
        .map(encode_filesystem_rule)
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_unstable();
    writer.write_count(records.len())?;
    for record in records {
        writer.write_count(record.len())?;
        writer.write_bytes(&record)?;
    }
    Ok(())
}

fn encode_filesystem_rule(rule: &super::FilesystemRule) -> Result<Vec<u8>, PolicyPayloadError> {
    let mut writer = BoundedWriter::default();
    writer.write_u8(match rule.kind {
        FilesystemRuleKind::ReadWrite => 0,
        FilesystemRuleKind::ReadOnly => 1,
        FilesystemRuleKind::Deny => 2,
        FilesystemRuleKind::MetadataRead => 3,
        FilesystemRuleKind::InheritUser => 4,
    })?;
    writer.write_count(rule.root.components.len())?;
    for component in &rule.root.components {
        match component {
            NormalizedComponent::Prefix(value) => {
                writer.write_u8(0)?;
                writer.write_canonical_os_str(value)?;
            }
            NormalizedComponent::Root => {
                writer.write_u8(1)?;
                writer.write_u32(0)?;
            }
            NormalizedComponent::Normal(value) => {
                writer.write_u8(2)?;
                writer.write_canonical_os_str(value)?;
            }
        }
    }
    Ok(writer.bytes)
}

fn encode_network(
    policy: &CompiledPolicy,
    writer: &mut BoundedWriter,
) -> Result<(), PolicyPayloadError> {
    let CompiledNetworkPolicy::AllowList(allow_list) = &policy.network else {
        return writer.write_u8(match policy.network {
            CompiledNetworkPolicy::Unrestricted => 0,
            CompiledNetworkPolicy::Denied => 1,
            CompiledNetworkPolicy::AllowList(_) => unreachable!(),
        });
    };
    writer.write_u8(2)?;
    writer.write_count(allow_list.domains.len())?;
    for domain in &allow_list.domains {
        writer.write_u8(u8::from(domain.wildcard))?;
        writer.write_sized_bytes(domain.ascii_domain.as_bytes())?;
    }
    writer.write_count(allow_list.addresses.len())?;
    for cidr in &allow_list.addresses {
        match cidr.address {
            IpAddr::V4(address) => {
                writer.write_u8(4)?;
                writer.write_u8(cidr.prefix_length)?;
                writer.write_bytes(&address.octets())?;
            }
            IpAddr::V6(address) => {
                writer.write_u8(6)?;
                writer.write_u8(cidr.prefix_length)?;
                writer.write_bytes(&address.octets())?;
            }
        }
    }
    writer.write_count(allow_list.ports.len())?;
    for port in &allow_list.ports {
        writer.write_u16(port.start)?;
        writer.write_u16(port.end)?;
    }
    Ok(())
}

fn encode_registry(
    policy: &CompiledPolicy,
    writer: &mut BoundedWriter,
) -> Result<(), PolicyPayloadError> {
    writer.write_count(policy.registry.rules.len())?;
    for rule in &policy.registry.rules {
        writer.write_u8(match rule.kind {
            RegistryRuleKind::NoAccess => 0,
            RegistryRuleKind::ReadOnly => 1,
            RegistryRuleKind::InheritUser => 2,
            RegistryRuleKind::ReadWrite => 3,
        })?;
        writer.write_u8(match rule.root.hive {
            RegistryHive::ClassesRoot => 0,
            RegistryHive::CurrentUser => 1,
            RegistryHive::LocalMachine => 2,
            RegistryHive::Users => 3,
            RegistryHive::CurrentConfig => 4,
        })?;
        writer.write_count(rule.root.components.len())?;
        for component in &rule.root.components {
            writer.write_sized_bytes(component.as_bytes())?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct BoundedWriter {
    bytes: Vec<u8>,
}

impl BoundedWriter {
    fn write_u8(&mut self, value: u8) -> Result<(), PolicyPayloadError> {
        self.ensure_capacity(1)?;
        self.bytes.push(value);
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<(), PolicyPayloadError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), PolicyPayloadError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_count(&mut self, value: usize) -> Result<(), PolicyPayloadError> {
        self.write_u32(u32::try_from(value).map_err(|_| PolicyPayloadError::PayloadTooLarge)?)
    }

    fn write_sized_bytes(&mut self, value: &[u8]) -> Result<(), PolicyPayloadError> {
        self.write_count(value.len())?;
        self.write_bytes(value)
    }

    fn write_bytes(&mut self, value: &[u8]) -> Result<(), PolicyPayloadError> {
        self.ensure_capacity(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn write_canonical_os_str(
        &mut self,
        value: &std::ffi::OsStr,
    ) -> Result<(), PolicyPayloadError> {
        let code_unit_count = value.encode_wide().count();
        let byte_count = code_unit_count
            .checked_mul(2)
            .ok_or(PolicyPayloadError::PayloadTooLarge)?;
        self.ensure_capacity(
            4_usize
                .checked_add(byte_count)
                .ok_or(PolicyPayloadError::PayloadTooLarge)?,
        )?;
        self.write_count(code_unit_count)?;
        for mut code_unit in value.encode_wide() {
            if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit = code_unit - u16::from(b'a') + u16::from(b'A');
            }
            self.bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        Ok(())
    }

    fn ensure_capacity(&self, additional: usize) -> Result<(), PolicyPayloadError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length > MAX_POLICY_BODY_LENGTH)
        {
            return Err(PolicyPayloadError::PayloadTooLarge);
        }
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::policy::{
        ChildProcessPolicy, FilesystemPolicy, NetworkAllowList, NetworkPolicy, RegistryPolicy,
        SandboxPolicy,
    };

    const CWD: &str = r"C:\workspace";

    fn compile_policy(policy: &SandboxPolicy) -> super::super::CompiledPolicy {
        super::super::compile(policy, Path::new(CWD)).expect("test policy must compile")
    }

    fn resign(encoded: &mut [u8]) {
        let digest = policy_digest(&encoded[..DIGEST_OFFSET], &encoded[HEADER_LENGTH..]);
        encoded[DIGEST_OFFSET..HEADER_LENGTH].copy_from_slice(&digest);
    }

    fn equivalent_policy(reverse: bool) -> SandboxPolicy {
        let (read_only, domains, registry) = if reverse {
            (
                vec![
                    PathBuf::from(r"c:\DATA\Beta"),
                    PathBuf::from(r"C:\data\alpha"),
                ],
                vec!["EXAMPLE.ORG".to_owned(), "*.Example.COM".to_owned()],
                vec![
                    r"hklm\Software\Beta".to_owned(),
                    r"HKEY_LOCAL_MACHINE\software\Alpha".to_owned(),
                ],
            )
        } else {
            (
                vec![
                    PathBuf::from(r"c:\DATA\ALPHA"),
                    PathBuf::from(r"C:\data\beta"),
                ],
                vec!["*.example.com".to_owned(), "example.org".to_owned()],
                vec![
                    r"HKLM\SOFTWARE\ALPHA".to_owned(),
                    r"hkey_local_machine\Software\BETA".to_owned(),
                ],
            )
        };

        SandboxPolicy {
            filesystem: FilesystemPolicy {
                read_only,
                ..FilesystemPolicy::default()
            },
            registry: RegistryPolicy {
                read_only: registry,
                ..RegistryPolicy::default()
            },
            network: NetworkPolicy::AllowList(NetworkAllowList {
                domains,
                ..NetworkAllowList::default()
            }),
            child_processes: ChildProcessPolicy::Deny,
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn req_010_equivalent_policies_have_identical_payload_bytes_and_digest() {
        let first =
            seal(&compile_policy(&equivalent_policy(false))).expect("first policy must serialize");
        let second = seal(&compile_policy(&equivalent_policy(true)))
            .expect("equivalent policy must serialize");

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn req_011_unknown_policy_payload_version_is_rejected_before_integrity() {
        let mut encoded = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize")
            .into_bytes();
        let unsupported = POLICY_PAYLOAD_VERSION + 1;
        encoded[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&unsupported.to_le_bytes());

        assert_eq!(
            verify(&encoded),
            Err(PolicyPayloadError::UnsupportedVersion {
                expected: POLICY_PAYLOAD_VERSION,
                actual: unsupported,
            })
        );
    }

    #[test]
    fn pol_010_modified_compiled_payload_fails_integrity_check() {
        let mut encoded = seal(&compile_policy(&equivalent_policy(false)))
            .expect("policy must serialize")
            .into_bytes();
        *encoded.last_mut().expect("payload body must not be empty") ^= 0x80;

        assert_eq!(verify(&encoded), Err(PolicyPayloadError::IntegrityMismatch));
    }

    #[test]
    fn pol_010_truncated_and_oversized_payloads_fail_closed() {
        assert_eq!(
            verify(&[0; HEADER_LENGTH - 1]),
            Err(PolicyPayloadError::TruncatedHeader)
        );

        let mut encoded = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize")
            .into_bytes();
        let oversized =
            u32::try_from(MAX_POLICY_BODY_LENGTH + 1).expect("policy payload limit must fit u32");
        encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&oversized.to_le_bytes());

        assert_eq!(verify(&encoded), Err(PolicyPayloadError::PayloadTooLarge));
    }

    #[test]
    fn pol_010_verified_payload_borrows_the_immutable_body() {
        let sealed = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize");
        let verified = verify(sealed.as_bytes()).expect("sealed policy must verify");

        assert_eq!(verified.version(), POLICY_PAYLOAD_VERSION);
        assert_eq!(verified.body(), &sealed.as_bytes()[HEADER_LENGTH..]);
    }

    #[test]
    fn pol_010_well_hashed_unknown_body_discriminants_fail_closed() {
        let sealed = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize");

        let mut invalid_child_mode = sealed.as_bytes().to_vec();
        invalid_child_mode[HEADER_LENGTH] = 0xFF;
        resign(&mut invalid_child_mode);
        assert_eq!(
            verify(&invalid_child_mode),
            Err(PolicyPayloadError::InvalidBody)
        );

        let mut invalid_network_mode = sealed.into_bytes();
        let network_mode_offset = invalid_network_mode.len() - 5;
        invalid_network_mode[network_mode_offset] = 0xFF;
        resign(&mut invalid_network_mode);
        assert_eq!(
            verify(&invalid_network_mode),
            Err(PolicyPayloadError::InvalidBody)
        );
    }

    #[test]
    fn pol_010_well_hashed_truncated_body_section_fails_closed() {
        let mut encoded = seal(&compile_policy(&SandboxPolicy::default()))
            .expect("default policy must serialize")
            .into_bytes();
        encoded.pop();
        let body_length =
            u32::try_from(encoded.len() - HEADER_LENGTH).expect("test payload length must fit u32");
        encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&body_length.to_le_bytes());
        resign(&mut encoded);

        assert_eq!(verify(&encoded), Err(PolicyPayloadError::InvalidBody));
    }
}
