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
pub(crate) enum PolicyPayloadError {
    TruncatedHeader,
    InvalidMagic,
    InvalidHeaderLength,
    UnsupportedVersion { expected: u16, actual: u16 },
    PayloadTooLarge,
    TruncatedPayload,
    TrailingBytes,
    IntegrityMismatch,
    InvalidBody,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "sealed policy is passed to the native launcher in a later phase"
)]
pub(crate) struct SealedPolicy {
    bytes: Vec<u8>,
}

#[allow(
    dead_code,
    reason = "sealed policy is passed to the native launcher in a later phase"
)]
impl SealedPolicy {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn digest(&self) -> &[u8] {
        &self.bytes[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_LENGTH]
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPolicy<'a> {
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
pub(crate) fn seal(policy: &CompiledPolicy) -> Result<SealedPolicy, PolicyPayloadError> {
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
pub(crate) fn verify(encoded: &[u8]) -> Result<VerifiedPolicy<'_>, PolicyPayloadError> {
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
    validate_body(body)?;
    Ok(VerifiedPolicy { version, body })
}

fn validate_body(body: &[u8]) -> Result<(), PolicyPayloadError> {
    let mut reader = BodyReader::new(body);
    match reader.read_u8()? {
        0 | 1 => {}
        _ => return Err(PolicyPayloadError::InvalidBody),
    }
    validate_filesystem_body(&mut reader)?;
    validate_network_body(&mut reader)?;
    validate_registry_body(&mut reader)?;
    reader.finish()
}

fn validate_filesystem_body(reader: &mut BodyReader<'_>) -> Result<(), PolicyPayloadError> {
    let rule_count = reader.read_count()?;
    for _ in 0..rule_count {
        let record_length = reader.read_count()?;
        let mut record = BodyReader::new(reader.read_exact(record_length)?);
        match record.read_u8()? {
            0..=4 => {}
            _ => return Err(PolicyPayloadError::InvalidBody),
        }
        let component_count = record.read_count()?;
        for _ in 0..component_count {
            let kind = record.read_u8()?;
            let code_unit_count = record.read_count()?;
            if kind > 2 || (kind == 1 && code_unit_count != 0) {
                return Err(PolicyPayloadError::InvalidBody);
            }
            let byte_count = code_unit_count
                .checked_mul(2)
                .ok_or(PolicyPayloadError::InvalidBody)?;
            record.read_exact(byte_count)?;
        }
        record.finish()?;
    }
    Ok(())
}

fn validate_network_body(reader: &mut BodyReader<'_>) -> Result<(), PolicyPayloadError> {
    match reader.read_u8()? {
        0 | 1 => Ok(()),
        2 => validate_network_allow_list(reader),
        _ => Err(PolicyPayloadError::InvalidBody),
    }
}

fn validate_network_allow_list(reader: &mut BodyReader<'_>) -> Result<(), PolicyPayloadError> {
    let domain_count = reader.read_count()?;
    if domain_count > super::MAX_NETWORK_RULES_PER_CATEGORY {
        return Err(PolicyPayloadError::InvalidBody);
    }
    for _ in 0..domain_count {
        if reader.read_u8()? > 1 {
            return Err(PolicyPayloadError::InvalidBody);
        }
        let domain = reader.read_sized_bytes()?;
        if domain.is_empty() || !domain.is_ascii() {
            return Err(PolicyPayloadError::InvalidBody);
        }
    }

    let address_count = reader.read_count()?;
    if address_count > super::MAX_NETWORK_RULES_PER_CATEGORY {
        return Err(PolicyPayloadError::InvalidBody);
    }
    for _ in 0..address_count {
        let family = reader.read_u8()?;
        let prefix_length = reader.read_u8()?;
        match family {
            4 if prefix_length <= 32 => {
                reader.read_exact(4)?;
            }
            6 if prefix_length <= 128 => {
                reader.read_exact(16)?;
            }
            _ => return Err(PolicyPayloadError::InvalidBody),
        }
    }

    let port_count = reader.read_count()?;
    if port_count > super::MAX_NETWORK_RULES_PER_CATEGORY
        || domain_count
            .checked_add(address_count)
            .and_then(|count| count.checked_add(port_count))
            .is_none_or(|count| count > super::MAX_TOTAL_NETWORK_RULES)
    {
        return Err(PolicyPayloadError::InvalidBody);
    }
    for _ in 0..port_count {
        let start = reader.read_u16()?;
        let end = reader.read_u16()?;
        if start == 0 || start > end {
            return Err(PolicyPayloadError::InvalidBody);
        }
    }
    Ok(())
}

fn validate_registry_body(reader: &mut BodyReader<'_>) -> Result<(), PolicyPayloadError> {
    let rule_count = reader.read_count()?;
    if rule_count > super::MAX_COMPILED_REGISTRY_RULES {
        return Err(PolicyPayloadError::InvalidBody);
    }
    for _ in 0..rule_count {
        if reader.read_u8()? > 3 || reader.read_u8()? > 4 {
            return Err(PolicyPayloadError::InvalidBody);
        }
        let component_count = reader.read_count()?;
        for _ in 0..component_count {
            let component = reader.read_sized_bytes()?;
            let component =
                std::str::from_utf8(component).map_err(|_| PolicyPayloadError::InvalidBody)?;
            if component.is_empty() {
                return Err(PolicyPayloadError::InvalidBody);
            }
        }
    }
    Ok(())
}

struct BodyReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BodyReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PolicyPayloadError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PolicyPayloadError::InvalidBody)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PolicyPayloadError::InvalidBody)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, PolicyPayloadError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PolicyPayloadError> {
        let value: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| PolicyPayloadError::InvalidBody)?;
        Ok(u16::from_le_bytes(value))
    }

    fn read_count(&mut self) -> Result<usize, PolicyPayloadError> {
        let value: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| PolicyPayloadError::InvalidBody)?;
        Ok(u32::from_le_bytes(value) as usize)
    }

    fn read_sized_bytes(&mut self) -> Result<&'a [u8], PolicyPayloadError> {
        let length = self.read_count()?;
        self.read_exact(length)
    }

    fn finish(self) -> Result<(), PolicyPayloadError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PolicyPayloadError::InvalidBody)
        }
    }
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

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_sized_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
        push_u32(
            bytes,
            u32::try_from(value.len()).expect("test value length must fit u32"),
        );
        bytes.extend_from_slice(value);
    }

    fn signed_body(body: &[u8]) -> Vec<u8> {
        let body_length = u32::try_from(body.len()).expect("test body length must fit u32");
        let mut encoded = vec![0; HEADER_LENGTH];
        encoded[..MAGIC.len()].copy_from_slice(&MAGIC);
        encoded[VERSION_OFFSET..VERSION_OFFSET + 2]
            .copy_from_slice(&POLICY_PAYLOAD_VERSION.to_le_bytes());
        encoded[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 2]
            .copy_from_slice(&HEADER_LENGTH_WIRE.to_le_bytes());
        encoded[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&body_length.to_le_bytes());
        encoded.extend_from_slice(body);
        resign(&mut encoded);
        encoded
    }

    fn body_with_filesystem_record(record: &[u8]) -> Vec<u8> {
        let mut body = vec![1];
        push_u32(&mut body, 1);
        push_u32(
            &mut body,
            u32::try_from(record.len()).expect("record length must fit u32"),
        );
        body.extend_from_slice(record);
        body.push(1);
        push_u32(&mut body, 0);
        body
    }

    fn body_with_network(network: &[u8]) -> Vec<u8> {
        let mut body = vec![1];
        push_u32(&mut body, 0);
        body.extend_from_slice(network);
        push_u32(&mut body, 0);
        body
    }

    fn body_with_registry(registry: &[u8]) -> Vec<u8> {
        let mut body = vec![1];
        push_u32(&mut body, 0);
        body.push(1);
        body.extend_from_slice(registry);
        body
    }

    fn assert_invalid_body(body: &[u8]) {
        assert_eq!(
            verify(&signed_body(body)),
            Err(PolicyPayloadError::InvalidBody)
        );
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

    #[test]
    fn pol_010_validator_accepts_all_canonical_network_and_registry_wire_families() {
        let mut network = vec![2];
        push_u32(&mut network, 1);
        network.push(0);
        push_sized_bytes(&mut network, b"example.test");
        push_u32(&mut network, 2);
        network.extend_from_slice(&[4, 32, 127, 0, 0, 1]);
        network.extend_from_slice(&[6, 128]);
        network.extend_from_slice(&[0; 16]);
        push_u32(&mut network, 1);
        push_u16(&mut network, 1);
        push_u16(&mut network, u16::MAX);

        let mut body = body_with_network(&network);
        body.truncate(body.len() - 4);
        push_u32(&mut body, 1);
        body.extend_from_slice(&[3, 4]);
        push_u32(&mut body, 1);
        push_sized_bytes(&mut body, b"COMPONENT");

        assert!(verify(&signed_body(&body)).is_ok());
    }

    #[test]
    fn pol_010_invalid_filesystem_record_shapes_fail_closed() {
        let malformed_records = [
            vec![5, 0, 0, 0, 0],
            vec![0, 1, 0, 0, 0, 3, 0, 0, 0, 0],
            vec![0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0xFF],
        ];

        for record in malformed_records {
            assert_invalid_body(&body_with_filesystem_record(&record));
        }
    }

    #[test]
    fn pol_010_invalid_network_counts_and_domain_records_fail_closed() {
        let mut too_many_domains = vec![2];
        push_u32(
            &mut too_many_domains,
            u32::try_from(super::super::MAX_NETWORK_RULES_PER_CATEGORY + 1)
                .expect("limit must fit u32"),
        );

        let malformed_networks = [
            too_many_domains,
            vec![2, 1, 0, 0, 0, 2, 1, 0, 0, 0, b'a'],
            vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0xFF],
        ];
        for network in malformed_networks {
            assert_invalid_body(&body_with_network(&network));
        }
    }

    #[test]
    fn pol_010_invalid_network_address_and_port_records_fail_closed() {
        let mut too_many_addresses = vec![2];
        push_u32(&mut too_many_addresses, 0);
        push_u32(
            &mut too_many_addresses,
            u32::try_from(super::super::MAX_NETWORK_RULES_PER_CATEGORY + 1)
                .expect("limit must fit u32"),
        );

        let mut ipv4_prefix = vec![2];
        push_u32(&mut ipv4_prefix, 0);
        push_u32(&mut ipv4_prefix, 1);
        ipv4_prefix.extend_from_slice(&[4, 33, 127, 0, 0, 1]);

        let mut ipv6_prefix = vec![2];
        push_u32(&mut ipv6_prefix, 0);
        push_u32(&mut ipv6_prefix, 1);
        ipv6_prefix.extend_from_slice(&[6, 129]);
        ipv6_prefix.extend_from_slice(&[0; 16]);

        let mut unknown_family = vec![2];
        push_u32(&mut unknown_family, 0);
        push_u32(&mut unknown_family, 1);
        unknown_family.extend_from_slice(&[5, 0]);

        let mut too_many_ports = vec![2];
        push_u32(&mut too_many_ports, 0);
        push_u32(&mut too_many_ports, 0);
        push_u32(
            &mut too_many_ports,
            u32::try_from(super::super::MAX_NETWORK_RULES_PER_CATEGORY + 1)
                .expect("limit must fit u32"),
        );

        let mut zero_port = vec![2];
        push_u32(&mut zero_port, 0);
        push_u32(&mut zero_port, 0);
        push_u32(&mut zero_port, 1);
        push_u16(&mut zero_port, 0);
        push_u16(&mut zero_port, 1);

        let mut reversed_port = vec![2];
        push_u32(&mut reversed_port, 0);
        push_u32(&mut reversed_port, 0);
        push_u32(&mut reversed_port, 1);
        push_u16(&mut reversed_port, 2);
        push_u16(&mut reversed_port, 1);

        for network in [
            too_many_addresses,
            ipv4_prefix,
            ipv6_prefix,
            unknown_family,
            too_many_ports,
            zero_port,
            reversed_port,
        ] {
            assert_invalid_body(&body_with_network(&network));
        }
    }

    #[test]
    fn pol_010_network_total_rule_limit_is_validated_independently() {
        let mut network = vec![2];
        push_u32(&mut network, 1_024);
        for _ in 0..1_024 {
            network.push(0);
            push_sized_bytes(&mut network, b"a");
        }
        push_u32(&mut network, 1_024);
        for _ in 0..1_024 {
            network.extend_from_slice(&[4, 32, 127, 0, 0, 1]);
        }
        push_u32(&mut network, 1);

        assert_invalid_body(&body_with_network(&network));
    }

    #[test]
    fn pol_010_invalid_registry_records_fail_closed() {
        let mut too_many = Vec::new();
        push_u32(
            &mut too_many,
            u32::try_from(super::super::MAX_COMPILED_REGISTRY_RULES + 1)
                .expect("limit must fit u32"),
        );

        let mut invalid_kind = Vec::new();
        push_u32(&mut invalid_kind, 1);
        invalid_kind.extend_from_slice(&[4, 0]);
        push_u32(&mut invalid_kind, 0);

        let mut invalid_hive = Vec::new();
        push_u32(&mut invalid_hive, 1);
        invalid_hive.extend_from_slice(&[0, 5]);
        push_u32(&mut invalid_hive, 0);

        let mut empty_component = Vec::new();
        push_u32(&mut empty_component, 1);
        empty_component.extend_from_slice(&[0, 0]);
        push_u32(&mut empty_component, 1);
        push_u32(&mut empty_component, 0);

        let mut invalid_utf8 = Vec::new();
        push_u32(&mut invalid_utf8, 1);
        invalid_utf8.extend_from_slice(&[0, 0]);
        push_u32(&mut invalid_utf8, 1);
        push_sized_bytes(&mut invalid_utf8, &[0xFF]);

        for registry in [
            too_many,
            invalid_kind,
            invalid_hive,
            empty_component,
            invalid_utf8,
        ] {
            assert_invalid_body(&body_with_registry(&registry));
        }
    }

    #[test]
    fn pol_010_well_formed_body_with_trailing_byte_fails_closed() {
        let mut body = body_with_network(&[1]);
        body.push(0xFF);

        assert_invalid_body(&body);
    }

    #[test]
    fn ipc_015_native_minimal_policy_golden_vector_is_rust_compatible() {
        let encoded = [
            0x42, 0x4c, 0x50, 0x31, 0x01, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0c, 0xee,
            0x19, 0x24, 0xbb, 0x11, 0x38, 0x05, 0x95, 0x58, 0xbc, 0x22, 0x1f, 0x5a, 0x7a, 0x1c,
            0xf1, 0x59, 0x59, 0x20, 0x23, 0x31, 0x0c, 0x7d, 0x00, 0xcd, 0xa8, 0x2e, 0xed, 0x90,
            0xbb, 0xeb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let verified = verify(&encoded).expect("native golden payload must verify in Rust");

        assert_eq!(verified.version(), POLICY_PAYLOAD_VERSION);
        assert_eq!(verified.body(), &encoded[HEADER_LENGTH..]);
    }
}
