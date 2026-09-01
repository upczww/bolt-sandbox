use std::{net::SocketAddr, path::PathBuf};

use crate::{
    FilesystemOperation, NetworkOperation, NetworkTarget, ProcessOperation, RegistryOperation,
    SandboxEvent, ViolationAggregate,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccessOperation {
    Filesystem(FilesystemOperation),
    Registry(RegistryOperation),
    Network(NetworkOperation),
    Process(ProcessOperation),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AccessResource {
    FilesystemPath(PathBuf),
    RegistryKey(String),
    NetworkDomain(String),
    NetworkEndpoint(SocketAddr),
    ProcessAuthority,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccessDenial {
    pub process_id: u32,
    pub operation: AccessOperation,
    pub resource: AccessResource,
    pub occurrences: u64,
}

impl ViolationAggregate {
    #[must_use]
    pub fn access_denial(&self) -> Option<AccessDenial> {
        let occurrences = self.duplicate_count.saturating_add(1);
        match &self.event {
            SandboxEvent::FilesystemViolation(violation) => Some(AccessDenial {
                process_id: violation.process_id,
                operation: AccessOperation::Filesystem(violation.operation),
                resource: AccessResource::FilesystemPath(violation.path.clone()),
                occurrences,
            }),
            SandboxEvent::RegistryViolation(violation) => Some(AccessDenial {
                process_id: violation.process_id,
                operation: AccessOperation::Registry(violation.operation),
                resource: AccessResource::RegistryKey(violation.key.clone()),
                occurrences,
            }),
            SandboxEvent::NetworkViolation(violation) => Some(AccessDenial {
                process_id: violation.process_id,
                operation: AccessOperation::Network(violation.operation),
                resource: match &violation.target {
                    NetworkTarget::Domain(domain) => AccessResource::NetworkDomain(domain.clone()),
                    NetworkTarget::Socket(endpoint) => AccessResource::NetworkEndpoint(*endpoint),
                },
                occurrences,
            }),
            SandboxEvent::ProcessViolation(violation) => Some(AccessDenial {
                process_id: violation.process_id,
                operation: AccessOperation::Process(violation.operation),
                resource: AccessResource::ProcessAuthority,
                occurrences,
            }),
            SandboxEvent::Ready
            | SandboxEvent::EventsDropped(_)
            | SandboxEvent::RecoveryArtifactCreated(_)
            | SandboxEvent::RecoveryFailed(_)
            | SandboxEvent::ChildInjectionFailed(_)
            | SandboxEvent::ProcessExited(_) => None,
        }
    }
}
