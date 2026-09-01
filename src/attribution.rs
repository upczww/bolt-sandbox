use std::num::NonZeroU64;

use crate::SandboxEvent;

const COMMAND_ID_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommandId([u8; COMMAND_ID_LENGTH]);

impl CommandId {
    #[must_use]
    pub fn new(bytes: [u8; COMMAND_ID_LENGTH]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMMAND_ID_LENGTH] {
        &self.0
    }

    pub(crate) fn generate() -> Result<Self, ()> {
        let mut bytes = [0_u8; COMMAND_ID_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| ())?;
        Self::new(bytes).ok_or(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExecutionId([u8; COMMAND_ID_LENGTH]);

impl ExecutionId {
    #[must_use]
    pub fn new(bytes: [u8; COMMAND_ID_LENGTH]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMMAND_ID_LENGTH] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyGeneration(NonZeroU64);

impl PolicyGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExecutionAttribution {
    pub execution_id: ExecutionId,
    pub command_id: CommandId,
    pub policy_generation: PolicyGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributedSandboxEvent {
    pub attribution: ExecutionAttribution,
    pub event: SandboxEvent,
}

#[cfg(test)]
mod tests {
    use super::{CommandId, ExecutionId, PolicyGeneration};

    #[test]
    fn attr_002_zero_is_rejected_and_nonzero_bytes_round_trip() {
        assert!(CommandId::new([0; 16]).is_none());

        let bytes = std::array::from_fn(|index| u8::try_from(index + 1).expect("index fits u8"));
        let command_id = CommandId::new(bytes).expect("nonzero ID must be valid");

        assert_eq!(command_id.as_bytes(), &bytes);
    }

    #[test]
    fn attr_002_execution_and_generation_identifiers_reject_zero() {
        assert!(ExecutionId::new([0; 16]).is_none());
        assert!(PolicyGeneration::new(0).is_none());
        assert_eq!(PolicyGeneration::new(7).expect("nonzero").get(), 7);
    }
}
