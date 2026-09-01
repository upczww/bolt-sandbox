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

#[cfg(test)]
mod tests {
    use super::CommandId;

    #[test]
    fn attr_002_zero_is_rejected_and_nonzero_bytes_round_trip() {
        assert!(CommandId::new([0; 16]).is_none());

        let bytes = std::array::from_fn(|index| u8::try_from(index + 1).expect("index fits u8"));
        let command_id = CommandId::new(bytes).expect("nonzero ID must be valid");

        assert_eq!(command_id.as_bytes(), &bytes);
    }
}
