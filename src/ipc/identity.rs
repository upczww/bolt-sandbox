#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FixedEntropy {
        bytes: [u8; 32],
        calls: Vec<usize>,
        fail: bool,
    }

    impl EntropySource for FixedEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), ()> {
            self.calls.push(destination.len());
            destination.copy_from_slice(&self.bytes[..destination.len()]);
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    #[test]
    fn ipc_001_pipe_identifier_and_handshake_nonce_use_disjoint_entropy() {
        let mut source = FixedEntropy {
            bytes: std::array::from_fn(|index| u8::try_from(index).expect("index fits u8")),
            ..FixedEntropy::default()
        };

        let identity = ExecutionIdentity::generate_with(&mut source).expect("entropy must succeed");

        assert_eq!(source.calls, [32]);
        assert_eq!(
            identity.endpoint_name(),
            r"\\.\pipe\bolt-sandbox-000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            identity.handshake_nonce(),
            &[
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f,
            ]
        );
        assert!(!identity.endpoint_name().contains("1011121314151617"));
    }

    #[test]
    fn ipc_017_entropy_failure_has_no_predictable_fallback_identity() {
        let mut source = FixedEntropy {
            bytes: [0xA5; 32],
            fail: true,
            ..FixedEntropy::default()
        };

        assert_eq!(
            ExecutionIdentity::generate_with(&mut source),
            Err(ExecutionIdentityError::EntropyUnavailable)
        );
        assert_eq!(source.calls, [32]);
    }

    #[test]
    fn ipc_001_system_identity_has_fixed_safe_endpoint_shape() {
        let identity = ExecutionIdentity::generate().expect("system entropy must be available");
        let suffix = identity
            .endpoint_name()
            .strip_prefix(r"\\.\pipe\bolt-sandbox-")
            .expect("endpoint prefix must be fixed");

        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(identity.handshake_nonce().len(), 16);
    }
}
