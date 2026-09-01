#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use super::*;

    #[test]
    fn ws_023_workspace_security_request_and_response_match_native_vectors() {
        let encoded = encode_request(
            WorkspaceSecurityOperation::Copy,
            Path::new(r"C:\work\source"),
            Path::new(r"C:\work\staged"),
            100,
        )
        .expect("valid request must encode");
        assert_eq!(&encoded[..4], b"BWS1");
        assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_le_bytes([encoded[6], encoded[7]]), 64);

        let response = b"BWR1\x01\x00\x0c\x00\x06\x00\x00\x00";
        assert_eq!(
            decode_response(&mut Cursor::new(response)),
            Ok(WorkspaceSecurityResult::Mismatch)
        );
    }

    #[test]
    fn ws_023_workspace_security_protocol_rejects_invalid_bounds_and_response() {
        assert_eq!(
            encode_request(
                WorkspaceSecurityOperation::Verify,
                Path::new(r"C:\work\source"),
                Path::new(r"C:\work\staged"),
                0,
            ),
            Err(WorkspaceSecurityProtocolError::InvalidField)
        );
        assert_eq!(
            decode_response(&mut Cursor::new(b"bad-response")),
            Err(WorkspaceSecurityProtocolError::InvalidResponse)
        );
    }
}
