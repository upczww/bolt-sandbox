#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use super::*;

    #[test]
    fn ws_004_projected_workspace_protocol_matches_native_vectors() {
        let encoded = encode_request(
            Path::new(r"C:\source"),
            Path::new(r"C:\projection"),
            100,
            1_048_576,
        )
        .expect("valid projected request must encode");
        assert_eq!(&encoded[..4], b"BPJ1");
        assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_le_bytes([encoded[6], encoded[7]]), 80);

        assert_eq!(
            decode_response(
                &mut Cursor::new(b"BPY1\x01\x00\x0c\x00\x01\x00\x00\x00"),
                ProjectedWorkspaceResponseKind::Ready,
            ),
            Ok(ProjectedWorkspaceResult::Unavailable)
        );
        assert_eq!(
            encode_control(ProjectedWorkspaceControl::Materialize),
            b"BPC1\x01\x00\x01\x00"
        );
    }
}
