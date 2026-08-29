#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn life_002_interleaved_streams_remain_independent() {
        let mut stdout = BoundedByteStream::new(8).expect("valid stdout capacity");
        let mut stderr = BoundedByteStream::new(8).expect("valid stderr capacity");

        stdout.ingest(b"out-").expect("stdout remains open");
        stderr.ingest(b"err-").expect("stderr remains open");
        stdout.ingest(b"data").expect("stdout remains open");
        stderr.ingest(b"data").expect("stderr remains open");

        assert_eq!(stdout.take(8), b"out-data");
        assert_eq!(stderr.take(8), b"err-data");
    }

    #[test]
    fn life_011_binary_and_split_multibyte_data_are_not_decoded() {
        let mut stream = BoundedByteStream::new(8).expect("valid capacity");

        stream
            .ingest(&[0x00, 0xff, 0xe4])
            .expect("first chunk remains open");
        stream
            .ingest(&[0xb8, 0xad, 0x80])
            .expect("second chunk remains open");

        assert_eq!(stream.take(2), [0x00, 0xff]);
        assert_eq!(stream.take(8), [0xe4, 0xb8, 0xad, 0x80]);
        assert_eq!(stream.loss_state(), StreamLossState::default());
    }

    #[test]
    fn life_009_slow_receiver_is_bounded_and_reports_capacity_loss() {
        let mut stream = BoundedByteStream::new(4).expect("valid capacity");

        assert_eq!(
            stream.ingest(b"abcdef"),
            Ok(IngestOutcome {
                buffered: 4,
                dropped: 2,
            })
        );

        assert_eq!(stream.buffered_len(), 4);
        assert_eq!(stream.take(8), b"abcd");
        assert_eq!(
            stream.loss_state(),
            StreamLossState {
                capacity_exceeded: true,
                receiver_disconnected: false,
                dropped_bytes: 2,
            }
        );
    }

    #[test]
    fn life_016_disconnect_discards_buffered_and_future_bytes() {
        let mut stream = BoundedByteStream::new(4).expect("valid capacity");
        stream.ingest(b"abc").expect("stream remains open");

        stream.disconnect_receiver();
        assert_eq!(stream.buffered_len(), 0);
        assert_eq!(
            stream.ingest(b"defgh"),
            Ok(IngestOutcome {
                buffered: 0,
                dropped: 5,
            })
        );
        assert!(stream.take(8).is_empty());
        assert_eq!(
            stream.loss_state(),
            StreamLossState {
                capacity_exceeded: false,
                receiver_disconnected: true,
                dropped_bytes: 8,
            }
        );
    }

    #[test]
    fn life_013_eof_is_committed_once_without_affecting_other_streams() {
        let mut closed = BoundedByteStream::new(4).expect("valid capacity");
        let mut open = BoundedByteStream::new(4).expect("valid capacity");

        assert_eq!(closed.mark_eof(), Ok(()));
        assert_eq!(closed.mark_eof(), Err(StreamBufferError::AlreadyClosed));
        assert_eq!(
            closed.ingest(b"late"),
            Err(StreamBufferError::AlreadyClosed)
        );
        assert_eq!(open.ingest(b"open"), Ok(IngestOutcome::buffered(4)));
        assert_eq!(open.take(4), b"open");
    }

    #[test]
    fn life_009_zero_capacity_is_rejected_and_empty_io_is_a_noop() {
        assert_eq!(
            BoundedByteStream::new(0),
            Err(StreamBufferError::ZeroCapacity)
        );

        let mut stream = BoundedByteStream::new(1).expect("valid capacity");
        assert_eq!(stream.ingest(&[]), Ok(IngestOutcome::buffered(0)));
        assert!(stream.take(0).is_empty());
        assert_eq!(stream.buffered_len(), 0);
    }
}
