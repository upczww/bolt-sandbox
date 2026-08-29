use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamBufferError {
    ZeroCapacity,
    AlreadyClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IngestOutcome {
    pub(super) buffered: usize,
    pub(super) dropped: usize,
}

impl IngestOutcome {
    pub(super) const fn buffered(buffered: usize) -> Self {
        Self {
            buffered,
            dropped: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct StreamLossState {
    pub(super) capacity_exceeded: bool,
    pub(super) receiver_disconnected: bool,
    pub(super) dropped_bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BoundedByteStream {
    capacity: usize,
    buffered: VecDeque<u8>,
    loss: StreamLossState,
    eof: bool,
}

impl BoundedByteStream {
    pub(super) fn new(capacity: usize) -> Result<Self, StreamBufferError> {
        if capacity == 0 {
            return Err(StreamBufferError::ZeroCapacity);
        }
        Ok(Self {
            capacity,
            buffered: VecDeque::with_capacity(capacity),
            loss: StreamLossState::default(),
            eof: false,
        })
    }

    pub(super) fn ingest(&mut self, bytes: &[u8]) -> Result<IngestOutcome, StreamBufferError> {
        if self.eof {
            return Err(StreamBufferError::AlreadyClosed);
        }
        if self.loss.receiver_disconnected {
            self.record_dropped(bytes.len());
            return Ok(IngestOutcome {
                buffered: 0,
                dropped: bytes.len(),
            });
        }

        let buffered = bytes.len().min(self.capacity - self.buffered.len());
        self.buffered.extend(&bytes[..buffered]);
        let dropped = bytes.len() - buffered;
        if dropped != 0 {
            self.loss.capacity_exceeded = true;
            self.record_dropped(dropped);
        }
        Ok(IngestOutcome { buffered, dropped })
    }

    pub(super) fn take(&mut self, maximum: usize) -> Vec<u8> {
        let count = maximum.min(self.buffered.len());
        self.buffered.drain(..count).collect()
    }

    pub(super) fn disconnect_receiver(&mut self) {
        if self.loss.receiver_disconnected {
            return;
        }
        self.loss.receiver_disconnected = true;
        let abandoned = self.buffered.len();
        self.buffered.clear();
        self.record_dropped(abandoned);
    }

    pub(super) fn mark_eof(&mut self) -> Result<(), StreamBufferError> {
        if self.eof {
            return Err(StreamBufferError::AlreadyClosed);
        }
        self.eof = true;
        Ok(())
    }

    pub(super) fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    pub(super) const fn loss_state(&self) -> StreamLossState {
        self.loss
    }

    fn record_dropped(&mut self, dropped: usize) {
        let dropped = u64::try_from(dropped).unwrap_or(u64::MAX);
        self.loss.dropped_bytes = self.loss.dropped_bytes.saturating_add(dropped);
    }
}

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
