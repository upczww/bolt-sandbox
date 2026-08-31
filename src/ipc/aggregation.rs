use std::num::NonZeroUsize;

use crate::SandboxEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AggregationDisposition {
    Added,
    Duplicate { duplicate_count: u64 },
    DroppedDistinct { dropped_count: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AggregationError {
    NotViolation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AggregatedViolation {
    pub(super) event: SandboxEvent,
    pub(super) duplicate_count: u64,
}

pub(super) struct ViolationAggregator {
    maximum_entries: NonZeroUsize,
    entries: Vec<AggregatedViolation>,
    dropped_distinct_count: u64,
}

impl ViolationAggregator {
    pub(super) const fn new(maximum_entries: NonZeroUsize) -> Self {
        Self {
            maximum_entries,
            entries: Vec::new(),
            dropped_distinct_count: 0,
        }
    }

    pub(super) fn observe(
        &mut self,
        event: SandboxEvent,
    ) -> Result<AggregationDisposition, AggregationError> {
        if !is_violation(&event) {
            return Err(AggregationError::NotViolation);
        }
        if let Some(existing) = self.entries.iter_mut().find(|entry| entry.event == event) {
            existing.duplicate_count = existing.duplicate_count.saturating_add(1);
            return Ok(AggregationDisposition::Duplicate {
                duplicate_count: existing.duplicate_count,
            });
        }
        if self.entries.len() == self.maximum_entries.get() {
            self.dropped_distinct_count = self.dropped_distinct_count.saturating_add(1);
            return Ok(AggregationDisposition::DroppedDistinct {
                dropped_count: self.dropped_distinct_count,
            });
        }
        self.entries.push(AggregatedViolation {
            event,
            duplicate_count: 0,
        });
        Ok(AggregationDisposition::Added)
    }

    pub(super) fn entries(&self) -> &[AggregatedViolation] {
        &self.entries
    }

    pub(super) const fn dropped_distinct_count(&self) -> u64 {
        self.dropped_distinct_count
    }
}

const fn is_violation(event: &SandboxEvent) -> bool {
    matches!(
        event,
        SandboxEvent::FilesystemViolation(_)
            | SandboxEvent::RegistryViolation(_)
            | SandboxEvent::NetworkViolation(_)
            | SandboxEvent::ProcessViolation(_)
    )
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        path::PathBuf,
    };

    use super::*;
    use crate::{
        FilesystemOperation, FilesystemViolation, NetworkOperation, NetworkTarget,
        NetworkViolation, ProcessOperation, ProcessViolation, SandboxEvent,
    };

    fn violation(process_id: u32, operation: FilesystemOperation, path: &str) -> SandboxEvent {
        SandboxEvent::FilesystemViolation(FilesystemViolation {
            process_id,
            operation,
            path: PathBuf::from(path),
        })
    }

    #[test]
    fn evt_004_repeated_identical_violations_preserve_first_and_increment_count() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(2).expect("nonzero"));
        let first = violation(10, FilesystemOperation::Write, r"C:\denied.txt");

        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Added)
        );
        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Duplicate { duplicate_count: 1 })
        );
        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Duplicate { duplicate_count: 2 })
        );

        assert_eq!(aggregator.entries().len(), 1);
        assert_eq!(aggregator.entries()[0].event, first);
        assert_eq!(aggregator.entries()[0].duplicate_count, 2);
    }

    #[test]
    fn fs_056_canonical_alias_events_aggregate_under_one_resource() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(2).expect("nonzero"));
        let canonical_from_win32 =
            violation(42, FilesystemOperation::Write, r"C:\denied\protected.txt");
        let canonical_from_native_alias =
            violation(42, FilesystemOperation::Write, r"C:\denied\protected.txt");

        assert_eq!(
            aggregator.observe(canonical_from_win32.clone()),
            Ok(AggregationDisposition::Added)
        );
        assert_eq!(
            aggregator.observe(canonical_from_native_alias),
            Ok(AggregationDisposition::Duplicate { duplicate_count: 1 })
        );
        assert_eq!(aggregator.entries().len(), 1);
        assert_eq!(aggregator.entries()[0].event, canonical_from_win32);
        assert_eq!(aggregator.entries()[0].duplicate_count, 1);
    }

    #[test]
    fn evt_005_process_operation_and_resource_are_part_of_the_aggregate_key() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(6).expect("nonzero"));
        let events = [
            violation(1, FilesystemOperation::Write, r"C:\same.txt"),
            violation(2, FilesystemOperation::Write, r"C:\same.txt"),
            violation(1, FilesystemOperation::Read, r"C:\same.txt"),
            violation(1, FilesystemOperation::Write, r"C:\other.txt"),
            SandboxEvent::ProcessViolation(ProcessViolation {
                process_id: 1,
                operation: ProcessOperation::CreateWithToken,
            }),
            SandboxEvent::ProcessViolation(ProcessViolation {
                process_id: 1,
                operation: ProcessOperation::CreateWithLogon,
            }),
        ];

        for event in events {
            assert_eq!(aggregator.observe(event), Ok(AggregationDisposition::Added));
        }

        assert_eq!(aggregator.entries().len(), 6);
    }

    #[test]
    fn evt_006_capacity_drops_new_distinct_items_but_existing_counts_survive() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(1).expect("nonzero"));
        let first = violation(1, FilesystemOperation::Write, r"C:\first.txt");
        let second = violation(1, FilesystemOperation::Write, r"C:\second.txt");

        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Added)
        );
        assert_eq!(
            aggregator.observe(second),
            Ok(AggregationDisposition::DroppedDistinct { dropped_count: 1 })
        );
        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Duplicate { duplicate_count: 1 })
        );

        assert_eq!(aggregator.entries().len(), 1);
        assert_eq!(aggregator.entries()[0].event, first);
        assert_eq!(aggregator.entries()[0].duplicate_count, 1);
        assert_eq!(aggregator.dropped_distinct_count(), 1);
    }

    #[test]
    fn evt_004_non_violation_events_are_rejected_instead_of_silently_aggregated() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(1).expect("nonzero"));

        assert_eq!(
            aggregator.observe(SandboxEvent::Ready),
            Err(AggregationError::NotViolation)
        );
        assert!(aggregator.entries().is_empty());
    }

    #[test]
    fn net_029_drop_summary_bypasses_violation_aggregation() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(1).expect("nonzero"));

        assert_eq!(
            aggregator.observe(SandboxEvent::EventsDropped(crate::EventsDropped {
                process_id: 9,
                count: 42,
            })),
            Err(AggregationError::NotViolation)
        );
        assert!(aggregator.entries().is_empty());
    }

    #[test]
    fn net_029_network_duplicates_and_distinct_capacity_loss_remain_counted() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(1).expect("nonzero"));
        let first = SandboxEvent::NetworkViolation(NetworkViolation {
            process_id: 9,
            operation: NetworkOperation::Connect,
            target: NetworkTarget::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                443,
            )),
        });
        let distinct = SandboxEvent::NetworkViolation(NetworkViolation {
            process_id: 9,
            operation: NetworkOperation::Send,
            target: NetworkTarget::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
                53,
            )),
        });

        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Added)
        );
        assert_eq!(
            aggregator.observe(first.clone()),
            Ok(AggregationDisposition::Duplicate { duplicate_count: 1 })
        );
        assert_eq!(
            aggregator.observe(distinct),
            Ok(AggregationDisposition::DroppedDistinct { dropped_count: 1 })
        );
        assert_eq!(aggregator.entries()[0].event, first);
        assert_eq!(aggregator.entries()[0].duplicate_count, 1);
        assert_eq!(aggregator.dropped_distinct_count(), 1);
    }
}
