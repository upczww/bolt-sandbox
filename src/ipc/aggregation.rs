#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, path::PathBuf};

    use super::*;
    use crate::{FilesystemOperation, FilesystemViolation, SandboxEvent};

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
    fn evt_005_process_operation_and_resource_are_part_of_the_aggregate_key() {
        let mut aggregator = ViolationAggregator::new(NonZeroUsize::new(4).expect("nonzero"));
        let events = [
            violation(1, FilesystemOperation::Write, r"C:\same.txt"),
            violation(2, FilesystemOperation::Write, r"C:\same.txt"),
            violation(1, FilesystemOperation::Read, r"C:\same.txt"),
            violation(1, FilesystemOperation::Write, r"C:\other.txt"),
        ];

        for event in events {
            assert_eq!(aggregator.observe(event), Ok(AggregationDisposition::Added));
        }

        assert_eq!(aggregator.entries().len(), 4);
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
}
