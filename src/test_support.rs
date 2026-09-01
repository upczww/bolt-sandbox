use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_MUTATION_CASES: usize = 4_096;

pub(crate) fn deterministic_mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut cases = BTreeSet::new();
    cases.insert(Vec::new());

    for length in representative_offsets(seed.len()) {
        cases.insert(seed[..length].to_vec());
    }

    for offset in representative_byte_offsets(seed.len()) {
        for mask in [0x01, 0x80, 0xff] {
            let mut mutated = seed.to_vec();
            mutated[offset] ^= mask;
            cases.insert(mutated);
        }

        for replacement in [0x00, 0x7f, 0x80, 0xff] {
            let mut mutated = seed.to_vec();
            mutated[offset] = replacement;
            cases.insert(mutated);
        }
    }

    for suffix in [
        vec![0],
        vec![0xff],
        vec![0; 2],
        vec![0xff; 4],
        vec![0; 8],
        vec![0xff; 16],
    ] {
        let mut mutated = seed.to_vec();
        mutated.extend_from_slice(&suffix);
        cases.insert(mutated);
    }

    cases.into_iter().take(MAX_MUTATION_CASES).collect()
}

pub(crate) fn assert_total_parser(parser_name: &str, seeds: &[Vec<u8>], parser: impl Fn(&[u8])) {
    assert!(!seeds.is_empty(), "{parser_name} corpus needs a seed");
    for (seed_index, seed) in seeds.iter().enumerate() {
        for (case_index, case) in deterministic_mutations(seed).iter().enumerate() {
            let outcome = catch_unwind(AssertUnwindSafe(|| parser(case)));
            assert!(
                outcome.is_ok(),
                "{parser_name} panicked for seed {seed_index}, mutation {case_index}, length {}",
                case.len()
            );
        }
    }
}

fn representative_offsets(length: usize) -> Vec<usize> {
    if length <= 512 {
        return (0..=length).collect();
    }

    let mut offsets = BTreeSet::from([0, length]);
    if length > 0 {
        offsets.extend([1, length / 2, length.saturating_sub(1)]);
    }
    offsets
        .into_iter()
        .filter(|offset| *offset <= length)
        .collect()
}

fn representative_byte_offsets(length: usize) -> Vec<usize> {
    if length <= 512 {
        return (0..length).collect();
    }

    let mut offsets = BTreeSet::new();
    for index in 0..256 {
        offsets.insert(index);
        offsets.insert(length - 1 - index);
    }
    offsets.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::deterministic_mutations;

    #[test]
    fn fuzz_001_mutation_corpus_is_deterministic_bounded_and_covers_each_input_byte() {
        let seed = b"Bolt parser seed";

        let first = deterministic_mutations(seed);
        let second = deterministic_mutations(seed);

        assert_eq!(first, second);
        assert!(!first.is_empty());
        assert!(first.len() <= 4_096);
        assert!(first.iter().all(|case| case.len() <= seed.len() + 16));
        assert!(first.iter().any(Vec::is_empty));
        for offset in 0..seed.len() {
            assert!(first.iter().any(|case| {
                case.len() == seed.len()
                    && case
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| index == offset || *byte == seed[index])
                    && case[offset] != seed[offset]
            }));
        }
    }
}
