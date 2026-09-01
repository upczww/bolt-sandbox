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
