#[cfg(test)]
mod tests {
    use super::*;

    const PE_OFFSET: usize = 0x80;

    fn pe_image(machine: u16) -> Vec<u8> {
        let mut image = vec![0; PE_OFFSET + 6];
        image[..2].copy_from_slice(b"MZ");
        let pe_offset = u32::try_from(PE_OFFSET).expect("test PE offset must fit u32");
        image[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        image[PE_OFFSET + 4..PE_OFFSET + 6].copy_from_slice(&machine.to_le_bytes());
        image
    }

    #[test]
    fn proc_028_x86_and_x64_machine_types_select_matching_hook_architecture() {
        assert_eq!(
            detect_image_architecture(&pe_image(0x014C)),
            Ok(ImageArchitecture::X86)
        );
        assert_eq!(
            detect_image_architecture(&pe_image(0x8664)),
            Ok(ImageArchitecture::X64)
        );
    }

    #[test]
    fn proc_029_arm64_and_unknown_machine_types_are_explicitly_unsupported() {
        for machine in [0xAA64, 0, 0xFFFF] {
            assert_eq!(
                detect_image_architecture(&pe_image(machine)),
                Err(ImageArchitectureError::UnsupportedMachine { machine })
            );
        }
    }

    #[test]
    fn proc_030_truncated_or_invalid_dos_headers_fail_closed() {
        assert_eq!(
            detect_image_architecture(&[0; 0x3F]),
            Err(ImageArchitectureError::TruncatedDosHeader)
        );
        let mut invalid = pe_image(0x8664);
        invalid[..2].copy_from_slice(b"NZ");
        assert_eq!(
            detect_image_architecture(&invalid),
            Err(ImageArchitectureError::InvalidDosSignature)
        );
    }

    #[test]
    fn proc_030_out_of_range_pe_offset_and_truncated_coff_header_fail_closed() {
        let mut outside = pe_image(0x8664);
        outside[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            detect_image_architecture(&outside),
            Err(ImageArchitectureError::PeHeaderOutOfRange)
        );

        let mut truncated = pe_image(0x8664);
        truncated.truncate(PE_OFFSET + 5);
        assert_eq!(
            detect_image_architecture(&truncated),
            Err(ImageArchitectureError::TruncatedCoffHeader)
        );
    }

    #[test]
    fn proc_030_invalid_pe_signature_is_not_interpreted_as_an_image() {
        let mut invalid = pe_image(0x014C);
        invalid[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PX\0\0");

        assert_eq!(
            detect_image_architecture(&invalid),
            Err(ImageArchitectureError::InvalidPeSignature)
        );
    }
}
