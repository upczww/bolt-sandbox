const DOS_HEADER_LENGTH: usize = 0x40;
const PE_OFFSET_FIELD: usize = 0x3C;
const PE_PREFIX_LENGTH: usize = 6;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImageArchitecture {
    X86,
    X64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImageArchitectureError {
    TruncatedDosHeader,
    InvalidDosSignature,
    PeHeaderOutOfRange,
    TruncatedCoffHeader,
    InvalidPeSignature,
    UnsupportedMachine { machine: u16 },
}

pub(super) fn detect_image_architecture(
    image: &[u8],
) -> Result<ImageArchitecture, ImageArchitectureError> {
    if image.len() < DOS_HEADER_LENGTH {
        return Err(ImageArchitectureError::TruncatedDosHeader);
    }
    if image[..2] != *b"MZ" {
        return Err(ImageArchitectureError::InvalidDosSignature);
    }

    let pe_offset = usize::try_from(read_u32(image, PE_OFFSET_FIELD))
        .map_err(|_| ImageArchitectureError::PeHeaderOutOfRange)?;
    if pe_offset < DOS_HEADER_LENGTH || pe_offset >= image.len() {
        return Err(ImageArchitectureError::PeHeaderOutOfRange);
    }
    let pe_end = pe_offset
        .checked_add(PE_PREFIX_LENGTH)
        .ok_or(ImageArchitectureError::PeHeaderOutOfRange)?;
    if pe_end > image.len() {
        return Err(ImageArchitectureError::TruncatedCoffHeader);
    }
    if image[pe_offset..pe_offset + 4] != *b"PE\0\0" {
        return Err(ImageArchitectureError::InvalidPeSignature);
    }

    let machine = read_u16(image, pe_offset + 4);
    match machine {
        IMAGE_FILE_MACHINE_I386 => Ok(ImageArchitecture::X86),
        IMAGE_FILE_MACHINE_AMD64 => Ok(ImageArchitecture::X64),
        _ => Err(ImageArchitectureError::UnsupportedMachine { machine }),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

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
