use std::io::{ErrorKind, Read, Seek, SeekFrom};

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
    ReadFailure,
}

pub(super) fn detect_image_architecture_from_reader<R: Read + Seek>(
    reader: &mut R,
) -> Result<ImageArchitecture, ImageArchitectureError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| ImageArchitectureError::ReadFailure)?;
    let mut dos_header = [0_u8; DOS_HEADER_LENGTH];
    reader.read_exact(&mut dos_header).map_err(|error| {
        map_read_error(error.kind(), ImageArchitectureError::TruncatedDosHeader)
    })?;
    if dos_header[..2] != *b"MZ" {
        return Err(ImageArchitectureError::InvalidDosSignature);
    }
    let pe_offset = usize::try_from(read_u32(&dos_header, PE_OFFSET_FIELD))
        .map_err(|_| ImageArchitectureError::PeHeaderOutOfRange)?;
    if pe_offset < DOS_HEADER_LENGTH {
        return Err(ImageArchitectureError::PeHeaderOutOfRange);
    }

    reader
        .seek(SeekFrom::Start(
            u64::try_from(pe_offset).map_err(|_| ImageArchitectureError::PeHeaderOutOfRange)?,
        ))
        .map_err(|_| ImageArchitectureError::ReadFailure)?;
    let mut pe_prefix = [0_u8; PE_PREFIX_LENGTH];
    reader.read_exact(&mut pe_prefix).map_err(|error| {
        map_read_error(error.kind(), ImageArchitectureError::TruncatedCoffHeader)
    })?;
    parse_pe_prefix(pe_prefix)
}

const fn map_read_error(
    kind: ErrorKind,
    truncated: ImageArchitectureError,
) -> ImageArchitectureError {
    if matches!(kind, ErrorKind::UnexpectedEof) {
        truncated
    } else {
        ImageArchitectureError::ReadFailure
    }
}

fn parse_pe_prefix(
    prefix: [u8; PE_PREFIX_LENGTH],
) -> Result<ImageArchitecture, ImageArchitectureError> {
    if prefix[..4] != *b"PE\0\0" {
        return Err(ImageArchitectureError::InvalidPeSignature);
    }
    let machine = read_u16(&prefix, 4);
    match machine {
        IMAGE_FILE_MACHINE_I386 => Ok(ImageArchitecture::X86),
        IMAGE_FILE_MACHINE_AMD64 => Ok(ImageArchitecture::X64),
        _ => Err(ImageArchitectureError::UnsupportedMachine { machine }),
    }
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
    let prefix: [u8; PE_PREFIX_LENGTH] = image[pe_offset..pe_end]
        .try_into()
        .map_err(|_| ImageArchitectureError::TruncatedCoffHeader)?;
    parse_pe_prefix(prefix)
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
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

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

    struct RecordingReader {
        inner: Cursor<Vec<u8>>,
        maximum_read_request: usize,
        total_bytes_read: usize,
    }

    impl RecordingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                maximum_read_request: 0,
                total_bytes_read: 0,
            }
        }
    }

    impl Read for RecordingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.maximum_read_request = self.maximum_read_request.max(buffer.len());
            let count = self.inner.read(buffer)?;
            self.total_bytes_read += count;
            Ok(count)
        }
    }

    impl Seek for RecordingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn proc_030_reader_detection_uses_fixed_header_reads_not_image_sized_allocation() {
        let mut reader = RecordingReader::new(pe_image(0x8664));

        assert_eq!(
            detect_image_architecture_from_reader(&mut reader),
            Ok(ImageArchitecture::X64)
        );
        assert_eq!(reader.maximum_read_request, DOS_HEADER_LENGTH);
        assert_eq!(
            reader.total_bytes_read,
            DOS_HEADER_LENGTH + PE_PREFIX_LENGTH
        );
    }

    #[test]
    fn proc_030_reader_short_reads_map_to_the_exact_header_stage() {
        let mut short_dos = Cursor::new(vec![0; DOS_HEADER_LENGTH - 1]);
        assert_eq!(
            detect_image_architecture_from_reader(&mut short_dos),
            Err(ImageArchitectureError::TruncatedDosHeader)
        );

        let mut short_coff = Cursor::new({
            let mut bytes = pe_image(0x8664);
            bytes.truncate(PE_OFFSET + PE_PREFIX_LENGTH - 1);
            bytes
        });
        assert_eq!(
            detect_image_architecture_from_reader(&mut short_coff),
            Err(ImageArchitectureError::TruncatedCoffHeader)
        );
    }
}
