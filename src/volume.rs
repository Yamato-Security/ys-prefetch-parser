use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{
    NtfsFile, PrefetchFileInformation, VolumeInformation, array_at, bytes_at, u16_at_pos,
    u32_at_pos, u64_at_pos, utf16_at_offset,
};

/// Size of a volume information entry in format version 17.
const VOLUME_ENTRY_SIZE_V17: usize = 40;
/// Size of a volume information entry in format versions 23 and 26.
const VOLUME_ENTRY_SIZE_V23: usize = 104;
/// Size of a volume information entry in format versions 30 and 31.
const VOLUME_ENTRY_SIZE_V30: usize = 96;
/// Size of the file references header in format version 17 (version and count).
const FILE_REFERENCES_HEADER_V17: usize = 8;
/// Size of the file references header in format versions 23 and later.
const FILE_REFERENCES_HEADER_V23: usize = 16;

pub fn volume_info_26(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info_23(file_buffer, info)
}

pub fn volume_info_30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info(
        file_buffer,
        info,
        VOLUME_ENTRY_SIZE_V30,
        FILE_REFERENCES_HEADER_V23,
    )
}

pub fn volume_info_17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info(
        file_buffer,
        info,
        VOLUME_ENTRY_SIZE_V17,
        FILE_REFERENCES_HEADER_V17,
    )
}

pub fn volume_info_23(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info(
        file_buffer,
        info,
        VOLUME_ENTRY_SIZE_V23,
        FILE_REFERENCES_HEADER_V23,
    )
}

/// Parses the volume information block. All offsets in a volume entry are relative to the
/// start of the block.
fn volume_info(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    entry_size: usize,
    file_references_header: usize,
) -> ForensicResult<Vec<VolumeInformation>> {
    let volume_data = bytes_at(
        file_buffer,
        info.volume_information_offset as usize,
        info.volume_information_size as usize,
        "volume information block",
    )?;
    let entries = array_at(
        volume_data,
        0,
        info.volume_count as usize,
        entry_size,
        "volume information array",
    )?;
    let mut volumes = Vec::with_capacity(info.volume_count as usize);
    for entry in entries.chunks_exact(entry_size) {
        let volume_device_path_offset = u32_at_pos(entry, 0) as usize;
        let volume_device_path_characters = u32_at_pos(entry, 4) as usize;
        let device_path = utf16_at_offset(
            volume_data,
            volume_device_path_offset,
            volume_device_path_characters.saturating_mul(2),
        )
        .map_err(|_| {
            ForensicError::bad_format_str(
                "The device path position is greater than the volume buffer",
            )
        })?;
        let creation_time = u64_at_pos(entry, 8);
        let serial_number = u32_at_pos(entry, 16);
        let file_references_offset = u32_at_pos(entry, 20) as usize;
        let file_references_data_size = u32_at_pos(entry, 24) as usize;
        let file_data = bytes_at(
            volume_data,
            file_references_offset,
            file_references_data_size,
            "file reference block",
        )?;
        let file_references = extract_file_references(file_data, file_references_header)?;
        let directory_strings_offset = u32_at_pos(entry, 28) as usize;
        let directory_strings_count = u32_at_pos(entry, 32) as usize;
        let directory_data = volume_data.get(directory_strings_offset..).ok_or_else(|| {
            ForensicError::bad_format_str(
                "The directory strings position is greater than the volume buffer",
            )
        })?;
        let directory_strings = extract_directory_strings(directory_data, directory_strings_count)?;
        volumes.push(VolumeInformation {
            device_path,
            directory_strings,
            file_references,
            creation_time,
            serial_number,
        });
    }
    Ok(volumes)
}

/// Parses the NTFS file references of a volume: a header holding the number of references,
/// followed by 8-byte references (48-bit MFT entry, 16-bit sequence number).
fn extract_file_references(
    file_reference: &[u8],
    header_size: usize,
) -> ForensicResult<Vec<NtfsFile>> {
    if file_reference.len() < header_size {
        return Err(ForensicError::Other(
            "Invalid size for file references".into(),
        ));
    }
    let file_reference_count = u32_at_pos(file_reference, 4) as usize;
    let references = array_at(
        file_reference,
        header_size,
        file_reference_count,
        8,
        "file reference array",
    )
    .map_err(|_| {
        ForensicError::bad_format_str("The file reference size is greater than the buffer")
    })?;
    let mut files = Vec::with_capacity(file_reference_count);
    for reference in references.as_chunks::<8>().0 {
        let file = NtfsFile::from_reference(u64::from_le_bytes(*reference));
        if file.mft_entry == 0 {
            continue;
        }
        files.push(file)
    }
    Ok(files)
}

/// Parses `count` directory strings: each one is a 16-bit number of characters, the
/// characters, and a NUL.
fn extract_directory_strings(
    directory_strings: &[u8],
    count: usize,
) -> ForensicResult<Vec<String>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if directory_strings.len() < 2 {
        return Err(ForensicError::bad_format_str(
            "Invalid buffer size for directory strings",
        ));
    }
    // Every string takes at least 4 bytes, which bounds the allocation for a bogus count.
    let mut list = Vec::with_capacity(count.min(directory_strings.len() / 4));
    let mut pos = 0;
    for _ in 0..count {
        let characters = u16_at_pos(directory_strings, pos) as usize;
        let size = 4 + characters * 2;
        if pos + size > directory_strings.len() {
            return Err(ForensicError::bad_format_str(
                "The Directory String size is greater than the buffer size",
            ));
        }
        let text = utf16_at_offset(directory_strings, pos + 2, characters * 2)?;
        pos += size;
        list.push(text);
    }
    Ok(list)
}
