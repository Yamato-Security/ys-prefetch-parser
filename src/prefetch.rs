use std::{io::Read, path::Path};

use forensic_rs::{
    artifact::WindowsArtifacts,
    err::{ForensicError, ForensicResult},
    notifications::NotificationType,
    notify_high, notify_low,
    traits::vfs::{VDirEntry, VirtualFile, VirtualFileSystem},
    utils::time::Filetime,
};

use crate::{
    common::{
        bytes_at, u32_at_pos, u64_at_pos, utf16_until_nul, PrefetchFile, PrefetchFileInformation,
    },
    decompress::{decompress, CompressionAlgorithm},
    metrics::*,
    volume::*,
};

/// Largest prefetch file, compressed or not, that is read. Real files are far smaller (the
/// largest seen is about 1 MB uncompressed, which the previous limit of 1,000,000 bytes
/// rejected); the limit only keeps other large files from being read into memory.
const PREFETCH_SIZE_LIMIT: u64 = 64 * 1024 * 1024;
/// Signature = MAM
const PREFETCH_COMPRESS_SIGNATURE: u32 = u32::from_le_bytes([b'M', b'A', b'M', b'\0']);
const PREFETC_COMPRESS_SIGNATURE_U8: &[u8] = b"MAM";

/// Reads all prefetch files on the folder C:\Windows\Prefetch.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
/// let _list = read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_form_fs(fs: &mut impl VirtualFileSystem) -> ForensicResult<Vec<PrefetchFile>> {
    forensic_rs::context::set_artifact(WindowsArtifacts::Prefetch);
    let prefetch_folder = Path::new(r"C:\Windows\Prefetch");
    let prefetch_files = match fs.read_dir(prefetch_folder) {
        Ok(v) => v,
        Err(e) => {
            notify_high!(NotificationType::AntiForensicsDetected, "No prefetch found");
            return Err(e);
        }
    };
    let mut prefetches = Vec::with_capacity(128);
    for file in prefetch_files {
        let file_name = match file {
            VDirEntry::File(v) => v,
            _ => continue,
        };
        if !file_name.ends_with(".pf") {
            continue;
        }
        let file = fs.open(prefetch_folder.join(&file_name).as_path())?;

        match read_prefetch_file(&file_name, file) {
            Ok(v) => {
                prefetches.push(v);
            }
            Err(e) => {
                forensic_rs::info!("Error procesing prefetch {}: {}", file_name, e);
            }
        };
    }
    Ok(prefetches)
}

/// Parses a sinle prefetch file. The file name is supplied as to check the prefetch hash and the name.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
/// let file = fs.open(std::path::Path::new("C:\\Windows\\Prefetch\\CMD.EXE-087B4001.pf")).unwrap();
/// let _list = read_prefetch_file("CMD.EXE-087B4001.pf", file).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_file(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    let mut buffer = [0u8; 64];
    file.read_exact(&mut buffer)?;
    if file_is_compressed(&buffer) {
        read_prefetch_file_compressed(artifact_name, file)
    } else {
        read_prefetch_file_no_compressed(artifact_name, file)
    }
}

fn file_is_compressed(buffer: &[u8]) -> bool {
    PREFETC_COMPRESS_SIGNATURE_U8 == &buffer[0..3]
}

/// Parsers a prefetch file that is compressed.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// use std::path::Path;
/// let mut fs = StdVirtualFS::new();
/// let file = fs.open(Path::new("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf")).unwrap();
/// read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    if file.metadata()?.size > PREFETCH_SIZE_LIMIT {
        notify_low!(
            NotificationType::AntiForensicsDetected,
            "File size is abnormally large"
        );
        return Err(ForensicError::bad_format_str(
            "File size is abnormally large",
        ));
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    process_compressed_data(artifact_name, &buffer)
}

/// Parses a prefetch file held in memory, compressed (Windows 8 and later) or not. The file
/// name (or a path ending in it) is used to check the executable name and the hash.
///
/// ```rust
/// use frnsc_prefetch::prelude::*;
/// let data = std::fs::read("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf").unwrap();
/// let prefetch = read_prefetch_bytes("RUST_OUT.EXE-5D2C8541.pf", &data).unwrap();
/// assert_eq!(prefetch.name, "RUST_OUT.EXE");
/// ```
pub fn read_prefetch_bytes(artifact_name: &str, data: &[u8]) -> ForensicResult<PrefetchFile> {
    if data.len() as u64 > PREFETCH_SIZE_LIMIT {
        notify_low!(
            NotificationType::AntiForensicsDetected,
            "Prefetch file {} size is abnormally large",
            artifact_name
        );
        return Err(ForensicError::bad_format_string(format!(
            "Prefetch file {} size is abnormally large",
            artifact_name
        )));
    }
    if data.starts_with(PREFETC_COMPRESS_SIGNATURE_U8) {
        process_compressed_data(artifact_name, data)
    } else {
        process_prefetch_data(artifact_name, data)
    }
}

fn process_compressed_data(artifact_name: &str, buffer: &[u8]) -> ForensicResult<PrefetchFile> {
    let header = bytes_at(buffer, 0, 8, "compressed prefetch header")?;
    let compressed = &buffer[8..];
    let signature = u32_at_pos(header, 0);
    let decompressed_size = u32_at_pos(header, 4);
    let compress_algorithm_value = (signature & 0x0F000000) >> 24;
    let crc_ck = (signature & 0xF0000000) >> 28;
    let magic = signature & 0x00FFFFFF;
    if magic != PREFETCH_COMPRESS_SIGNATURE {
        return Err(ForensicError::bad_format_string(format!(
            "Invalid prefetch signature: {}",
            magic
        )));
    }
    if crc_ck > 0 {
        if compressed.len() < 4 {
            return Err(ForensicError::bad_format_str(
                "The CRC of the prefetch is outside of the prefetch data",
            ));
        }
        let file_crc = u32_at_pos(compressed, 0);
        let mut hash = crc32fast::Hasher::new();
        hash.update(header);
        hash.update(&[0, 0, 0, 0]);
        hash.update(&compressed[4..]);
        let crc32 = hash.finalize();
        if crc32 != file_crc {
            notify_low!(
                NotificationType::AntiForensicsDetected,
                "Invalid CRC for prefetch {:?}: expected={} obtained={}",
                artifact_name,
                file_crc,
                crc32
            );
            return Err(ForensicError::bad_format_str(
                "The CRC of the prefetch does not match",
            ));
        }
    }
    if compress_algorithm_value > 4 {
        return Err(ForensicError::bad_format_string(format!(
            "Unknown prefetch compression algorithm: {}",
            compress_algorithm_value
        )));
    }
    if u64::from(decompressed_size) > PREFETCH_SIZE_LIMIT {
        notify_low!(
            NotificationType::AntiForensicsDetected,
            "Prefetch file {} decompressed size is abnormally large",
            artifact_name
        );
        return Err(ForensicError::bad_format_str(
            "Decompressed size is abnormally large",
        ));
    }
    let compress_algorithm: CompressionAlgorithm = compress_algorithm_value.into();
    let mut decompressed = Vec::with_capacity(decompressed_size as usize);
    decompress(
        compressed,
        &mut decompressed,
        compress_algorithm,
        decompressed_size as usize,
    )?;
    process_prefetch_data(artifact_name, &decompressed)
}

/// Parsers a prefetch file that is not compressed.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// use std::path::Path;
/// let mut fs = StdVirtualFS::new();
/// let file = fs.open(Path::new("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf")).unwrap();
/// read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_no_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    if file.metadata()?.size > PREFETCH_SIZE_LIMIT {
        notify_low!(
            NotificationType::AntiForensicsDetected,
            "Prefetch file {} size is abnormally large",
            artifact_name
        );
        return Err(ForensicError::bad_format_string(format!(
            "Prefetch file {} size is abnormally large",
            artifact_name
        )));
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    process_prefetch_data(artifact_name, &buffer)
}

fn process_prefetch_data(artifact_name: &str, buffer: &[u8]) -> ForensicResult<PrefetchFile> {
    bytes_at(buffer, 0, HEADER_SIZE, "prefetch header")?;
    let version = u32_at_pos(buffer, 0);
    let signature = &buffer[4..8];
    if b"SCCA" != signature {
        return Err(ForensicError::bad_format_str("Invalid prefetch signature"));
    }
    //let file_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
    let executable_name = utf16_until_nul(&buffer[16..76]);
    let raw_hash = u32_at_pos(buffer, 76);
    check_prefetch_info_correct(artifact_name, &executable_name, raw_hash);

    let mut prefetch_content = PrefetchFile {
        name: executable_name,
        version,
        ..Default::default()
    };
    if version == 17 {
        let info = file_information_17(file_information(buffer, FILE_INFORMATION_SIZE_V17)?)?;
        prefetch_content.metrics = metrics_array_17(buffer, &info)?;
        prefetch_content.volume = volume_info_17(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 23 {
        let info = file_information_23(file_information(buffer, FILE_INFORMATION_SIZE_V23)?)?;
        prefetch_content.metrics = metrics_array_23(buffer, &info)?;
        prefetch_content.volume = volume_info_23(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 26 {
        let info = file_information_26(file_information(buffer, FILE_INFORMATION_SIZE_V26)?)?;
        prefetch_content.metrics = metrics_array_26(buffer, &info)?;
        prefetch_content.volume = volume_info_26(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 30 {
        let info = file_information_30(file_information(buffer, FILE_INFORMATION_SIZE_V30)?)?;
        prefetch_content.metrics = metrics_array_30(buffer, &info)?;
        prefetch_content.volume = volume_info_30(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 31 {
        let info = file_information_30(file_information(buffer, FILE_INFORMATION_SIZE_V30)?)?;
        prefetch_content.metrics = metrics_array_30(buffer, &info)?;
        prefetch_content.volume = volume_info_30(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else {
        notify_low!(
            NotificationType::Informational,
            "The prefetch version is unknown: {}",
            version
        );
        return Err(ForensicError::bad_format_string(format!(
            "The prefetch version is unknown: {}",
            version
        )));
    };
    Ok(prefetch_content)
}

/// Size of the file header; the file information follows it.
const HEADER_SIZE: usize = 84;
const FILE_INFORMATION_SIZE_V17: usize = 68;
const FILE_INFORMATION_SIZE_V23: usize = 156;
const FILE_INFORMATION_SIZE_V26: usize = 220;
/// Version 30 has a 220-byte variant (the metrics array at offset 304, like version 26) and
/// a 212-byte one (offset 296).
const FILE_INFORMATION_SIZE_V30: usize = 212;

fn file_information(buffer: &[u8], size: usize) -> ForensicResult<&[u8]> {
    bytes_at(buffer, HEADER_SIZE, size, "file information")
}

fn file_information_17(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times: vec![Filetime::new(u64_at_pos(buffer, 36))],
        run_count: u32_at_pos(buffer, 60),
    })
}

fn file_information_23(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times: vec![Filetime::new(u64_at_pos(buffer, 44))],
        run_count: u32_at_pos(buffer, 68),
    })
}

fn file_information_26(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 124),
    })
}

fn file_information_30v1(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 124),
    })
}

fn file_information_30v2(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 116),
    })
}

fn file_information_30(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    if metrics_offsets == 304 {
        return file_information_30v1(buffer);
    }
    file_information_30v2(buffer)
}

fn check_prefetch_info_correct(artifact_name: &str, executable_name: &str, hash: u32) {
    match extract_hash_ands_signature(artifact_name) {
        Ok((expected_name, expected_hash)) => {
            if !expected_name.eq_ignore_ascii_case(executable_name) {
                forensic_rs::info!("Invalid prefetch executable name expected={expected_name} found={executable_name}");
                forensic_rs::notify_info!(NotificationType::AntiForensicsDetected, "Invalid prefetch executable name expected={expected_name} found={executable_name}");
            }
            if hash != expected_hash {
                forensic_rs::info!(
                    "Invalid prefetch hash expected={expected_hash:08X} found={hash:08X}"
                );
                forensic_rs::notify_info!(
                    NotificationType::AntiForensicsDetected,
                    "Invalid prefetch hash expected={expected_hash:08X} found={hash:08X}"
                );
            }
        }
        Err(e) => {
            forensic_rs::info!("{}", e);
        }
    }
}

/// Splits a prefetch file name such as `CMD.EXE-087B4001.pf` (or a path ending in one) into
/// the executable name and the hexadecimal prefetch hash.
fn extract_hash_ands_signature(name: &str) -> ForensicResult<(&str, u32)> {
    let invalid = || ForensicError::bad_format_str("Invalid prefetch artifact name");
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = name
        .len()
        .checked_sub(3)
        .filter(|&end| {
            name.get(end..)
                .is_some_and(|ext| ext.eq_ignore_ascii_case(".pf"))
        })
        .map(|end| &name[..end])
        .ok_or_else(invalid)?;
    let (executable, hash) = stem.rsplit_once('-').ok_or_else(invalid)?;
    if hash.len() != 8 {
        return Err(invalid());
    }
    let hash = u32::from_str_radix(hash, 16).map_err(|_| invalid())?;
    Ok((executable, hash))
}

#[cfg(test)]
mod name_tests {
    use super::extract_hash_ands_signature;

    #[test]
    fn prefetch_file_names_are_split_at_the_last_dash() {
        assert_eq!(
            extract_hash_ands_signature("CMD.EXE-087B4001.pf").unwrap(),
            ("CMD.EXE", 0x087B4001)
        );
        assert_eq!(
            extract_hash_ands_signature(r"C:\Windows\Prefetch\MICROSOFT-EDGE.EXE-1C2D3E4F.PF")
                .unwrap(),
            ("MICROSOFT-EDGE.EXE", 0x1C2D3E4F)
        );
        assert!(extract_hash_ands_signature("CMD.EXE.pf").is_err());
        assert!(extract_hash_ands_signature("CMD.EXE-XYZ.pf").is_err());
        assert!(extract_hash_ands_signature("CMD.EXE-087B4001.txt").is_err());
    }
}
