use std::{borrow::Cow, path::PathBuf};

use forensic_rs::{
    activity::{ForensicActivity, ProgramExecution, SessionId},
    data::ForensicData,
    dictionary::*,
    err::{ForensicError, ForensicResult},
    field::{Field, Text},
    traits::forensic::{IntoActivity, IntoTimeline, TimeContext, TimelineData},
    utils::time::Filetime,
};

/// By default blocks will be loaded into executable memory sections
pub const FLAG_PROGRAM_BLOCK_EXECUTABLE: u32 = 0x0200;

/// By default blocks will be loaded as resources, not executable
pub const FLAG_PROGRAM_BLOCK_RESOURCE: u32 = 0x0002;

/// By default blocks should not be prefetched, should be pulled from disk.
pub const FLAG_PROGRAM_BLOCK_DONT_PREFETCH: u32 = 0x0001;

/// The block is loaded into a executable memory section
pub const FLAG_BLOCK_EXECUTABLE: u8 = 0x02;

/// The block is loaded as resouce
pub const FLAG_BLOCK_RESOURCE: u8 = 0x04;
/// The block is forced to be prefetched
pub const FLAG_BLOCK_FORCE_PREFETCH: u8 = 0x08;
/// The block will not be prefetched, should be pulled from disk.
pub const FLAG_BLOCK_DONT_PREFETCH: u8 = 0x01;

/// The header has room for 30 UTF-16 characters including the terminating NUL.
const MAX_EXECUTABLE_NAME_CHARACTERS: usize = 29;

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

#[derive(Debug, Clone, Default)]
pub struct PrefetchFile {
    /// Prefetch file version
    pub version: u32,
    /// Executable name
    pub name: String,
    /// Prefetch hash of the executable's path (the hexadecimal part of the file name)
    pub hash: u32,
    /// Size of the uncompressed prefetch data, as recorded in its header
    pub file_size: u32,
    /// List of DLLs/EXEs loaded by the executable
    pub metrics: Vec<Metric>,
    /// Last execution times (max 8)
    pub last_run_times: Vec<Filetime>,
    /// Number of times executed
    pub run_count: u32,
    /// Information about the disks and other volumes
    pub volume: Vec<VolumeInformation>,
}
#[derive(Clone, Debug, Default)]
pub struct PrefetchFileInformation {
    pub metrics_offsets: u32,
    pub metrics_count: u32,
    pub trace_chain_offset: u32,
    pub trace_chain_count: u32,
    pub filename_string_offset: u32,
    pub filename_string_size: u32,
    pub volume_information_offset: u32,
    pub volume_count: u32,
    pub volume_information_size: u32,
    pub last_run_times: Vec<Filetime>,
    pub run_count: u32,
}

/// Files loaded by the executable
#[derive(Debug, Clone, Default)]
pub struct Metric {
    /// Full path to the dependency. Ex: File=\VOLUME{01d962d37536cd21-a2691d2c}\WINDOWS\SYSTEM32\NTDLL.DLL
    pub file: String,
    /// Default flags for loading blocks: executable, resource or non-prefetchable.
    pub flags: PrefetchFlag,
    /// Number of blocks to be prefetched
    pub blocks_to_prefetch: u32,
    /// Traces for this dependency
    pub traces: Vec<Trace>,
    /// NTFS file reference of the dependency (format version 23 and later; `None` when the
    /// entry holds no reference)
    pub file_reference: Option<NtfsFile>,
}
#[derive(Debug, Clone, Default)]
pub struct Trace {
    /// Flags for loading blocks: executable, resource, non-prefetchable or force prefetch.
    pub flags: BlockFlags,
    /// Memory block offset
    pub block_offset: u32,
    /// Stores whether the block was used in each of the last eight runs (1 bit each)
    pub used_bitfield: u8,
    /// Stores whether the block was prefetched in each of the last eight runs (1 bit each)
    pub prefetched_bitfield: u8,
}
#[derive(Clone, Default)]
pub struct PrefetchFlag(u32);

impl PrefetchFlag {
    pub fn is_executable(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_EXECUTABLE > 0
    }
    pub fn is_resource(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_RESOURCE > 0
    }
    pub fn is_not_prefetched(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_DONT_PREFETCH > 0
    }
}
impl From<u32> for PrefetchFlag {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl core::fmt::Debug for PrefetchFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for PrefetchFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}
#[derive(Clone, Default)]
pub struct BlockFlags(u8);

impl BlockFlags {
    pub fn is_executable(&self) -> bool {
        self.0 & FLAG_BLOCK_EXECUTABLE > 0
    }
    pub fn is_resource(&self) -> bool {
        self.0 & FLAG_BLOCK_RESOURCE > 0
    }
    pub fn is_not_prefetched(&self) -> bool {
        self.0 & FLAG_BLOCK_DONT_PREFETCH > 0
    }
    pub fn is_force_prefetch(&self) -> bool {
        self.0 & FLAG_BLOCK_FORCE_PREFETCH > 0
    }
}

impl core::fmt::Debug for BlockFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_force_prefetch() {
            f.write_str("F")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

impl From<u8> for BlockFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for BlockFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_force_prefetch() {
            f.write_str("F")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VolumeInformation {
    pub device_path: String,
    pub file_references: Vec<NtfsFile>,
    pub directory_strings: Vec<String>,
    pub creation_time: u64,
    pub serial_number: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtfsFile {
    pub mft_entry: u64,
    pub seq_number: u16,
}

impl NtfsFile {
    /// Splits a 64-bit NTFS file reference into its 48-bit MFT entry and 16-bit sequence
    /// number.
    pub fn from_reference(reference: u64) -> Self {
        Self {
            mft_entry: reference & 0xffffffffffff,
            seq_number: (reference >> 48) as u16,
        }
    }
}

/// Decodes the UTF-16LE string stored in the `size` bytes at `offset`, up to the first NUL.
pub fn utf16_at_offset(file_buffer: &[u8], offset: usize, size: usize) -> ForensicResult<String> {
    let txt = offset
        .checked_add(size)
        .and_then(|end_pos| file_buffer.get(offset..end_pos))
        .ok_or_else(|| {
            ForensicError::bad_format_str(
                "The utf16 string position is greater than the file buffer",
            )
        })?;
    Ok(utf16_until_nul(txt))
}

/// Decodes UTF-16LE bytes up to the first NUL (or the end of the bytes).
pub fn utf16_until_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&v| v != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Returns the `len` bytes at `offset`, or an error naming `what` when they are not all
/// inside `buffer`.
pub fn bytes_at<'a>(
    buffer: &'a [u8],
    offset: usize,
    len: usize,
    what: &str,
) -> ForensicResult<&'a [u8]> {
    offset
        .checked_add(len)
        .and_then(|end| buffer.get(offset..end))
        .ok_or_else(|| {
            ForensicError::bad_format_string(format!("The {what} is outside of the prefetch data"))
        })
}

/// Returns the `count` entries of `entry_size` bytes at `offset`, or an error naming `what`
/// when they are not all inside `buffer`.
pub fn array_at<'a>(
    buffer: &'a [u8],
    offset: usize,
    count: usize,
    entry_size: usize,
    what: &str,
) -> ForensicResult<&'a [u8]> {
    let len = count.checked_mul(entry_size).ok_or_else(|| {
        ForensicError::bad_format_string(format!("The {what} is outside of the prefetch data"))
    })?;
    bytes_at(buffer, offset, len, what)
}

fn array_at_pos<const N: usize>(buffer: &[u8], pos: usize) -> [u8; N] {
    pos.checked_add(N)
        .and_then(|end| buffer.get(pos..end))
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0; N])
}

/// Reads a little-endian `u16` at `pos`; 0 when the buffer is too short.
pub fn u16_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes(array_at_pos(buffer, pos))
}
/// Reads a little-endian `u32` at `pos`; 0 when the buffer is too short.
pub fn u32_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(array_at_pos(buffer, pos))
}
/// Reads a little-endian `u64` at `pos`; 0 when the buffer is too short.
pub fn u64_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(array_at_pos(buffer, pos))
}

impl Metric {
    pub fn has_executable_block(&self) -> bool {
        for trace in self.traces.iter() {
            if trace.flags.is_executable() {
                return true;
            }
        }
        false
    }
}

impl PrefetchFile {
    pub fn new() -> Self {
        PrefetchFile::default()
    }

    /// Path of the executable: the loaded file whose name is the executable name, or the
    /// executable name when no loaded file has it.
    ///
    /// Windows stores at most 29 characters of the executable name. A truncated name is
    /// resolved when exactly one loaded file name starts with it.
    pub fn executable_path(&self) -> &str {
        let name = self.name.as_str();
        if let Some(loaded) = self
            .metrics
            .iter()
            .find(|m| file_name(&m.file).eq_ignore_ascii_case(name))
        {
            return &loaded.file;
        }
        if name.encode_utf16().count() >= MAX_EXECUTABLE_NAME_CHARACTERS {
            let upper = name.to_uppercase();
            let mut candidates = self
                .metrics
                .iter()
                .filter(|m| file_name(&m.file).to_uppercase().starts_with(&upper));
            if let (Some(loaded), None) = (candidates.next(), candidates.next()) {
                return &loaded.file;
            }
        }
        name
    }
    /// Gets for which user was the program executed. Its not precise.
    pub fn user(&self) -> Option<&str> {
        for volume in &self.volume {
            for file in &volume.directory_strings {
                if !file.starts_with(r"\") {
                    continue;
                }
                let filename = &file[1..];
                let mut splited = filename.split(r"\");
                if splited.next().is_none() {
                    continue;
                };
                match splited.next() {
                    Some("USERS") => {}
                    _ => continue,
                };
                let user = match splited.next() {
                    Some(v) => v,
                    None => continue,
                };
                match splited.next() {
                    Some("APPDATA") => {}
                    _ => continue,
                };
                return Some(user);
            }
        }
        None
    }
}

pub struct PrefetchTimelineIterator<'a> {
    prefetch: &'a PrefetchFile,
    time_pos: usize,
}
impl<'a> Iterator for PrefetchTimelineIterator<'a> {
    type Item = TimelineData;
    fn next(&mut self) -> Option<Self::Item> {
        let actual_pos = self.time_pos;
        if actual_pos >= self.prefetch.last_run_times.len() {
            return None;
        }
        self.time_pos += 1;
        let mut data = ForensicData::default();
        data.add_field(
            FILE_ACCESSED,
            Field::Date(self.prefetch.last_run_times[actual_pos]),
        );
        data.add_field(FILE_PATH, Field::Path(PathBuf::from(&self.prefetch.name)));
        let dependencies: Vec<Text> = self
            .prefetch
            .metrics
            .iter()
            .map(|v| Cow::Owned(v.file.clone()))
            .collect();
        data.add_field(PE_IMPORTS, Field::Array(dependencies));
        data.add_field("prefetch.execution_times", self.prefetch.run_count.into());
        data.add_field("prefetch.version", self.prefetch.version.into());
        let mut volume_files = Vec::with_capacity(1024);
        for volumn in self.prefetch.volume.iter() {
            for files in volumn.directory_strings.iter() {
                volume_files.push(Cow::Owned(files.clone()))
            }
        }
        data.add_field("prefetch.volume_files", Field::Array(volume_files));
        Some(TimelineData {
            time: self.prefetch.last_run_times[actual_pos],
            data,
            time_context: TimeContext::Accessed,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.time_pos, Some(self.prefetch.last_run_times.len()))
    }
}

pub struct PrefetchActivityIterator<'a> {
    prefetch: &'a PrefetchFile,
    time_pos: usize,
}
impl<'a> Iterator for PrefetchActivityIterator<'a> {
    type Item = ForensicActivity;
    fn next(&mut self) -> Option<Self::Item> {
        let actual_pos = self.time_pos;
        if actual_pos >= self.prefetch.last_run_times.len() {
            return None;
        }
        self.time_pos += 1;
        Some(ForensicActivity {
            timestamp: self.prefetch.last_run_times[actual_pos],
            activity: ProgramExecution::new(self.prefetch.executable_path().to_string()).into(),
            user: self
                .prefetch
                .user()
                .map(|v| v.to_string())
                .unwrap_or_default(),
            session_id: SessionId::Unknown,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.time_pos, Some(self.prefetch.last_run_times.len()))
    }
}

impl<'a> IntoActivity<'a> for &'a PrefetchFile {
    fn activity(&'a self) -> Self::IntoIter {
        PrefetchActivityIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchActivityIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoActivity<'a> for PrefetchFile {
    fn activity(&'a self) -> Self::IntoIter {
        PrefetchActivityIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchActivityIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoTimeline<'a> for &'a PrefetchFile {
    fn timeline(&'a self) -> Self::IntoIter {
        PrefetchTimelineIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchTimelineIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoTimeline<'a> for PrefetchFile {
    fn timeline(&'a self) -> Self::IntoIter {
        PrefetchTimelineIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchTimelineIterator<'a>
    where
        Self: 'a;
}

#[cfg(test)]
mod tests {
    use super::{Metric, PrefetchFile};

    fn prefetch(name: &str, files: &[&str]) -> PrefetchFile {
        PrefetchFile {
            name: name.into(),
            metrics: files
                .iter()
                .map(|f| Metric {
                    file: f.to_string(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn executable_path_matches_the_whole_file_name() {
        let pf = prefetch(
            "CMD.EXE",
            &[
                r"\VOLUME{1}\TOOLS\NOTCMD.EXE",
                r"\VOLUME{1}\WINDOWS\SYSTEM32\CMD.EXE",
            ],
        );
        assert_eq!(pf.executable_path(), r"\VOLUME{1}\WINDOWS\SYSTEM32\CMD.EXE");
        assert_eq!(
            prefetch("CMD.EXE", &[r"\VOLUME{1}\X.DLL"]).executable_path(),
            "CMD.EXE"
        );
    }

    #[test]
    fn executable_path_resolves_unambiguous_truncated_names() {
        let name = "AM_DELTA_PATCH_1.377.757.0.EX";
        let path = r"\VOLUME{1}\INSTALL\AM_DELTA_PATCH_1.377.757.0.EXE";
        assert_eq!(
            prefetch(name, &[r"\VOLUME{1}\X.DLL", path]).executable_path(),
            path
        );
        let other = r"\VOLUME{1}\INSTALL\AM_DELTA_PATCH_1.377.757.0.EXE.MUI";
        assert_eq!(prefetch(name, &[path, other]).executable_path(), name);
    }
}
