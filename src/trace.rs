use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{array_at, u32_at_pos, PrefetchFileInformation, Trace};

/// Size of a trace chain entry in format versions 17, 23 and 26.
const TRACE_ENTRY_SIZE_V17: usize = 12;
/// Size of a trace chain entry in format versions 30 and 31.
const TRACE_ENTRY_SIZE_V30: usize = 8;

fn trace_array<'a>(
    file_buffer: &'a [u8],
    info: &PrefetchFileInformation,
    entry_size: usize,
) -> ForensicResult<&'a [u8]> {
    array_at(
        file_buffer,
        info.trace_chain_offset as usize,
        info.trace_chain_count as usize,
        entry_size,
        "trace chain array",
    )
}

/// The `size` entries of the trace chain array starting at entry `index`.
fn trace_entries<'a>(
    trace_array: &'a [u8],
    entry_size: usize,
    index: usize,
    size: usize,
) -> ForensicResult<&'a [u8]> {
    index
        .checked_mul(entry_size)
        .ok_or_else(|| {
            ForensicError::bad_format_str(
                "The trace array position is greater than the file buffer length",
            )
        })
        .and_then(|offset| array_at(trace_array, offset, size, entry_size, "trace chain"))
}

fn trace_v17(entry: &[u8]) -> Trace {
    Trace {
        flags: entry[8].into(),
        block_offset: u32_at_pos(entry, 4),
        used_bitfield: entry[10],
        prefetched_bitfield: entry[11],
    }
}

fn trace_v30(entry: &[u8]) -> Trace {
    Trace {
        flags: entry[4].into(),
        block_offset: u32_at_pos(entry, 0),
        used_bitfield: entry[6],
        prefetched_bitfield: entry[7],
    }
}

pub fn traces_for_dependency_v17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    index: usize,
    size: usize,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_array(file_buffer, info, TRACE_ENTRY_SIZE_V17)?;
    let entries = trace_entries(trace_array, TRACE_ENTRY_SIZE_V17, index, size)?;
    Ok(entries
        .chunks_exact(TRACE_ENTRY_SIZE_V17)
        .map(trace_v17)
        .collect())
}

pub fn process_trace_chain_v17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_array(file_buffer, info, TRACE_ENTRY_SIZE_V17)?;
    Ok(trace_array
        .chunks_exact(TRACE_ENTRY_SIZE_V17)
        .map(trace_v17)
        .collect())
}

pub fn process_trace_chain_v30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_array(file_buffer, info, TRACE_ENTRY_SIZE_V30)?;
    Ok(trace_array
        .chunks_exact(TRACE_ENTRY_SIZE_V30)
        .map(trace_v30)
        .collect())
}

pub fn traces_for_dependency_v30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    index: usize,
    size: usize,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_array(file_buffer, info, TRACE_ENTRY_SIZE_V30)?;
    let entries = trace_entries(trace_array, TRACE_ENTRY_SIZE_V30, index, size)?;
    Ok(entries
        .chunks_exact(TRACE_ENTRY_SIZE_V30)
        .map(trace_v30)
        .collect())
}
