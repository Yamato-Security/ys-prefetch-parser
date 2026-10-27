use forensic_rs::{err::ForensicResult, notifications::NotificationType};

use crate::{
    common::{
        array_at, bytes_at, u32_at_pos, u64_at_pos, utf16_at_offset, Metric, NtfsFile,
        PrefetchFileInformation, Trace,
    },
    trace::{traces_for_dependency_v17, traces_for_dependency_v30},
};

/// Size of a file metrics entry in format version 17.
const METRIC_ENTRY_SIZE_V17: usize = 20;
/// Size of a file metrics entry in format versions 23 and later.
const METRIC_ENTRY_SIZE_V23: usize = 32;

type TraceReader = fn(&[u8], &PrefetchFileInformation, usize, usize) -> ForensicResult<Vec<Trace>>;

/// Parses the file metrics array. Version 17 entries have no "blocks to prefetch" field, so
/// their number of trace chain entries is used instead.
fn metrics_array(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    entry_size: usize,
    traces: TraceReader,
) -> ForensicResult<Vec<Metric>> {
    let strings_array = bytes_at(
        file_buffer,
        info.filename_string_offset as usize,
        info.filename_string_size as usize,
        "filename string block",
    )?;
    let metric_array = array_at(
        file_buffer,
        info.metrics_offsets as usize,
        info.metrics_count as usize,
        entry_size,
        "file metrics array",
    )?;
    let mut metrics = Vec::with_capacity(info.metrics_count as usize);
    for entry in metric_array.chunks_exact(entry_size) {
        let trace_index = u32_at_pos(entry, 0) as usize;
        let trace_size = u32_at_pos(entry, 4);
        let (blocks_to_prefetch, fields, file_reference) = if entry_size == METRIC_ENTRY_SIZE_V17 {
            (trace_size, 8, None)
        } else {
            let reference = u64_at_pos(entry, 24);
            let file_reference = (reference != 0).then(|| NtfsFile::from_reference(reference));
            (u32_at_pos(entry, 8), 12, file_reference)
        };
        let filename_offset = u32_at_pos(entry, fields) as usize;
        let filename_length = u32_at_pos(entry, fields + 4) as usize;
        let flags = u32_at_pos(entry, fields + 8);
        let file = utf16_at_offset(
            strings_array,
            filename_offset,
            filename_length.saturating_mul(2),
        )?;
        let metric = Metric {
            file,
            flags: flags.into(),
            traces: traces(file_buffer, info, trace_index, trace_size as usize)?,
            blocks_to_prefetch,
            file_reference,
        };
        check_anomaly_in_metrics(&metric);
        metrics.push(metric);
    }
    Ok(metrics)
}

pub fn metrics_array_23(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array(
        file_buffer,
        info,
        METRIC_ENTRY_SIZE_V23,
        traces_for_dependency_v17,
    )
}

pub fn metrics_array_17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array(
        file_buffer,
        info,
        METRIC_ENTRY_SIZE_V17,
        traces_for_dependency_v17,
    )
}

pub fn metrics_array_26(
    buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array_23(buffer, info)
}

pub fn metrics_array_30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array(
        file_buffer,
        info,
        METRIC_ENTRY_SIZE_V23,
        traces_for_dependency_v30,
    )
}

fn check_anomaly_in_metrics(metric: &Metric) {
    if is_resource(&metric.file) {
        // ICON
        if metric.has_executable_block() {
            forensic_rs::notify_info!(
                NotificationType::SuspiciousArtifact,
                "The loaded file {} should not have executable blocks",
                metric.file
            );
        }
    }
}

fn is_resource(file: &str) -> bool {
    if file.ends_with(".NLS") || file.ends_with(".RES") {
        return true;
    }
    false
}
