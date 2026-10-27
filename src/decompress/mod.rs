use forensic_rs::prelude::ForensicResult;

pub mod lz77;
pub mod xpress_huff;

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    CompressionFormatNone = 0x0000,
    CompressionFormatDefault = 0x0001,
    CompressionFormatLznt1 = 0x0002,
    CompressionFormatXpress = 0x0003,
    CompressionFormatXpressHuff = 0x0004,
}

impl From<u32> for CompressionAlgorithm {
    fn from(value: u32) -> Self {
        match value {
            1 => CompressionAlgorithm::CompressionFormatDefault,
            2 => CompressionAlgorithm::CompressionFormatLznt1,
            3 => CompressionAlgorithm::CompressionFormatXpress,
            4 => CompressionAlgorithm::CompressionFormatXpressHuff,
            _ => CompressionAlgorithm::CompressionFormatNone,
        }
    }
}

/// Decompresses `in_buf` into `out_buf`, producing at most `output_size` bytes.
pub fn decompress(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    algorithm: CompressionAlgorithm,
    output_size: usize,
) -> ForensicResult<()> {
    match algorithm {
        CompressionAlgorithm::CompressionFormatNone => {
            out_buf.extend_from_slice(&in_buf[..in_buf.len().min(output_size)]);
        }
        // COMPRESSION_FORMAT_DEFAULT is LZNT1.
        CompressionAlgorithm::CompressionFormatDefault
        | CompressionAlgorithm::CompressionFormatLznt1 => {
            return Err(forensic_rs::err::ForensicError::Other(
                "LZNT1 compression is not supported".into(),
            ))
        }
        // COMPRESSION_FORMAT_XPRESS is plain LZ77.
        CompressionAlgorithm::CompressionFormatXpress => {
            lz77::decompress(in_buf, out_buf, output_size)?
        }
        CompressionAlgorithm::CompressionFormatXpressHuff => {
            xpress_huff::decompress(in_buf, out_buf, output_size)?
        }
    }
    Ok(())
}
