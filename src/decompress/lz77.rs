use forensic_rs::err::{ForensicError, ForensicResult};

/// Decompresses plain LZ77 data ([MS-XCA] 2.4) into `out_buf`, producing at most
/// `output_size` bytes.
pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>, output_size: usize) -> ForensicResult<()> {
    let truncated = || ForensicError::bad_format_str("decompress_LZ77(): Truncated input");
    let byte_at = |pos: usize| in_buf.get(pos).copied().ok_or_else(truncated);
    let u16_at = |pos: usize| -> ForensicResult<u32> {
        Ok(u16::from_le_bytes([byte_at(pos)?, byte_at(pos + 1)?]) as u32)
    };
    let mut buffered_flags = 0;
    let mut buffered_flag_count = 0;
    let mut input_position = 0;
    let mut last_length_half_byte = 0;
    while out_buf.len() < output_size {
        if buffered_flag_count == 0 {
            if input_position + 4 > in_buf.len() {
                return Ok(());
            }
            buffered_flags = u32::from_le_bytes([
                in_buf[input_position],
                in_buf[input_position + 1],
                in_buf[input_position + 2],
                in_buf[input_position + 3],
            ]);
            input_position += 4;
            buffered_flag_count = 32;
        }
        buffered_flag_count -= 1;
        if (buffered_flags & (1 << buffered_flag_count)) == 0 {
            if input_position == in_buf.len() {
                return Ok(());
            }
            out_buf.push(in_buf[input_position]);
            input_position += 1;
        } else {
            if input_position == in_buf.len() {
                return Ok(());
            }
            let match_bytes = u16_at(input_position)?;
            input_position += 2;
            let mut match_length = match_bytes % 8;
            let match_offset = (match_bytes / 8) as usize + 1;
            if match_length == 7 {
                if last_length_half_byte == 0 {
                    match_length = (byte_at(input_position)? as u32) % 16;
                    last_length_half_byte = input_position;
                    input_position += 1;
                } else {
                    match_length = (in_buf[last_length_half_byte] as u32) / 16;
                    last_length_half_byte = 0;
                }
                if match_length == 15 {
                    match_length = byte_at(input_position)? as u32;
                    input_position += 1;
                    if match_length == 255 {
                        match_length = u16_at(input_position)?;
                        input_position += 2;
                        if match_length == 0 {
                            match_length =
                                u16_at(input_position)? | u16_at(input_position + 2)? << 16;
                            input_position += 4;
                        }
                        if match_length < 22 {
                            return Err(ForensicError::bad_format_str(
                                "decompress_LZ77(): Invalid match length, must be greater than 22",
                            ));
                        }
                        match_length -= 22;
                    }
                    match_length += 15;
                }
                match_length += 7;
            }
            let match_length = (match_length as usize)
                .saturating_add(3)
                .min(output_size - out_buf.len());
            if match_offset > out_buf.len() {
                return Err(ForensicError::bad_format_str(
                    "decompress_LZ77(): Invalid match offset",
                ));
            }
            for _ in 0..match_length {
                out_buf.push(out_buf[out_buf.len() - match_offset]);
            }
        }
    }
    Ok(())
}

#[test]
fn basic_lz77_decompression() {
    let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
    let encoded: [u8; 30] = [
        0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    ];

    let mut decoded_value = Vec::new();
    decompress(&encoded, &mut decoded_value, 1024).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn basic_lz77_decompression_2() {
    let uncompressed = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let encoded: [u8; 13] = [
        0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
    ];

    let mut decoded_value = Vec::new();
    decompress(&encoded, &mut decoded_value, 1024).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn damaged_lz77_input_is_an_error() {
    // A match before any output and a match length that runs past the input.
    let mut decoded_value = Vec::new();
    assert!(
        decompress(
            &[0x00, 0x00, 0x00, 0x80, 0x00, 0x00],
            &mut decoded_value,
            64
        )
        .is_err()
    );
    let mut decoded_value = Vec::new();
    assert!(
        decompress(
            &[0x00, 0x00, 0x00, 0x40, 0x61, 0x07, 0x00],
            &mut decoded_value,
            64
        )
        .is_err()
    );
}

#[test]
fn lz77_output_stops_at_the_output_size() {
    let encoded: [u8; 13] = [
        0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
    ];
    let mut decoded_value = Vec::new();
    decompress(&encoded, &mut decoded_value, 10).unwrap();
    assert_eq!(b"abcabcabca", &decoded_value[..]);
}
