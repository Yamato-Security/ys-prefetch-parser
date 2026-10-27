use forensic_rs::err::{ForensicError, ForensicResult};
use std::{cell::RefCell, cmp::Ordering, rc::Rc};

/// Decompresses LZ77+Huffman data ([MS-XCA] 2.1) into `out_buf`, producing at most
/// `output_size` bytes.
///
/// Inspired by https://raw.githubusercontent.com/Velocidex/go-prefetch/master/lzxpress.go
pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>, output_size: usize) -> ForensicResult<()> {
    let mut in_index = 0;
    let mut out_index = 0;
    if output_size == 0 {
        return Ok(());
    }
    loop {
        let chunk_size = (output_size - out_index).min(65536);
        let (new_in_index, new_out_index) = decompress_chunk(
            in_index,
            in_buf,
            out_index,
            out_buf,
            chunk_size,
            output_size,
        )?;
        if new_in_index <= in_index && new_out_index <= out_index {
            return Err(ForensicError::bad_format_str(
                "decompress_expres_huff(): No progress when decompressing a chunk",
            ));
        }
        (in_index, out_index) = (new_in_index, new_out_index);
        if in_index >= in_buf.len() || out_index >= output_size {
            break;
        }
    }
    if output_size < out_buf.len() {
        out_buf.resize(output_size, 0);
    }
    Ok(())
}

fn decompress_chunk(
    in_index: usize,
    in_buf: &[u8],
    out_index: usize,
    out_buf: &mut Vec<u8>,
    chunk_size: usize,
    output_size: usize,
) -> ForensicResult<(usize, usize)> {
    // The 256-byte table of code lengths is followed by at least 4 bytes of bit stream.
    if in_index + 256 + 4 > in_buf.len() {
        return Err(ForensicError::bad_format_str(
            "decompress_expres_huff(): Not enough compressed data for Huffman table",
        ));
    }
    let root = prefix_code_tree_rebuild(&in_buf[in_index..])?;
    let mut bstr = BitStream::new(in_buf, in_index + 256);
    let mut i = out_index;
    while i < out_index + chunk_size {
        let mut symbol = match prefix_code_tree_decode_symbol(&mut bstr, root.clone()) {
            Ok(v) => v,
            Err(e) => match e {
                ForensicError::NoMoreData => return Ok((bstr.index, i)),
                _ => return Err(e),
            },
        };
        if symbol < 256 {
            out_buf.push(symbol as u8);
            i += 1;
        } else {
            symbol -= 256;
            let mut length = symbol & 15;
            symbol >>= 4;

            let mut offset = 0;
            if symbol != 0 {
                offset = bstr.lookup(symbol) as i32;
            }
            offset |= 1 << symbol;
            offset = -offset;

            if length == 15 {
                if bstr.index >= bstr.source.len() {
                    return Ok((bstr.index, i));
                }
                length = (bstr.source[bstr.index] as u32) + 15;
                bstr.index += 1;
                if length == 270 {
                    if bstr.index + 2 > bstr.source.len() {
                        return Ok((bstr.index, i));
                    }
                    length = u16::from_le_bytes(
                        bstr.source[bstr.index..bstr.index + 2].try_into().unwrap(),
                    ) as u32;
                    bstr.index += 2;
                    if length == 0 {
                        if bstr.index + 4 > bstr.source.len() {
                            return Ok((bstr.index, i));
                        }
                        length = u32::from_le_bytes(
                            bstr.source[bstr.index..bstr.index + 4].try_into().unwrap(),
                        );
                        bstr.index += 4;
                    }
                    if length < 15 {
                        return Err(ForensicError::bad_format_str(
                            "decompress_expres_huff(): Invalid match length",
                        ));
                    }
                }
            }
            bstr.skip(symbol)?;

            // A match may run past the end of the chunk but never past the output.
            let mut length = (length as usize).saturating_add(3).min(output_size - i);
            loop {
                if (i as i32 + offset) < 0 {
                    return Err(ForensicError::bad_format_str("decompress_expres_huff(): Invalid offset position when decompressing a chunk"));
                }
                let position = (i as i32 + offset) as usize;
                out_buf.push(out_buf[position]);
                i += 1;
                length -= 1;
                if length == 0 {
                    break;
                }
            }
        }
    }
    Ok((bstr.index, i))
}

struct BitStream<'a> {
    pub source: &'a [u8],
    pub index: usize,
    pub mask: u32,
    pub bits: u32,
}
impl<'a> BitStream<'a> {
    pub fn new(source: &'a [u8], in_pos: usize) -> Self {
        let mask = ((u16::from_le_bytes(source[in_pos..in_pos + 2].try_into().unwrap_or_default())
            as u32)
            << 16)
            + (u16::from_le_bytes(
                source[in_pos + 2..in_pos + 4]
                    .try_into()
                    .unwrap_or_default(),
            ) as u32);
        Self {
            source,
            index: in_pos + 4,
            bits: 32,
            mask,
        }
    }

    pub fn lookup(&self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.mask >> (32 - n)
    }
    pub fn skip(&mut self, n: u32) -> ForensicResult<()> {
        self.mask <<= n;
        self.bits = self.bits.saturating_sub(n);
        if self.bits < 16 {
            if (self.index + 2) > self.source.len() {
                return Err(ForensicError::NoMoreData);
            }
            self.mask += (u16::from_le_bytes(
                self.source[self.index..self.index + 2]
                    .try_into()
                    .unwrap_or_default(),
            ) as u32)
                << (16 - self.bits);
            self.index += 2;
            self.bits += 16;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct PrefixCodeNode {
    pub id: u32,
    pub symbol: u32,
    pub leaf: bool,
    pub child: [Option<Rc<RefCell<PrefixCodeNode>>>; 2],
}

#[derive(Clone, Debug, Default)]
struct PrefixCodeSymbol {
    pub id: u32,
    pub symbol: u32,
    pub length: u32,
}

impl Ord for PrefixCodeSymbol {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.length, &self.symbol).cmp(&(other.length, &other.symbol))
    }
}

impl PartialOrd for PrefixCodeSymbol {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PrefixCodeSymbol {
    fn eq(&self, other: &Self) -> bool {
        (self.length, &self.symbol) == (other.length, &other.symbol)
    }
}

impl Eq for PrefixCodeSymbol {}

fn prefix_code_tree_add_leaf(
    tree_nodes: &[Rc<RefCell<PrefixCodeNode>>],
    leaf_index: usize,
    mask: u32,
    bits: u32,
) -> ForensicResult<u32> {
    let mut node = match tree_nodes.first() {
        Some(v) => v.clone(),
        None => {
            return Err(ForensicError::bad_format_str(
                "decompress_expres_huff(): Invalid PreficCode",
            ))
        }
    };
    // A table of code lengths that is not a valid prefix code can need more nodes than a
    // complete tree of 512 symbols has.
    let too_many_nodes =
        || ForensicError::bad_format_str("decompress_expres_huff(): Invalid Huffman table");
    let mut i = leaf_index + 1;
    let mut child_index;
    let mut bits = bits;
    while bits > 1 {
        bits -= 1;
        child_index = (mask >> bits) & 1;
        let mut nt = node.borrow_mut();
        if nt.child[child_index as usize].is_none() {
            let new_node = tree_nodes.get(i).ok_or_else(too_many_nodes)?;
            nt.child[child_index as usize] = Some(new_node.clone());
            new_node.borrow_mut().leaf = false;
            i += 1;
        }
        let new_node = nt.child[child_index as usize].as_ref().unwrap().clone();
        drop(nt);
        node = new_node;
    }
    let mut nt = node.borrow_mut();
    nt.child[(mask & 1) as usize] = Some(
        tree_nodes
            .get(leaf_index)
            .ok_or_else(too_many_nodes)?
            .clone(),
    );
    Ok(i as u32)
}

fn prefix_code_tree_rebuild(input: &[u8]) -> ForensicResult<Rc<RefCell<PrefixCodeNode>>> {
    let mut tree_nodes: Vec<Rc<RefCell<PrefixCodeNode>>> = (0..1024)
        .map(|_| Rc::new(RefCell::new(PrefixCodeNode::default())))
        .collect();
    let mut symbol_info: Vec<PrefixCodeSymbol> =
        (0..512).map(|_| PrefixCodeSymbol::default()).collect();
    for i in 0..256 {
        let mut value = input[i] as usize;

        symbol_info[2 * i].id = (2 * i) as u32;
        symbol_info[2 * i].symbol = (2 * i) as u32;
        symbol_info[2 * i].length = (value & 0xf) as u32;

        value >>= 4;
        symbol_info[(2 * i) + 1].id = ((2 * i) + 1) as u32;
        symbol_info[(2 * i) + 1].symbol = ((2 * i) + 1) as u32;
        symbol_info[(2 * i) + 1].length = (value & 0xf) as u32;
    }
    symbol_info.sort_by(|a, b| {
        if a.length < b.length {
            return Ordering::Less;
        }
        if a.length > b.length {
            return Ordering::Greater;
        }

        if a.symbol < b.symbol {
            return Ordering::Less;
        }
        if a.symbol > b.symbol {
            return Ordering::Greater;
        }
        Ordering::Equal
    });
    let mut i = 0;
    while i < 512 && symbol_info[i].length == 0 {
        i += 1
    }
    let mut mask = 0;
    let mut bits = 1;

    let mut j = 1;
    for symbol in symbol_info.iter().take(512).skip(i) {
        let mut tree_node_j = tree_nodes
            .get(j)
            .ok_or_else(|| {
                ForensicError::bad_format_str("decompress_expres_huff(): Invalid Huffman table")
            })?
            .borrow_mut();
        tree_node_j.id = j as u32;
        tree_node_j.symbol = symbol.symbol;
        tree_node_j.leaf = true;
        drop(tree_node_j);

        mask <<= symbol.length - bits;
        bits = symbol.length;
        j = prefix_code_tree_add_leaf(&tree_nodes, j, mask, bits)? as usize;
        mask += 1;
    }
    let root = tree_nodes.remove(0);
    Ok(root)
}

fn prefix_code_tree_decode_symbol(
    bstr: &mut BitStream,
    root: Rc<RefCell<PrefixCodeNode>>,
) -> ForensicResult<u32> {
    let mut node = root;
    loop {
        let bit = bstr.lookup(1);
        bstr.skip(1)?;
        let nt = node.borrow();
        let new_node = match &nt.child[bit as usize] {
            Some(v) => v.clone(),
            None => {
                return Err(ForensicError::Other(format!(
                    "No child in decode symbol: {}",
                    bit
                )))
            }
        };
        drop(nt);
        node = new_node;
        if node.borrow().leaf {
            break;
        }
    }
    let nt = node.borrow();
    Ok(nt.symbol)
}

#[test]
fn basic_huffman_decoding() {
    let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
    let encoded: [u8; 276] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45,
        0x44, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf,
        0x8d, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut decoded_value = Vec::new();
    decompress(&encoded, &mut decoded_value, uncompressed.len()).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);

    // Truncated Huffman table must error instead of looping forever
    let mut truncated_value = Vec::new();
    assert!(decompress(&encoded[..200], &mut truncated_value, uncompressed.len()).is_err());
}

#[cfg(test)]
/// "abc" repeated 100 times.
const ABC_REPEATED: [u8; 263] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa8, 0xdc, 0x00, 0x00, 0xff, 0x26, 0x01,
];

#[test]
fn basic_huffman_decoding2() {
    let uncompressed = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let encoded = ABC_REPEATED;

    let mut decoded_value = Vec::new();
    decompress(&encoded, &mut decoded_value, uncompressed.len()).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn invalid_huffman_table_is_an_error() {
    // Every symbol has a 15-bit code: the lengths do not form a prefix code and need more
    // tree nodes than a complete code of 512 symbols.
    let mut encoded = vec![0xffu8; 256];
    encoded.extend_from_slice(&[0u8; 16]);
    let mut decoded_value = Vec::new();
    assert!(decompress(&encoded, &mut decoded_value, 1024).is_err());
}

#[test]
fn matches_stop_at_the_output_size() {
    // "abc" followed by one long match: only the first 12 bytes are wanted.
    let uncompressed = b"abcabcabcabc";
    let mut decoded_value = Vec::new();
    decompress(&ABC_REPEATED, &mut decoded_value, uncompressed.len()).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}
