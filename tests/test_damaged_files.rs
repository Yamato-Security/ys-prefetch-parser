//! Damaged and crafted prefetch files must produce errors: no panics, and no allocation
//! larger than the size limit however large the counts and sizes in the file claim to be.
use frnsc_prefetch::decompress::{decompress, CompressionAlgorithm};
use frnsc_prefetch::prelude::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Records the largest allocation request.
struct Tracking;
static LARGEST: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static TRACKING: Tracking = Tracking;

const SIZE_LIMIT: usize = 64 * 1024 * 1024;

fn samples() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from("artifacts")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "pf")
                && path.metadata().unwrap().len() < 200_000
            {
                out.push((path.display().to_string(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// The uncompressed SCCA payload of a sample, so that damage reaches the structures rather
/// than only the compressed stream.
fn payload(data: &[u8]) -> Option<Vec<u8>> {
    if !data.starts_with(b"MAM") {
        return Some(data.to_vec());
    }
    let size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    decompress(
        &data[8..],
        &mut out,
        CompressionAlgorithm::CompressionFormatXpressHuff,
        size,
    )
    .ok()?;
    Some(out)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

static LOCATION: Mutex<String> = Mutex::new(String::new());

/// Parses damaged inputs and groups the panics by location.
#[derive(Default)]
struct Checker {
    panics: BTreeMap<String, usize>,
}

impl Checker {
    fn new() -> Self {
        std::panic::set_hook(Box::new(|info| {
            if let Some(l) = info.location() {
                *LOCATION.lock().unwrap() = format!("{}:{}", l.file(), l.line());
            }
        }));
        Self::default()
    }

    fn check(&mut self, data: &[u8]) {
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = read_prefetch_bytes("X.EXE-00000000.pf", data);
        }))
        .is_err()
        {
            *self
                .panics
                .entry(LOCATION.lock().unwrap().clone())
                .or_insert(0) += 1;
        }
    }

    fn assert_clean(self) {
        let _ = std::panic::take_hook();
        assert!(self.panics.is_empty(), "panics: {:?}", self.panics);
        assert!(LARGEST.load(Ordering::Relaxed) <= SIZE_LIMIT);
    }
}

#[test]
fn random_damage_does_not_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut checker = Checker::new();
    for (_, data) in samples() {
        for original in [Some(data.clone()), payload(&data)].into_iter().flatten() {
            for i in 0..150 {
                let mut d = original.clone();
                for _ in 0..1 + rng.next() % 8 {
                    let pos = rng.next() as usize % d.len();
                    d[pos] = match i % 3 {
                        0 => rng.next() as u8,
                        1 => 0xFF,
                        _ => 0x00,
                    };
                }
                if i % 7 == 0 {
                    d.truncate(rng.next() as usize % d.len());
                }
                checker.check(&d);
            }
        }
    }
    checker.assert_clean();
}

#[test]
fn every_header_byte_at_its_extremes_does_not_panic() {
    // The header and the file information hold every offset, count and size.
    let mut checker = Checker::new();
    for (_, data) in samples() {
        let Some(original) = payload(&data) else {
            continue;
        };
        for pos in 0..original.len().min(308) {
            for value in [0x00, 0xFF, 0x7F, 0x80] {
                let mut d = original.clone();
                d[pos] = value;
                checker.check(&d);
            }
        }
    }
    checker.assert_clean();
}

#[test]
fn huge_sizes_and_counts_are_errors() {
    // A compressed header announcing 4 GiB of data.
    let mut mam = b"MAM\x04\xff\xff\xff\xff".to_vec();
    mam.extend_from_slice(&[0u8; 300]);
    assert!(read_prefetch_bytes("X.EXE-00000000.pf", &mam).is_err());

    // A version 30 payload whose every count and size is 0xFFFFFFFF.
    let mut scca = vec![0u8; 400];
    scca[0..4].copy_from_slice(&30u32.to_le_bytes());
    scca[4..8].copy_from_slice(b"SCCA");
    for field in (84 + 4..84 + 36).step_by(4) {
        scca[field..field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    assert!(read_prefetch_bytes("X.EXE-00000000.pf", &scca).is_err());
    assert!(LARGEST.load(Ordering::Relaxed) <= SIZE_LIMIT);
}
