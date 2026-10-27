# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - 2026-10-27 (ys-prefetch-parser)

First version of Yamato Security's fork, based on upstream `main` 5413f19 (0.13.4).

### Added
- `read_prefetch_bytes(name, &[u8])` parses a compressed or uncompressed file held in memory.
- `PrefetchFile::hash` (the prefetch hash) and `PrefetchFile::file_size` (the size in the header).
- `Metric::file_reference`: the NTFS file reference of each loaded file (version 23 and later).
- `NtfsFile::from_reference` splits a 64-bit file reference.

### Changed
- `decompress::decompress` and the decompressors take the output size instead of reading the
  capacity of the output vector.
- Files and decompressed data up to 64 MiB are read (was 1,000,000 bytes).
- The crate is not published (`publish = false`); MSRV 1.88.

### Fixed
- Strings were read by transmuting `&[u8]` to `&[u16]` (unaligned, and twice the length).
- Damaged files panicked on out-of-range offsets and counts, and counts read from the file were
  passed to `Vec::with_capacity` (process abort); a trace chain count was reserved per metric.
- A valid Windows 8.1 file of 1,000,188 bytes was rejected as abnormally large.
- The MAM header's decompressed size (up to 4 GiB) was reserved before decompressing.
- Xpress Huffman: unbounded match lengths, the 32-bit match length form, Huffman tables needing
  more than 1024 tree nodes, and a missing bit stream header.
- LZ77 (`COMPRESSION_FORMAT_XPRESS`) data went to the Huffman decoder and LZNT1 data to the LZ77
  decoder; LZNT1 is now reported as unsupported, and the LZ77 decoder no longer panics.
- The hash in the file name was parsed as decimal (a mismatch notification for every file) and
  the name was split at the first dash.
- A volume whose last directory string ends at the end of the volume block was rejected.
- The metrics anomaly check printed to stdout.
- `PrefetchFile::executable_path` matched any path ending in the executable name and never
  resolved names truncated to 29 characters.

### Tests
- All samples are compared with libscca; randomly damaged files and every header byte at its
  extremes must not panic or allocate more than the size limit.
- Samples from the artemis test data (Windows 7, 8.1, 10 and 11).


## [0.13.3] - 18/02/2025 

### Added

- Support for Prefetch version 31

## [0.13.2] - 21/10/2024 

### Fixed

- Correctly parse the MFT entry number

## [0.13.1] - 23/09/2024 

### Fixed

- Suporrt rust version 1.81

## [0.13.0] - 23/09/2024 

### Added

- Sync version of ForensicRS version 0.13