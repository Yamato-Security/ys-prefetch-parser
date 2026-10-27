# Samples from artemis

These prefetch files are copied from the test data of
[artemis](https://github.com/puffycid/artemis) (`forensics/tests/test_data/windows/prefetch`,
commit 3f80fd4), Copyright (c) 2023 puffyCid, MIT License.

| File | Why it is here |
| --- | --- |
| `win7/VERCLSID.EXE-7C52E31C.pf`, `win7/MSCORSVW.EXE-57D17DAF.pf` | Format version 23 (Windows 7) |
| `win81/CL.EXE-08C6C593.pf` | Format version 26, 1,000,188 bytes: larger than the old 1,000,000-byte size limit |
| `win81/WWAHOST.EXE-B72D66AF.pf` | Non-ASCII characters in a loaded file name |
| `win81/SVCHOST.EXE-7AC6742A.pf` | Two volumes |
| `win10/_IU14D2N.TMP-136252D4.pf` | Format version 30 (Windows 10), artemis's own reference sample |
| `win10/AM_DELTA_PATCH_1.377.757.0.EX-0C03AAF4.pf` | Executable name truncated to 29 characters |
| `win11/SVCHOST.EXE-576FFE64.pf` | Format version 30 (Windows 11) with three volumes |
| `win11/7Z.EXE-886612C8.pf` | Format version 30 (Windows 11) |

`../corrupt/bad_compression.pf` and `../corrupt/malformed.pf` come from the same directory
(`bad data/`); libscca rejects both, as it does `../corrupt/SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf`.
