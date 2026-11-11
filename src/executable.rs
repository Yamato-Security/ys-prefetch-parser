// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Resolve the executable among loaded paths using the SCCA path hash. A loaded module with
//! the same basename is not necessarily the process image (for example, x86 versus x64).
//!
//! XP and Vista+ hash algorithms are cross-checked against Eric Zimmerman's PrefetchHash
//! test vectors: https://github.com/EricZimmerman/Prefetch/blob/master/Prefetch/PrefetchHash.cs

use crate::common::PrefetchFile;

const NAME_LIMIT: usize = 29;
const MAX_CANDIDATES: usize = 64;
const MAX_PATH_UNITS: usize = 32_767;

/// An executable path with the basis for choosing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutablePath<'a> {
    /// A loaded path, or the header's executable name when no single path can be selected.
    pub path: &'a str,
    /// The path reproduces the prefetch header hash. This is path attribution, not proof
    /// of the program's purpose or integrity. Hosting processes can hash command-line data.
    pub hash_validated: bool,
    /// More than one distinct matching loaded path exists and the hash did not resolve it.
    pub ambiguous: bool,
}

// .NET/Windows invariant uppercase does not expand one character into several (such as ß).
fn upper(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut u = c.to_uppercase();
            let first = u.next().unwrap_or(c);
            if u.next().is_none() { first } else { c }
        })
        .collect()
}

pub(crate) fn resolve(pf: &PrefetchFile) -> ExecutablePath<'_> {
    let fallback = |ambiguous| ExecutablePath {
        path: &pf.name,
        hash_validated: false,
        ambiguous,
    };
    if pf.name.is_empty() {
        return fallback(false);
    }
    let name = upper(&pf.name);
    let truncated = pf.name.encode_utf16().count() >= NAME_LIMIT;
    let mut paths: Vec<&str> = Vec::new();
    for metric in &pf.metrics {
        let base = metric
            .file
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&metric.file);
        let base = upper(base);
        if base != name && !(truncated && base.starts_with(&name)) {
            continue;
        }
        if paths.iter().any(|p| p.eq_ignore_ascii_case(&metric.file)) {
            continue;
        }
        if paths.len() == MAX_CANDIDATES {
            return fallback(true);
        }
        paths.push(&metric.file);
    }
    let mut matched = paths
        .iter()
        .copied()
        .filter(|p| matches_hash(p, pf.version, pf.hash));
    if let Some(path) = matched.next() {
        return if matched.next().is_none() {
            ExecutablePath {
                path,
                hash_validated: true,
                ambiguous: false,
            }
        } else {
            fallback(true)
        };
    }
    if paths.len() == 1 {
        ExecutablePath {
            path: paths[0],
            hash_validated: false,
            ambiguous: false,
        }
    } else {
        fallback(paths.len() > 1)
    }
}

fn raw_hash(s: &str, seed: u32) -> u32 {
    s.encode_utf16()
        .flat_map(u16::to_le_bytes)
        .fold(seed, |hash, b| {
            hash.wrapping_mul(37).wrapping_add(u32::from(b))
        })
}

fn finish(mut raw: u32, version: u32) -> u32 {
    if version == 17 {
        raw = raw.wrapping_mul(314_159_269);
        if raw > 0x8000_0000 {
            raw = raw.wrapping_neg();
        }
        raw % 1_000_000_007
    } else {
        raw
    }
}

fn matches_hash(path: &str, version: u32, expected: u32) -> bool {
    if !matches!(version, 17 | 23 | 26 | 30 | 31)
        || path.encode_utf16().take(MAX_PATH_UNITS + 1).count() > MAX_PATH_UNITS
    {
        return false;
    }
    let path = upper(path);
    let seed = if version == 17 { 0 } else { 314_159 };
    if finish(raw_hash(&path, seed), version) == expected {
        return true;
    }
    if !path.starts_with(r"\VOLUME{") {
        return false;
    }
    let Some(end) = path.find('}') else {
        return false;
    };
    let suffix = &path[end + 1..];
    if !suffix.starts_with('\\') {
        return false;
    }
    // h(prefix || suffix) = h(prefix) * 37^len(suffix) + h_0(suffix), modulo 2^32.
    // Hash the long suffix once rather than re-reading it for every device number.
    let factor = 37u32.wrapping_pow((suffix.encode_utf16().count() * 2) as u32);
    let tail = raw_hash(suffix, 0);
    (1..=255).any(|n| {
        let prefix = format!(r"\DEVICE\HARDDISKVOLUME{n}");
        let hash = raw_hash(&prefix, seed)
            .wrapping_mul(factor)
            .wrapping_add(tail);
        finish(hash, version) == expected
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Metric;

    fn pf(version: u32, hash: u32, name: &str, paths: &[&str]) -> PrefetchFile {
        PrefetchFile {
            version,
            hash,
            name: name.into(),
            metrics: paths
                .iter()
                .map(|p| Metric {
                    file: (*p).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn independently_published_hash_vectors() {
        assert!(matches_hash(
            r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE",
            17,
            0x087b_4001
        ));
        assert!(matches_hash(
            r"\device\harddiskvolume1\windows\system32\cmd.exe",
            17,
            0x087b_4001
        ));
        for version in [23, 26, 30, 31] {
            assert!(matches_hash(
                r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE",
                version,
                0x4a81_b364
            ));
            assert!(matches_hash(
                r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE",
                version,
                0x8930_5d47
            ));
        }
    }

    #[test]
    fn hash_selects_later_image_instead_of_first_same_named_module() {
        let right = r"\VOLUME{11111111-1111-1111-1111-111111111111}\WINDOWS\SYSTEM32\CMD.EXE";
        let pf = pf(
            30,
            0x4a81_b364,
            "CMD.EXE",
            &[
                r"\VOLUME{11111111-1111-1111-1111-111111111111}\TOOLS\CMD.EXE",
                right,
            ],
        );
        assert_eq!(pf.executable_path(), right);
        assert!(pf.executable_path_info().hash_validated);
        assert!(!pf.executable_path_info().ambiguous);
    }

    #[test]
    fn ambiguous_names_without_a_matching_hash_remain_unresolved() {
        let pf = pf(
            30,
            0,
            "CMD.EXE",
            &[r"\VOLUME{1}\A\CMD.EXE", r"\VOLUME{1}\B\CMD.EXE"],
        );
        assert_eq!(pf.executable_path(), "CMD.EXE");
        assert!(pf.executable_path_info().ambiguous);
        assert!(!pf.executable_path_info().hash_validated);
    }

    #[test]
    fn unique_unvalidated_hosting_path_and_case_duplicates_are_retained() {
        let path = r"\VOLUME{1}\WINDOWS\SYSTEM32\DLLHOST.EXE";
        let other_case = path.to_lowercase();
        let pf = pf(30, 1, "DLLHOST.EXE", &[path, &other_case]);
        assert_eq!(pf.executable_path(), path);
        assert!(!pf.executable_path_info().hash_validated);
        assert!(!pf.executable_path_info().ambiguous);
    }

    #[test]
    fn unreasonable_candidate_counts_do_not_create_a_large_hash_search() {
        let names: Vec<_> = (0..100)
            .map(|n| format!(r"\VOLUME{{1}}\{n}\CMD.EXE"))
            .collect();
        let paths: Vec<_> = names.iter().map(String::as_str).collect();
        let pf = pf(30, 0, "CMD.EXE", &paths);
        assert_eq!(pf.executable_path(), "CMD.EXE");
        assert!(pf.executable_path_info().ambiguous);
        assert!(!matches_hash(&"x".repeat(100_000), 30, 0));
    }

    #[test]
    fn the_hash_does_not_choose_between_indistinguishable_volume_guids() {
        let pf = pf(
            30,
            0x4a81_b364,
            "CMD.EXE",
            &[
                r"\VOLUME{11111111-1111-1111-1111-111111111111}\WINDOWS\SYSTEM32\CMD.EXE",
                r"\VOLUME{22222222-2222-2222-2222-222222222222}\WINDOWS\SYSTEM32\CMD.EXE",
            ],
        );
        assert_eq!(pf.executable_path(), "CMD.EXE");
        assert!(pf.executable_path_info().ambiguous);
        assert!(!pf.executable_path_info().hash_validated);
    }

    #[test]
    fn unknown_versions_and_malformed_volume_names_are_not_hash_validated() {
        assert!(!matches_hash(
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE",
            0,
            0x4a81_b364
        ));
        assert!(!matches_hash(r"\VOLUME{missing", 30, 0x4a81_b364));
        assert!(!matches_hash(r"\VOLUME{1}noslash", 30, 0x4a81_b364));
    }
}
