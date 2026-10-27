//! Compares the parser with libscca (libyal's prefetch library), the reference
//! implementation. `libscca_expected.json` was written with libscca-python 20260527 from
//! the samples in `artifacts/`.
use frnsc_prefetch::prelude::*;
use serde_json::Value;

fn expected() -> serde_json::Map<String, Value> {
    let text = include_str!("libscca_expected.json");
    match serde_json::from_str(text).unwrap() {
        Value::Object(map) => map,
        _ => panic!("libscca_expected.json is not an object"),
    }
}

#[test]
fn every_sample_matches_libscca() {
    let expected = expected();
    assert_eq!(expected.len(), 16);
    for (path, want) in expected {
        let data = std::fs::read(&path).unwrap();
        let pf = read_prefetch_bytes(&path, &data).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            pf.version,
            want["version"].as_u64().unwrap() as u32,
            "{path}"
        );
        assert_eq!(pf.name, want["name"].as_str().unwrap(), "{path}");
        assert_eq!(pf.hash, want["hash"].as_u64().unwrap() as u32, "{path}");
        assert_eq!(
            pf.run_count,
            want["run_count"].as_u64().unwrap() as u32,
            "{path}"
        );
        let times: Vec<u64> = pf.last_run_times.iter().map(|t| t.filetime()).collect();
        let want_times: Vec<u64> = want["last_run_times"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_u64().unwrap())
            .collect();
        assert_eq!(times, want_times, "{path}");

        let volumes = want["volumes"].as_array().unwrap();
        assert_eq!(pf.volume.len(), volumes.len(), "{path}");
        for (got, want) in pf.volume.iter().zip(volumes) {
            assert_eq!(
                got.device_path,
                want["device_path"].as_str().unwrap(),
                "{path}"
            );
            assert_eq!(
                got.serial_number,
                want["serial_number"].as_u64().unwrap() as u32,
                "{path}"
            );
            assert_eq!(
                got.creation_time,
                want["creation_time"].as_u64().unwrap(),
                "{path}"
            );
        }

        let files: Vec<&str> = pf.metrics.iter().map(|m| m.file.as_str()).collect();
        let want_files: Vec<&str> = want["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        assert_eq!(files, want_files, "{path}");

        let references: Vec<Option<(u64, u16)>> = pf
            .metrics
            .iter()
            .map(|m| {
                m.file_reference
                    .as_ref()
                    .map(|r| (r.mft_entry, r.seq_number))
            })
            .collect();
        let want_references: Vec<Option<(u64, u16)>> = want["file_references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                r.as_array()
                    .map(|r| (r[0].as_u64().unwrap(), r[1].as_u64().unwrap() as u16))
            })
            .collect();
        assert_eq!(references, want_references, "{path}");
    }
}

#[test]
fn files_libscca_rejects_are_errors() {
    for entry in std::fs::read_dir("artifacts/corrupt").unwrap() {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(read_prefetch_bytes(name, &data).is_err(), "{name}");
    }
}

#[test]
fn the_file_name_matches_the_executable_name_and_hash() {
    for path in expected().keys() {
        let data = std::fs::read(path).unwrap();
        let pf = read_prefetch_bytes(path, &data).unwrap();
        let stem = path
            .rsplit('/')
            .next()
            .unwrap()
            .strip_suffix(".pf")
            .unwrap();
        assert_eq!(stem, format!("{}-{:08X}", pf.name, pf.hash), "{path}");
    }
}
