// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2024 Samuel Garcés Marín
//
// This file is changed from ForensicRS/frnsc-prefetch
// (https://github.com/ForensicRS/frnsc-prefetch), whose code is under the MIT License
// (LICENSE-MIT).
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

pub mod common;
pub mod decompress;
pub mod metrics;
pub mod prefetch;
pub mod trace;
pub mod volume;

#[cfg(test)]
pub(crate) mod tst;

pub mod prelude {
    pub use crate::common::PrefetchFile;
    pub use crate::prefetch::{
        read_prefetch_bytes, read_prefetch_file, read_prefetch_file_compressed,
        read_prefetch_file_no_compressed, read_prefetch_form_fs,
    };
}
