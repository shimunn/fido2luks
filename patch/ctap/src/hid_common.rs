// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::path::PathBuf;

#[derive(Debug, Clone)]
/// Storage for device related information
pub struct DeviceInfo {
    pub path: PathBuf,
    pub usage_page: u16,
    pub usage: u16,
    pub report_size: u16,
}
