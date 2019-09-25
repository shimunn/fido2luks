// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
pub use super::hid_common::*;
use byteorder::{ByteOrder, LittleEndian};
use std::fs;
use std::io;
use std::path::PathBuf;

static REPORT_DESCRIPTOR_KEY_MASK: u8 = 0xfc;
static LONG_ITEM_ENCODING: u8 = 0xfe;
static USAGE_PAGE: u8 = 0x04;
static USAGE: u8 = 0x08;
static REPORT_SIZE: u8 = 0x74;

pub fn enumerate() -> io::Result<impl Iterator<Item = DeviceInfo>> {
    fs::read_dir("/sys/class/hidraw").map(|entries| {
        entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| path_to_device(&entry.path()).ok())
    })
}

fn path_to_device(path: &PathBuf) -> io::Result<DeviceInfo> {
    let mut rd_path = path.clone();
    rd_path.push("device/report_descriptor");
    let rd = fs::read(rd_path)?;
    let mut usage_page: u16 = 0;
    let mut usage: u16 = 0;
    let mut report_size: u16 = 0;
    let mut pos: usize = 0;

    while pos < rd.len() {
        let key = rd[pos];
        let mut key_size: usize = 1;
        let mut size: u8;

        if key == LONG_ITEM_ENCODING {
            key_size = 3;
            size = rd[pos + 1];
        } else {
            size = key & 0x03;

            if size == 0x03 {
                size = 0x04
            }
        }

        if key & REPORT_DESCRIPTOR_KEY_MASK == USAGE_PAGE {
            if size != 2 {
                usage_page = u16::from(rd[pos + 1])
            } else {
                usage_page = LittleEndian::read_u16(&rd[(pos + 1)..(pos + 1 + (size as usize))]);
            }
        }

        if key & REPORT_DESCRIPTOR_KEY_MASK == USAGE {
            if size != 2 {
                usage = u16::from(rd[pos + 1])
            } else {
                usage = LittleEndian::read_u16(&rd[(pos + 1)..(pos + 1 + (size as usize))]);
            }
        }

        if key & REPORT_DESCRIPTOR_KEY_MASK == REPORT_SIZE {
            if size != 2 {
                report_size = u16::from(rd[pos + 1])
            } else {
                report_size = LittleEndian::read_u16(&rd[(pos + 1)..(pos + 1 + (size as usize))]);
            }
        }

        pos = pos + key_size + size as usize;
    }

    let mut device_path = PathBuf::from("/dev");
    device_path.push(path.file_name().unwrap());

    Ok(DeviceInfo {
        path: device_path,
        usage_page,
        usage,
        report_size,
    })
}
