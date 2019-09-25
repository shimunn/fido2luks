// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use super::error::*;
use failure::ResultExt;
use num_traits::{FromPrimitive, ToPrimitive};

use std::io::{Read, Write};

static FRAME_INIT: u8 = 0x80;

#[repr(u8)]
#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum CtapCommand {
    Invalid = 0x00,
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
}

impl CtapCommand {
    pub fn to_wire_format(&self) -> u8 {
        match self.to_u8() {
            Some(x) => x,
            None => 0x00,
        }
    }
}

#[repr(u8)]
#[derive(FromPrimitive, Fail, Debug)]
pub enum CtapError {
    #[fail(display = "The command in the request is invalid")]
    InvalidCmd = 0x01,
    #[fail(display = "The parameter(s) in the request is invalid")]
    InvalidPar = 0x02,
    #[fail(display = "The length field (BCNT) is invalid for the request ")]
    InvalidLen = 0x03,
    #[fail(display = "The sequence does not match expected value ")]
    InvalidSeq = 0x04,
    #[fail(display = "The message has timed out ")]
    MsgTimeout = 0x05,
    #[fail(display = "The device is busy for the requesting channel ")]
    ChannelBusy = 0x06,
    #[fail(display = "Command requires channel lock ")]
    LockRequired = 0x0A,
    #[fail(display = "Reserved error")]
    NA = 0x0B,
    #[fail(display = "Unspecified error")]
    Other = 0x7F,
}

pub fn write_init_packet<W: Write>(
    mut writer: W,
    report_size: usize,
    cid: &[u8],
    cmd: &CtapCommand,
    size: u16,
    payload: &[u8],
) -> FidoResult<()> {
    if cid.len() != 4 {
        Err(FidoErrorKind::WritePacket)?
    }
    let mut packet = Vec::with_capacity(report_size);
    packet.push(0);
    packet.extend_from_slice(cid);
    packet.push(FRAME_INIT | cmd.to_wire_format());
    packet.push(((size >> 8) & 0xff) as u8);
    packet.push((size & 0xff) as u8);
    packet.extend_from_slice(payload);
    if packet.len() > report_size + 1 {
        Err(FidoErrorKind::WritePacket)?
    }
    packet.resize(report_size + 1, 0);
    writer
        .write_all(&packet)
        .context(FidoErrorKind::WritePacket)?;
    Ok(())
}

pub struct InitPacket {
    pub cid: [u8; 4],
    pub cmd: CtapCommand,
    pub size: u16,
    pub payload: Vec<u8>,
}

impl InitPacket {
    pub fn from_reader<R: Read>(mut reader: R, report_size: usize) -> FidoResult<InitPacket> {
        let mut buf = Vec::with_capacity(report_size);
        buf.resize(report_size, 0);
        reader
            .read_exact(&mut buf[0..report_size])
            .context(FidoErrorKind::ReadPacket)?;
        let mut cid = [0; 4];
        cid.copy_from_slice(&buf[0..4]);
        let cmd = match CtapCommand::from_u8(buf[4] ^ FRAME_INIT) {
            Some(cmd) => cmd,
            None => CtapCommand::Invalid,
        };
        let size = ((u16::from(buf[5])) << 8) | u16::from(buf[6]);
        let payload_end = if (size as usize) >= (report_size - 7) {
            report_size
        } else {
            size as usize + 7
        };
        let payload = buf.drain(7..payload_end).collect();
        Ok(InitPacket {
            cid,
            cmd,
            size,
            payload,
        })
    }
}

pub fn write_cont_packet<W: Write>(
    mut writer: W,
    report_size: usize,
    cid: &[u8],
    seq: u8,
    payload: &[u8],
) -> FidoResult<()> {
    if cid.len() != 4 {
        Err(FidoErrorKind::WritePacket)?
    }
    let mut packet = Vec::with_capacity(report_size);
    packet.push(0);
    packet.extend_from_slice(cid);
    packet.push(seq);
    packet.extend_from_slice(payload);
    if packet.len() > report_size + 1 {
        Err(FidoErrorKind::WritePacket)?
    }
    packet.resize(report_size + 1, 0);
    writer
        .write_all(&packet)
        .context(FidoErrorKind::WritePacket)?;
    Ok(())
}

pub struct ContPacket {
    pub cid: [u8; 4],
    pub seq: u8,
    pub payload: Vec<u8>,
}

impl ContPacket {
    pub fn from_reader<R: Read>(
        mut reader: R,
        report_size: usize,
        expected_data: usize,
    ) -> FidoResult<ContPacket> {
        let mut buf = Vec::with_capacity(report_size);
        buf.resize(report_size, 0);
        reader
            .read_exact(&mut buf[0..report_size])
            .context(FidoErrorKind::ReadPacket)?;
        let mut cid = [0; 4];
        cid.copy_from_slice(&buf[0..4]);
        let seq = buf[4];
        let payload_end = if expected_data >= (report_size - 5) {
            report_size
        } else {
            expected_data + 5
        };
        let payload = buf.drain(5..payload_end).collect();
        Ok(ContPacket { cid, seq, payload })
    }
}
