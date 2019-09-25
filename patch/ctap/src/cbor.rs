// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use cbor_codec::value;
use cbor_codec::value::Value;
use cbor_codec::{Config, Decoder, Encoder, GenericDecoder, GenericEncoder};

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use failure::ResultExt;

use std::collections::HashMap;
use std::io::Cursor;

use super::error::*;

pub enum Request<'a> {
    MakeCredential(MakeCredentialRequest<'a>),
    GetAssertion(GetAssertionRequest<'a>),
    GetInfo,
    ClientPin(ClientPinRequest<'a>),
}

impl<'a> Request<'a> {
    pub fn encode<W: WriteBytesExt>(&self, writer: &mut W) -> FidoResult<()> {
        let mut encoder = Encoder::new(writer);
        match self {
            Request::MakeCredential(req) => req.encode(&mut encoder),
            Request::GetAssertion(req) => req.encode(&mut encoder),
            Request::GetInfo => encoder
                .writer()
                .write_u8(0x04)
                .context(FidoErrorKind::CborEncode)
                .map_err(From::from),
            Request::ClientPin(req) => req.encode(&mut encoder),
        }
    }

    pub fn decode<R: ReadBytesExt>(&self, reader: R) -> FidoResult<Response> {
        Ok(match self {
            Request::MakeCredential(_) => {
                Response::MakeCredential(MakeCredentialResponse::decode(reader)?)
            }
            Request::GetAssertion(_) => {
                Response::GetAssertion(GetAssertionResponse::decode(reader)?)
            }
            Request::GetInfo => Response::GetInfo(GetInfoResponse::decode(reader)?),
            Request::ClientPin(_) => Response::ClientPin(ClientPinResponse::decode(reader)?),
        })
    }
}

#[derive(Debug)]
pub enum Response {
    MakeCredential(MakeCredentialResponse),
    GetAssertion(GetAssertionResponse),
    GetInfo(GetInfoResponse),
    ClientPin(ClientPinResponse),
}

#[derive(Default, Debug)]
pub struct MakeCredentialRequest<'a> {
    pub client_data_hash: &'a [u8],
    pub rp: PublicKeyCredentialRpEntity<'a>,
    pub user: PublicKeyCredentialUserEntity<'a>,
    pub pub_key_cred_params: &'a [(&'a str, i32)],
    pub exclude_list: &'a [PublicKeyCredentialDescriptor],
    pub extensions: &'a [(&'a str, &'a Value)],
    pub options: Option<AuthenticatorOptions>,
    pub pin_auth: Option<[u8; 16]>,
    pub pin_protocol: Option<u8>,
}

impl<'a> MakeCredentialRequest<'a> {
    pub fn encode<W: WriteBytesExt>(&self, mut encoder: &mut Encoder<W>) -> FidoResult<()> {
        encoder
            .writer()
            .write_u8(0x01)
            .context(FidoErrorKind::CborEncode)?; // authenticatorMakeCredential
        let mut length = 4;
        length += !self.exclude_list.is_empty() as usize;
        length += !self.extensions.is_empty() as usize;
        length += self.options.is_some() as usize;
        length += self.pin_auth.is_some() as usize;
        length += self.pin_protocol.is_some() as usize;
        encoder.object(length)?;
        encoder.u8(0x01)?; // clientDataHash
        encoder.bytes(&self.client_data_hash)?;
        encoder.u8(0x02)?; // rp
        self.rp.encode(&mut encoder)?;
        encoder.u8(0x03)?; // user
        self.user.encode(&mut encoder)?;
        encoder.u8(0x04)?; // pubKeyCredParams
        encoder.array(self.pub_key_cred_params.len())?;
        for (cred_type, alg) in self.pub_key_cred_params {
            encoder.object(2)?;
            encoder.text("alg")?;
            encoder.i32(*alg)?;
            encoder.text("type")?;
            encoder.text(&cred_type)?;
        }
        if self.exclude_list.len() > 0 {
            encoder.u8(0x05)?; // excludeList
            encoder.array(self.exclude_list.len())?;
            for item in self.exclude_list {
                item.encode(&mut encoder)?;
            }
        }
        if self.extensions.len() > 0 {
            encoder.u8(0x06)?; // extensions
            encoder.object(self.extensions.len())?;
            for (key, value) in self.extensions {
                encoder.text(key)?;
                let mut generic = GenericEncoder::new(encoder.writer());
                generic.value(value)?;
            }
        }
        if let Some(options) = &self.options {
            if options.encoded() {
                encoder.u8(0x07)?; // options
                options.encode(&mut encoder)?;
            }
        }
        if let Some(pin_auth) = &self.pin_auth {
            encoder.u8(0x08)?; // pinAuth
            encoder.bytes(pin_auth)?;
        }
        if let Some(pin_protocol) = &self.pin_protocol {
            encoder.u8(0x09)?; // pinProtocol
            encoder.u8(*pin_protocol)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MakeCredentialResponse {
    pub format: String,
    pub auth_data: AuthenticatorData,
}

impl MakeCredentialResponse {
    pub fn decode<R: ReadBytesExt>(mut reader: R) -> FidoResult<Self> {
        let status = reader.read_u8().context(FidoErrorKind::CborDecode)?;
        if status != 0 {
            Err(FidoErrorKind::CborError(status))?
        }
        let mut decoder = Decoder::new(Config::default(), reader);
        let mut response = MakeCredentialResponse::default();
        for _ in 0..decoder.object()? {
            let key = decoder.u8()?;
            match key {
                0x01 => response.format = decoder.text()?,
                0x02 => response.auth_data = AuthenticatorData::from_bytes(&decoder.bytes()?)?,
                0x03 => break, // TODO: parse attestation
                _ => continue,
            }
        }
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct GetAssertionRequest<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8],
    pub allow_list: &'a [PublicKeyCredentialDescriptor],
    pub extensions: &'a [(&'a str, &'a Value)],
    pub options: Option<AuthenticatorOptions>,
    pub pin_auth: Option<[u8; 16]>,
    pub pin_protocol: Option<u8>,
}

impl<'a> GetAssertionRequest<'a> {
    pub fn encode<W: WriteBytesExt>(&self, mut encoder: &mut Encoder<W>) -> FidoResult<()> {
        encoder
            .writer()
            .write_u8(0x02)
            .context(FidoErrorKind::CborEncode)?; // authenticatorGetAssertion
        let mut length = 2;
        length += !self.allow_list.is_empty() as usize;
        length += !self.extensions.is_empty() as usize;
        length += self.options.is_some() as usize;
        length += self.pin_auth.is_some() as usize;
        length += self.pin_protocol.is_some() as usize;
        encoder.object(length)?;
        encoder.u8(0x01)?; // rpId
        encoder.text(&self.rp_id)?;
        encoder.u8(0x02)?; // clientDataHash
        encoder.bytes(self.client_data_hash)?;
        if !self.allow_list.is_empty() {
            encoder.u8(0x03)?; // allowList
            encoder.array(self.allow_list.len())?;
            for item in self.allow_list {
                item.encode(&mut encoder)?;
            }
        }
        if self.extensions.len() > 0 {
            encoder.u8(0x04)?; // extensions
            encoder.object(self.extensions.len())?;
            for (key, value) in self.extensions {
                encoder.text(key)?;
                let mut generic = GenericEncoder::new(encoder.writer());
                generic.value(value)?;
            }
        }
        if let Some(options) = &self.options {
            if options.encoded() {
                encoder.u8(0x05)?; // options
                options.encode(&mut encoder)?;
            }
        }
        if let Some(pin_auth) = &self.pin_auth {
            encoder.u8(0x06)?; // pinAuth
            encoder.bytes(pin_auth)?;
        }
        if let Some(pin_protocol) = &self.pin_protocol {
            encoder.u8(0x07)?; // pinProtocol
            encoder.u8(*pin_protocol)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct GetAssertionResponse {
    pub credential: Option<PublicKeyCredentialDescriptor>,
    pub auth_data_bytes: Vec<u8>,
    pub auth_data: AuthenticatorData,
    pub signature: Vec<u8>,
}

impl GetAssertionResponse {
    pub fn decode<R: ReadBytesExt>(mut reader: R) -> FidoResult<Self> {
        let status = reader.read_u8().context(FidoErrorKind::CborDecode)?;
        if status != 0 {
            Err(FidoErrorKind::CborError(status))?
        }
        let mut decoder = Decoder::new(Config::default(), reader);
        let mut response = GetAssertionResponse::default();
        for _ in 0..decoder.object()? {
            let key = decoder.u8()?;
            match key {
                0x01 => {
                    response.credential = Some(PublicKeyCredentialDescriptor::decode(&mut decoder)?)
                }
                0x02 => {
                    response.auth_data_bytes = decoder.bytes()?;
                    response.auth_data = AuthenticatorData::from_bytes(&response.auth_data_bytes)?;
                }
                0x03 => response.signature = decoder.bytes()?,
                _ => continue,
            }
        }
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct GetInfoResponse {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: [u8; 16],
    pub options: OptionsInfo,
    pub max_msg_size: u16,
    pub pin_protocols: Vec<u8>,
}

impl GetInfoResponse {
    pub fn decode<R: ReadBytesExt>(mut reader: R) -> FidoResult<Self> {
        let status = reader.read_u8().context(FidoErrorKind::CborDecode)?;
        if status != 0 {
            Err(FidoErrorKind::CborError(status))?
        }
        let mut decoder = Decoder::new(Config::default(), reader);
        let mut response = GetInfoResponse::default();
        for _ in 0..decoder.object()? {
            match decoder.u8()? {
                0x01 => {
                    for _ in 0..decoder.array()? {
                        response.versions.push(decoder.text()?);
                    }
                }
                0x02 => {
                    for _ in 0..decoder.array()? {
                        response.extensions.push(decoder.text()?);
                    }
                }
                0x03 => response.aaguid.copy_from_slice(&decoder.bytes()?[..]),
                0x04 => response.options = OptionsInfo::decode(&mut decoder)?,
                0x05 => response.max_msg_size = decoder.u16()?,
                0x06 => {
                    for _ in 0..decoder.array()? {
                        response.pin_protocols.push(decoder.u8()?);
                    }
                }
                _ => continue,
            }
        }
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct ClientPinRequest<'a> {
    pub pin_protocol: u8,
    pub sub_command: u8,
    pub key_agreement: Option<&'a CoseKey>,
    pub pin_auth: Option<[u8; 16]>,
    pub new_pin_enc: Option<Vec<u8>>,
    pub pin_hash_enc: Option<[u8; 16]>,
}

impl<'a> ClientPinRequest<'a> {
    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        encoder
            .writer()
            .write_u8(0x06)
            .context(FidoErrorKind::CborEncode)?; // authenticatorClientPIN
        let mut length = 2;
        length += self.key_agreement.is_some() as usize;
        length += self.pin_auth.is_some() as usize;
        length += self.new_pin_enc.is_some() as usize;
        length += self.pin_hash_enc.is_some() as usize;
        encoder.object(length)?;
        encoder.u8(0x01)?; // pinProtocol
        encoder.u8(self.pin_protocol)?;
        encoder.u8(0x02)?; // subCommand
        encoder.u8(self.sub_command)?;
        if let Some(key_agreement) = self.key_agreement {
            encoder.u8(0x03)?; // keyAgreement
            key_agreement.encode(encoder)?;
        }
        if let Some(pin_auth) = &self.pin_auth {
            encoder.u8(0x04)?; // pinAuth
            encoder.bytes(pin_auth)?;
        }
        if let Some(new_pin_enc) = &self.new_pin_enc {
            encoder.u8(0x05)?; // newPinEnc
            encoder.bytes(&new_pin_enc)?;
        }
        if let Some(pin_hash_enc) = &self.pin_hash_enc {
            encoder.u8(0x06)?; // pinHashEnc
            encoder.bytes(pin_hash_enc)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ClientPinResponse {
    pub key_agreement: Option<CoseKey>,
    pub pin_token: Option<[u8; 16]>,
    pub retries: Option<u8>,
}

impl ClientPinResponse {
    pub fn decode<R: ReadBytesExt>(mut reader: R) -> FidoResult<Self> {
        let status = reader.read_u8().context(FidoErrorKind::CborDecode)?;
        if status != 0 {
            Err(FidoErrorKind::CborError(status))?
        }
        let mut decoder = Decoder::new(Config::default(), reader);
        let mut response = ClientPinResponse::default();
        for _ in 0..decoder.object()? {
            match decoder.u8()? {
                0x01 => {
                    let mut generic = GenericDecoder::from_decoder(decoder);
                    response.key_agreement = Some(CoseKey::decode(&mut generic)?);
                    decoder = generic.into_inner();
                }
                0x02 => {
                    let mut pin_token = [0; 16];
                    pin_token.copy_from_slice(&decoder.bytes()?[..]);
                    response.pin_token = Some(pin_token)
                }
                0x03 => response.retries = Some(decoder.u8()?),
                _ => continue,
            }
        }
        Ok(response)
    }
}

#[derive(Debug)]
pub struct OptionsInfo {
    pub plat: bool,
    pub rk: bool,
    pub client_pin: Option<bool>,
    pub up: bool,
    pub uv: Option<bool>,
}

impl Default for OptionsInfo {
    fn default() -> Self {
        OptionsInfo {
            plat: false,
            rk: false,
            client_pin: None,
            up: true,
            uv: None,
        }
    }
}

impl OptionsInfo {
    pub fn decode<R: ReadBytesExt>(decoder: &mut Decoder<R>) -> FidoResult<Self> {
        let mut options = OptionsInfo::default();
        for _ in 0..decoder.object()? {
            match decoder.text()?.as_ref() {
                "plat" => options.plat = decoder.bool()?,
                "rk" => options.rk = decoder.bool()?,
                "clientPin" => options.client_pin = Some(decoder.bool()?),
                "up" => options.up = decoder.bool()?,
                "uv" => options.uv = Some(decoder.bool()?),
                _ => continue,
            }
        }
        Ok(options)
    }
}

#[derive(Debug, Default)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub up: bool,
    pub uv: bool,
    pub sign_count: u32,
    pub attested_credential_data: AttestedCredentialData,
    pub extensions: HashMap<String, Value>,
}

impl AuthenticatorData {
    pub fn from_bytes(bytes: &[u8]) -> FidoResult<Self> {
        let mut data = AuthenticatorData::default();
        data.rp_id_hash.copy_from_slice(&bytes[0..32]);
        let flags = bytes[32];
        data.up = (flags & 0x01) == 0x01;
        data.uv = (flags & 0x02) == 0x02;
        let is_attested = (flags & 0x40) == 0x40;
        let has_extension_data = (flags & 0x80) == 0x80;
        data.sign_count = BigEndian::read_u32(&bytes[33..37]);
        if bytes.len() < 38 {
            return Ok(data);
        }

        let mut cur = Cursor::new(&bytes[37..]);
        if is_attested {
            let attested_credential_data = AttestedCredentialData::from_bytes(&mut cur)?;
            data.attested_credential_data = attested_credential_data;
            if cur.position() >= (bytes.len() - 37) as u64 {
                return Ok(data);
            }
        }
        if has_extension_data {
            let mut decoder = GenericDecoder::new(Config::default(), cur);
            for _ in 0..decoder.borrow_mut().object()? {
                let key = decoder.borrow_mut().text()?;
                let value = decoder.value()?;
                data.extensions.insert(key.to_string(), value);
            }
        }
        Ok(data)
    }
}

#[derive(Debug, Default)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: CoseKey,
}

impl AttestedCredentialData {
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> FidoResult<Self> {
        let mut response = AttestedCredentialData::default();
        let bytes = cur.get_ref();
        if bytes.is_empty() {
            return Ok(response);
        }
        response.aaguid.copy_from_slice(&bytes[0..16]);
        let id_length = BigEndian::read_u16(&bytes[16..18]) as usize;
        response.credential_id = Vec::from(&bytes[18..(18 + id_length)]);
        cur.set_position(18 + id_length as u64);
        let mut decoder = GenericDecoder::new(Config::default(), cur);
        response.credential_public_key = CoseKey::decode(&mut decoder)?;
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct P256Key {
    x: [u8; 32],
    y: [u8; 32],
}

impl P256Key {
    pub fn from_cose(cose: &CoseKey) -> FidoResult<Self> {
        if cose.key_type != 2 || cose.algorithm != -7 {
            Err(FidoErrorKind::KeyType)?
        }
        if let (
            Some(Value::U8(curve)),
            Some(Value::Bytes(value::Bytes::Bytes(x))),
            Some(Value::Bytes(value::Bytes::Bytes(y))),
        ) = (
            cose.parameters.get(&-1),
            cose.parameters.get(&-2),
            cose.parameters.get(&-3),
        ) {
            if *curve != 1 {
                Err(FidoErrorKind::KeyType)?
            }
            let mut key = P256Key::default();
            key.x.copy_from_slice(&x);
            key.y.copy_from_slice(&y);
            return Ok(key);
        }
        Err(FidoErrorKind::KeyType)?
    }

    pub fn from_bytes(bytes: &[u8]) -> FidoResult<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            Err(FidoErrorKind::CborDecode)?
        }
        let mut res = P256Key::default();
        res.x.copy_from_slice(&bytes[1..33]);
        res.y.copy_from_slice(&bytes[33..65]);
        Ok(res)
    }

    pub fn to_cose(&self) -> CoseKey {
        CoseKey {
            key_type: 2,
            algorithm: -7,
            parameters: [
                (-1, Value::U8(1)),
                (-2, Value::Bytes(value::Bytes::Bytes(self.x.to_vec()))),
                (-3, Value::Bytes(value::Bytes::Bytes(self.y.to_vec()))),
            ]
            .iter()
            .cloned()
            .collect(),
        }
    }

    pub fn bytes(&self) -> [u8; 65] {
        let mut bytes = [0; 65];
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(&self.x);
        bytes[33..65].copy_from_slice(&self.y);
        bytes
    }
}

#[derive(Debug, Default)]
pub struct CoseKey {
    key_type: u16,
    algorithm: i32,
    parameters: HashMap<i16, Value>,
}

impl CoseKey {
    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        let size = 1 + self.parameters.len();
        encoder.object(size)?;
        encoder.i16(0x01)?; // keyType
        encoder.u16(self.key_type)?;
        //encoder.i16(0x02)?; // algorithm
        //encoder.i32(self.algorithm)?;
        for (key, value) in self.parameters.iter() {
            encoder.i16(*key)?;
            let mut generic = GenericEncoder::new(encoder.writer());
            generic.value(value)?;
        }
        Ok(())
    }

    pub fn decode<R: ReadBytesExt>(generic: &mut GenericDecoder<R>) -> FidoResult<Self> {
        let items;
        {
            let decoder = generic.borrow_mut();
            items = decoder.object()?;
        }
        let mut cose_key = CoseKey::default();
        cose_key.algorithm = -7;
        for _ in 0..items {
            match generic.borrow_mut().i16()? {
                0x01 => cose_key.key_type = generic.borrow_mut().u16()?,
                0x02 => cose_key.algorithm = generic.borrow_mut().i32()?,
                key if key < 0 => {
                    cose_key.parameters.insert(key, generic.value()?);
                }
                _ => {
                    generic.value()?; // skip unknown parameter
                }
            }
        }
        Ok(cose_key)
    }
}

#[derive(Debug, Default)]
pub struct PublicKeyCredentialRpEntity<'a> {
    pub id: &'a str,
    pub name: Option<&'a str>,
    pub icon: Option<&'a str>,
}

impl<'a> PublicKeyCredentialRpEntity<'a> {
    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        let mut length = 1;
        length += self.name.is_some() as usize;
        length += self.icon.is_some() as usize;
        encoder.object(length)?;
        encoder.text("id")?;
        encoder.text(&self.id)?;
        if let Some(icon) = &self.icon {
            encoder.text("icon")?;
            encoder.text(&icon)?;
        }
        if let Some(name) = &self.name {
            encoder.text("name")?;
            encoder.text(&name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PublicKeyCredentialUserEntity<'a> {
    pub id: &'a [u8],
    pub name: &'a str,
    pub icon: Option<&'a str>,
    pub display_name: Option<&'a str>,
}

impl<'a> PublicKeyCredentialUserEntity<'a> {
    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        let mut length = 2;
        length += self.icon.is_some() as usize;
        length += self.display_name.is_some() as usize;
        encoder.object(length)?;
        encoder.text("id")?;
        encoder.bytes(&self.id)?;
        if let Some(icon) = &self.icon {
            encoder.text("icon")?;
            encoder.text(&icon)?;
        }
        encoder.text("name")?;
        encoder.text(&self.name)?;
        if let Some(display_name) = &self.display_name {
            encoder.text("displayName")?;
            encoder.text(&display_name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PublicKeyCredentialDescriptor {
    pub cred_type: String,
    pub id: Vec<u8>,
}

impl PublicKeyCredentialDescriptor {
    pub fn decode<R: ReadBytesExt>(decoder: &mut Decoder<R>) -> FidoResult<Self> {
        let mut response = PublicKeyCredentialDescriptor::default();
        for _ in 0..decoder.object()? {
            match decoder.text()?.as_ref() {
                "id" => response.id = decoder.bytes()?,
                "type" => response.cred_type = decoder.text()?,
                _ => continue,
            }
        }
        Ok(response)
    }

    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        encoder.object(2)?;
        encoder.text("id")?;
        encoder.bytes(&self.id)?;
        encoder.text("type")?;
        encoder.text(&self.cred_type)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AuthenticatorOptions {
    pub rk: bool,
    pub uv: bool,
}

impl AuthenticatorOptions {
    pub fn encoded(&self) -> bool {
        self.rk || self.uv
    }

    pub fn encode<W: WriteBytesExt>(&self, encoder: &mut Encoder<W>) -> FidoResult<()> {
        let length = (self.rk as usize) + (self.uv as usize);
        encoder.object(length)?;
        if self.rk {
            encoder.text("rk")?;
            encoder.bool(true)?;
        }
        if self.uv {
            encoder.text("uv")?;
            encoder.bool(true)?;
        }
        Ok(())
    }
}
