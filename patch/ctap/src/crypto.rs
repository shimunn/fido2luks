// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use super::cbor::{CoseKey, P256Key};
use super::error::*;
use failure::ResultExt;
use ring::error::Unspecified;
use ring::{agreement, digest, hmac, rand, signature};
use rust_crypto::aes;
use rust_crypto::blockmodes::NoPadding;
use rust_crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use rust_crypto::symmetriccipher::{Decryptor, Encryptor};
use untrusted::Input;

#[derive(Debug)]
pub struct SharedSecret {
    pub public_key: CoseKey,
    pub shared_secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> FidoResult<Self> {
        let rng = rand::SystemRandom::new();
        let private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .context(FidoErrorKind::GenerateKey)?;
        let public = &mut [0u8; agreement::PUBLIC_KEY_MAX_LEN][..private.public_key_len()];
        private
            .compute_public_key(public)
            .context(FidoErrorKind::GenerateKey)?;
        let peer = P256Key::from_cose(peer_key)
            .context(FidoErrorKind::ParsePublic)?
            .bytes();
        let peer = Input::from(&peer);
        let shared_secret = agreement::agree_ephemeral(
            private,
            &agreement::ECDH_P256,
            peer,
            Unspecified,
            |material| Ok(digest::digest(&digest::SHA256, material)),
        )
        .context(FidoErrorKind::GenerateSecret)?;
        let mut res = SharedSecret {
            public_key: P256Key::from_bytes(&public)
                .context(FidoErrorKind::ParsePublic)?
                .to_cose(),
            shared_secret: [0; 32],
        };
        res.shared_secret.copy_from_slice(shared_secret.as_ref());
        Ok(res)
    }

    pub fn encryptor(&self) -> Box<dyn Encryptor + 'static> {
        aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.shared_secret,
            &[0u8; 16],
            NoPadding,
        )
    }

    pub fn encrypt_pin(&self, pin: &str) -> FidoResult<[u8; 16]> {
        let mut encryptor = self.encryptor();
        let pin_bytes = pin.as_bytes();
        let hash = digest::digest(&digest::SHA256, &pin_bytes);
        let in_bytes = &hash.as_ref()[0..16];
        let mut input = RefReadBuffer::new(&in_bytes);
        let mut out_bytes = [0; 16];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        encryptor
            .encrypt(&mut input, &mut output, true)
            .map_err(|_| FidoErrorKind::EncryptPin)?;
        Ok(out_bytes)
    }

    pub fn decryptor(&self) -> Box<dyn Decryptor + 'static> {
        aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &self.shared_secret,
            &[0u8; 16],
            NoPadding,
        )
    }

    pub fn decrypt_token(&self, data: &mut [u8]) -> FidoResult<PinToken> {
        let mut decryptor = self.decryptor();
        let mut input = RefReadBuffer::new(data);
        let mut out_bytes = [0; 16];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        decryptor
            .decrypt(&mut input, &mut output, true)
            .map_err(|_| FidoErrorKind::DecryptPin)?;
        Ok(PinToken(hmac::SigningKey::new(&digest::SHA256, &out_bytes)))
    }
}

pub struct PinToken(hmac::SigningKey);

impl PinToken {
    pub fn auth(&self, data: &[u8]) -> [u8; 16] {
        let signature = hmac::sign(&self.0, &data);
        let mut out = [0; 16];
        out.copy_from_slice(&signature.as_ref()[0..16]);
        out
    }
}

pub fn verify_signature(
    public_key: &[u8],
    client_data: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> bool {
    let public_key = Input::from(&public_key);
    let msg_len = client_data.len() + auth_data.len();
    let mut msg = Vec::with_capacity(msg_len);
    msg.extend_from_slice(auth_data);
    msg.extend_from_slice(client_data);
    let msg = Input::from(&msg);
    let signature = Input::from(signature);
    signature::verify(
        &signature::ECDSA_P256_SHA256_ASN1,
        public_key,
        msg,
        signature,
    )
    .is_ok()
}
