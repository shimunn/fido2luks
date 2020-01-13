use crate::error::*;
use crate::util::sha256;

use ctap::{
    self,
    extensions::hmac::{FidoHmacCredential, HmacExtension},
    AuthenticatorOptions, FidoDevice, FidoError, FidoErrorKind, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
};

const RP_ID: &'static str = "fido2luks";

fn authenticator_options() -> Option<AuthenticatorOptions> {
    Some(AuthenticatorOptions {
        uv: false, //TODO: should get this from config
        rk: true,
    })
}

fn authenticator_rp() -> PublicKeyCredentialRpEntity<'static> {
    PublicKeyCredentialRpEntity {
        id: RP_ID,
        name: None,
        icon: None,
    }
}

fn authenticator_user(name: Option<&str>) -> PublicKeyCredentialUserEntity {
    PublicKeyCredentialUserEntity {
        id: &[0u8],
        name: name.unwrap_or(""),
        icon: None,
        display_name: name,
    }
}

pub fn make_credential_id(name: Option<&str>) -> Fido2LuksResult<FidoHmacCredential> {
    let mut errs = Vec::new();
    match get_devices()? {
        ref devs if devs.is_empty() => Err(Fido2LuksError::NoAuthenticatorError)?,
        devs => {
            for mut dev in devs.into_iter() {
                match dev
                    .make_hmac_credential_full(
                        authenticator_rp(),
                        authenticator_user(name),
                        &[0u8; 32],
                        &[],
                        authenticator_options(),
                    )
                    .map(|cred| cred.into())
                {
                    //TODO: make credentials device specific
                    Ok(cred) => {
                        return Ok(cred);
                    }
                    Err(e) => {
                        errs.push(e);
                    }
                }
            }
        }
    }
    Err(errs.pop().ok_or(Fido2LuksError::NoAuthenticatorError)?)?
}

pub fn perform_challenge(credential_id: &[u8], salt: &[u8; 32]) -> Fido2LuksResult<[u8; 32]> {
    let cred = FidoHmacCredential {
        id: credential_id.to_vec(),
        rp_id: RP_ID.to_string(),
    };
    let mut errs = Vec::new();
    match get_devices()? {
        ref devs if devs.is_empty() => Err(Fido2LuksError::NoAuthenticatorError)?,
        devs => {
            for mut dev in devs.into_iter() {
                match dev.get_hmac_assertion(&cred, &sha256(&[&salt[..]]), None, None) {
                    Ok(secret) => {
                        return Ok(secret.0);
                    }
                    Err(e) => {
                        errs.push(e);
                    }
                }
            }
        }
    }
    Err(errs.pop().ok_or(Fido2LuksError::NoAuthenticatorError)?)?
}

pub fn get_devices() -> Fido2LuksResult<Vec<FidoDevice>> {
    let mut devices = Vec::with_capacity(2);
    for di in ctap::get_devices()? {
        match FidoDevice::new(&di) {
            Err(e) => match e.kind() {
                FidoErrorKind::ParseCtap | FidoErrorKind::DeviceUnsupported => (),
                err => Err(FidoError::from(err))?,
            },
            Ok(dev) => devices.push(dev),
        }
    }
    Ok(devices)
}
