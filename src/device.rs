use crate::error::*;

use ctap;
use ctap::extensions::hmac::{FidoHmacCredential, HmacExtension};
use ctap::{FidoDevice, FidoError, FidoErrorKind};

pub fn make_credential_id() -> Fido2LuksResult<FidoHmacCredential> {
    let mut errs = Vec::new();
    match get_devices()? {
        ref devs if devs.is_empty() => Err(Fido2LuksError::NoAuthenticatorError)?,
        devs => {
            for mut dev in devs.into_iter() {
                match dev.make_hmac_credential() {
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

pub fn perform_challenge(credential_id: &str, salt: &[u8; 32]) -> Fido2LuksResult<[u8; 32]> {
    let cred = FidoHmacCredential {
        id: hex::decode(credential_id).unwrap(),
        rp_id: "hmac".to_string(),
    };
    let mut errs = Vec::new();
    match get_devices()? {
        ref devs if devs.is_empty() => Err(Fido2LuksError::NoAuthenticatorError)?,
        devs => {
            for mut dev in devs.into_iter() {
                match dev.hmac_challange(&cred, &salt[..]) {
                    Ok(secret) => {
                        return Ok(secret);
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
