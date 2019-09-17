use crate::error::*;

use ctap;
use ctap::extensions::hmac::{FidoHmacCredential, HmacExtension};
use ctap::FidoDevice;

pub fn perform_challenge(credential_id: &str, salt: &[u8; 32]) -> Fido2LuksResult<[u8; 32]> {
    let cred = FidoHmacCredential {
        id: hex::decode(credential_id).unwrap(),
        rp_id: "hmac".to_string(),
    };
    let mut errs = Vec::new();
    for di in ctap::get_devices()? {
        let mut dev = FidoDevice::new(&di)?;
        match dev.hmac_challange(&cred, &salt[..]) {
            Ok(secret) => {
                return Ok(secret);
            }
            Err(e) => {
                errs.push(e);
            }
        }
    }
    Err(errs.pop().ok_or(Fido2LuksError::NoAuthenticatorError)?)?
}
