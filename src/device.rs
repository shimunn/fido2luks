use crate::error::*;

use crate::util;
use ctap::{
    self, extensions::hmac::HmacExtension, request_multiple_devices, FidoAssertionRequestBuilder,
    FidoCredential, FidoCredentialRequestBuilder, FidoDevice, FidoError, FidoErrorKind,
};
use std::time::Duration;

const RP_ID: &str = "fido2luks";

pub fn make_credential_id(
    name: Option<&str>,
    pin: Option<&str>,
) -> Fido2LuksResult<FidoCredential> {
    let mut request = FidoCredentialRequestBuilder::default().rp_id(RP_ID);
    if let Some(user_name) = name {
        request = request.user_name(user_name);
    }
    let request = request.build().unwrap();
    let make_credential = |device: &mut FidoDevice| {
        if let Some(pin) = pin {
            device.unlock(pin)?;
        }
        device.make_hmac_credential(&request)
    };
    Ok(request_multiple_devices(
        get_devices()?
            .iter_mut()
            .map(|device| (device, &make_credential)),
        None,
    )?)
}

pub fn perform_challenge<'a>(
    credentials: &'a [&'a FidoCredential],
    salt: &[u8; 32],
    timeout: Duration,
    pin: Option<&str>,
) -> Fido2LuksResult<([u8; 32], &'a FidoCredential)> {
    let request = FidoAssertionRequestBuilder::default()
        .rp_id(RP_ID)
        .credentials(credentials)
        .build()
        .unwrap();
    let get_assertion = |device: &mut FidoDevice| {
        if let Some(pin) = pin {
            device.unlock(pin)?;
        }
        device.get_hmac_assertion(&request, &util::sha256(&[&salt[..]]), None)
    };
    let (credential, (secret, _)) = request_multiple_devices(
        get_devices()?
            .iter_mut()
            .map(|device| (device, &get_assertion)),
        Some(timeout),
    )?;
    Ok((secret, credential))
}

pub fn get_devices() -> Fido2LuksResult<Vec<FidoDevice>> {
    let mut devices = Vec::with_capacity(2);
    for di in ctap::get_devices()? {
        match FidoDevice::new(&di) {
            Err(e) => match e.kind() {
                FidoErrorKind::ParseCtap | FidoErrorKind::DeviceUnsupported => (),
                err => return Err(FidoError::from(err).into()),
            },
            Ok(dev) => devices.push(dev),
        }
    }
    Ok(devices)
}
