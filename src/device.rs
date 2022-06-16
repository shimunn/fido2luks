use crate::error::*;

use crate::util;
use ctap_hid_fido2;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params;
use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::MakeCredentialArgsBuilder;
use ctap_hid_fido2::get_fidokey_devices;
use ctap_hid_fido2::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::HidInfo;
use ctap_hid_fido2::LibCfg;
use std::time::Duration;

const RP_ID: &str = "fido2luks";

fn lib_cfg() -> LibCfg {
    let mut cfg = LibCfg::init();
    cfg.enable_log = false;
    cfg.keep_alive_msg = String::new();
    cfg
}

pub fn make_credential_id(
    name: Option<&str>,
    pin: Option<&str>,
    exclude: &[&PublicKeyCredentialDescriptor],
) -> Fido2LuksResult<PublicKeyCredentialDescriptor> {
    let mut req = MakeCredentialArgsBuilder::new(RP_ID, &[])
        .extensions(&[make_credential_params::Extension::HmacSecret(Some(true))]);
    if let Some(pin) = pin {
        req = req.pin(pin);
    } else {
        req = req.without_pin_and_uv();
    }
    for cred in exclude {
        req = req.exclude_authenticator(cred.id.as_ref());
    }
    if let Some(_) = name {
        req = req.user_entity(&PublicKeyCredentialUserEntity::new(
            Some(b"00"),
            name.clone(),
            name,
        ));
    }
    let devices = get_devices()?;
    let mut err: Option<Fido2LuksError> = None;
    let req = req.build();
    for dev in devices {
        let handle = FidoKeyHidFactory::create_by_params(&vec![dev.param], &lib_cfg()).unwrap();
        match handle.make_credential_with_args(&req) {
            Ok(resp) => return Ok(resp.credential_descriptor),
            Err(e) => err = Some(e.into()),
        }
    }
    Err(err.unwrap_or(Fido2LuksError::NoAuthenticatorError))
}

pub fn perform_challenge<'a>(
    credentials: &'a [&'a PublicKeyCredentialDescriptor],
    salt: &[u8; 32],
    _timeout: Duration,
    pin: Option<&str>,
) -> Fido2LuksResult<([u8; 32], &'a PublicKeyCredentialDescriptor)> {
    if credentials.is_empty() {
        return Err(Fido2LuksError::InsufficientCredentials);
    }
    let mut req = GetAssertionArgsBuilder::new(RP_ID, &[]).extensions(&[
        get_assertion_params::Extension::HmacSecret(Some(util::sha256(&[&salt[..]]))),
    ]);
    for cred in credentials {
        req = req.add_credential_id(&cred.id);
    }
    if let Some(pin) = pin {
        req = req.pin(pin);
    } else {
        req = req.without_pin_and_uv();
    }
    let process_response = |resp: Vec<get_assertion_params::Assertion>| -> Fido2LuksResult<([u8; 32], &'a PublicKeyCredentialDescriptor)> {
    for att in resp {
        for ext in att.extensions.iter() {
            match ext {
                get_assertion_params::Extension::HmacSecret(Some(secret)) => {
                    //TODO: eliminate unwrap
                    let cred_used = credentials
                        .iter()
                        .copied()
                        .find(|cred| {
                            att.credential_id == cred.id
                        })
                        .unwrap();
                    return Ok((secret.clone(), cred_used));
                }
                _ => continue,
            }
        }
     }
        Err(Fido2LuksError::WrongSecret)
    };

    let devices = get_devices()?;
    let mut err: Option<Fido2LuksError> = None;
    let req = req.build();
    for dev in devices {
        let handle = FidoKeyHidFactory::create_by_params(&vec![dev.param], &lib_cfg()).unwrap();
        match handle.get_assertion_with_args(&req) {
            Ok(resp) => return process_response(resp),
            Err(e) => err = Some(e.into()),
        }
    }
    Err(err.unwrap_or(Fido2LuksError::NoAuthenticatorError))
}

pub fn may_require_pin() -> Fido2LuksResult<bool> {
    for dev in get_devices()? {
        let handle = FidoKeyHidFactory::create_by_params(&vec![dev.param], &lib_cfg()).unwrap();
        let info = handle.get_info()?;
        let needs_pin = info
            .options
            .iter()
            .any(|(name, val)| &name[..] == "clientPin" && *val);
        if needs_pin {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn get_devices() -> Fido2LuksResult<Vec<HidInfo>> {
    Ok(get_fidokey_devices())
}
