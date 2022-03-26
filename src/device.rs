use crate::error::*;

use crate::util;
use ctap_hid_fido2;
use ctap_hid_fido2::get_assertion_params;
use ctap_hid_fido2::get_assertion_with_args;
use ctap_hid_fido2::get_info;
use ctap_hid_fido2::make_credential_params;
use ctap_hid_fido2::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::GetAssertionArgsBuilder;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::MakeCredentialArgsBuilder;
use std::time::Duration;

const RP_ID: &str = "fido2luks";

fn lib_cfg() -> LibCfg {
    let mut cfg = LibCfg::init();
    cfg.enable_log = false;
    cfg
}

pub fn make_credential_id(
    name: Option<&str>,
    pin: Option<&str>,
) -> Fido2LuksResult<PublicKeyCredentialDescriptor> {
    let mut req = MakeCredentialArgsBuilder::new(RP_ID, &[])
        .extensions(&[make_credential_params::Extension::HmacSecret(Some(true))]);
    if let Some(pin) = pin {
        req = req.pin(pin);
    } else {
        req = req.without_pin_and_uv();
    }
    if let Some(_) = name {
        req = req.rkparam(&PublicKeyCredentialUserEntity::new(
            Some(b"00"),
            name.clone(),
            name,
        ));
    }
    let resp = ctap_hid_fido2::make_credential_with_args(&lib_cfg(), &req.build())?;
    Ok(resp.credential_descriptor)
}

pub fn perform_challenge<'a>(
    credentials: &'a [&'a PublicKeyCredentialDescriptor],
    salt: &[u8; 32],
    timeout: Duration,
    pin: Option<&str>,
) -> Fido2LuksResult<([u8; 32], &'a PublicKeyCredentialDescriptor)> {
    let mut req = GetAssertionArgsBuilder::new(RP_ID, &[]).extensions(&[
        get_assertion_params::Extension::HmacSecret(Some(util::sha256(&[&salt[..]]))),
    ]);
    if let Some(pin) = pin {
        req = req.pin(pin);
    } else {
        req = req.without_pin_and_uv();
    }
    let resp = get_assertion_with_args(&lib_cfg(), &req.build())?;
    fn dbg_hex<'a>(name: &str, vec: &'a Vec<u8>) -> &'a Vec<u8> {
        dbg!((name, hex::encode(&vec)));
        vec
    }
    let cred_used2 = credentials.iter().copied().find(|cred| {
        resp.iter()
            .any(|att| dbg_hex("att", &att.credential_id) == dbg_hex("cred", &cred.id))
    });
    for att in resp {
        for ext in att.extensions.iter() {
            match ext {
                get_assertion_params::Extension::HmacSecret(Some(secret)) => {
                    dbg!(cred_used2);
                    //TODO: eliminate unwrap
                    let cred_used = credentials
                        .iter()
                        .copied()
                        .find(|cred| {
                            dbg_hex("att", &att.credential_id) == dbg_hex("cred", &cred.id)
                        })
                        .unwrap();
                    return Ok((secret.clone(), cred_used));
                }
                _ => continue,
            }
        }
    }
    //TODO: create fitting error
    Err(Fido2LuksError::WrongSecret)
}

pub fn may_require_pin() -> Fido2LuksResult<bool> {
    let info = get_info(&lib_cfg())?;
    let needs_pin = info
        .options
        .iter()
        .any(|(name, val)| &name[..] == "clientPin" && *val);
    Ok(needs_pin)
}
