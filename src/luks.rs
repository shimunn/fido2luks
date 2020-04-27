use crate::error::*;

use failure::{Fail, ResultExt};
use libcryptsetup_rs::{
    CryptActivateFlags, CryptDevice, CryptInit, CryptTokenInfo, EncryptionFormat, KeyslotInfo,
};
use std::path::Path;

fn load_device_handle<P: AsRef<Path>>(path: P) -> Fido2LuksResult<CryptDevice> {
    let mut device = CryptInit::init(path.as_ref())?;
    //TODO: determine luks version some way other way than just trying
    let mut load = |format| device.context_handle().load::<()>(format, None).map(|_| ());
    vec![EncryptionFormat::Luks2, EncryptionFormat::Luks1]
        .into_iter()
        .fold(None, |res, format| match res {
            Some(Ok(())) => res,
            Some(e) => Some(e.or_else(|_| load(format))),
            None => Some(load(format)),
        })
        .unwrap()?;
    Ok(device)
}

fn check_luks2(device: &mut CryptDevice) -> Fido2LuksResult<()> {
    match device.format_handle().get_type()? {
        EncryptionFormat::Luks2 => Ok(()),
        other => Err(Fido2LuksError::LuksError {
            cause: LuksError::Luks2Required,
        }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Fido2LuksToken {
    #[serde(rename = "type")]
    type_: String,
    credential: Vec<String>,
    keyslots: Vec<String>,
}

impl Fido2LuksToken {
    fn new(credential_id: impl AsRef<[u8]>, slot: u32) -> Self {
        Self {
            type_: "fido2luks".into(),
            credential: vec![hex::encode(credential_id)],
            keyslots: vec![slot.to_string()],
        }
    }
}

pub fn open_container<P: AsRef<Path>>(path: P, name: &str, secret: &[u8]) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, secret, CryptActivateFlags::empty())
        .map(|_slot| ())
        .map_err(|_e| Fido2LuksError::WrongSecret)
}

/*pub fn open_container_token<P: AsRef<Path>>(path: P, name: &str, secret: &[u8]) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    check_luks2(&mut device)?;
    unimplemented!()
}*/

pub fn add_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
    credential_id: Option<&[u8]>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    let slot = device
        .keyslot_handle(None)
        .add_by_passphrase(old_secret, secret)?;
    if let Some(id) = credential_id {
      /*  if let e @ Err(_) = check_luks2(&mut device) {
            //rollback
            device.keyslot_handle(Some(slot)).destroy()?;
            return e.map(|_| 0u32);
        }*/
        device.token_handle().json_set(
            None,
            &serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap(),
        )?;
    }

    Ok(slot)
}

fn find_token(
    device: &mut CryptDevice,
    slot: u32,
) -> Fido2LuksResult<Option<(u32, Fido2LuksToken)>> {
    for i in 0..256 {
        let (status, type_) = device.token_handle().status(i)?;
        if status == CryptTokenInfo::Inactive {
            break;
        }
        if type_ != "fido2luks" {
            continue;
        }
        let json = device.token_handle().json_get(i)?;
        let info: Fido2LuksToken =
            serde_json::from_value(json.clone()).map_err(|_| Fido2LuksError::LuksError {
                cause: LuksError::InvalidToken(json.to_string()),
            })?;
        if info.keyslots.contains(&slot.to_string()) {
            return Ok(Some((i, info)));
        }
    }
    Ok((None))
}

fn remove_token(device: &mut CryptDevice, slot: u32) -> Fido2LuksResult<()> {
    if let Some((token, _)) = find_token(device, slot)? {
        // remove API??
        // device.token_handle()
    }
    Ok(())
}

pub fn remove_keyslots<P: AsRef<Path>>(path: P, exclude: &[u32]) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    let mut handle;
    let mut destroyed = 0;
    //TODO: detect how many keyslots there are instead of trying within a given range
    for slot in 0..1024 {
        handle = device.keyslot_handle(Some(slot));
        let last = KeyslotInfo::ActiveLast == handle.status()?;
        match handle.status()? {
            KeyslotInfo::Inactive => continue,
            KeyslotInfo::Active if !exclude.contains(&slot) => {
                handle.destroy()?;
                remove_token(&mut device, slot)?;
                destroyed += 1;
            }
            _ => (),
        }
        if last {
            break;
        }
    }
    Ok(destroyed)
}

pub fn replace_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
    credential_id: Option<&[u8]>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    // Set iteration time not sure wether this applies to luks2 as well
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    let slot = device
        .keyslot_handle(None)
        .change_by_passphrase(None, None, old_secret, secret)? as u32;
    if let Some(id) = credential_id {
        if check_luks2(&mut device).is_ok() {
            let token = find_token(&mut device, slot)?.map(|(t, _)| t);
            device.token_handle().json_set(
                token,
                &serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap(),
            )?;
        }
    }
    Ok(slot)
}
