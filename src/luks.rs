use crate::error::*;

use failure::{Fail, ResultExt};
use libcryptsetup_rs::{
    size_t, CryptActivateFlags, CryptDevice, CryptInit, CryptLuks2Token, CryptTokenInfo,
    EncryptionFormat, KeyslotInfo, LibcryptErr,
};
use std::path::Path;
use std::result::Result;

fn load_device_handle<P: AsRef<Path>>(path: P) -> Fido2LuksResult<CryptDevice> {
    let mut device = CryptInit::init(path.as_ref())?;
    //TODO: determine luks version some way other way than just trying
    let mut load = |format| {
        device
            .context_handle()
            .load::<()>(Some(format), None)
            .map(|_| ())
    };
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
    Ok(())
    /* match device.format_handle().get_type()? {
        EncryptionFormat::Luks2 => Ok(()),
        _ => Err(Fido2LuksError::LuksError {
            cause: LuksError::Luks2Required,
        }),
    }*/
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
            type_: "fido2luks\0".into(),
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

pub fn open_container_token<P: AsRef<Path>>(
    path: P,
    name: &str,
    mut secret: Box<Fn(Vec<String>) -> Fido2LuksResult<Box<[u8]>>>,
) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    check_luks2(&mut device)?;
    /*
    // https://gitlab.com/cryptsetup/cryptsetup/-/blob/0b38128e21175b24f8dd1ad06257754af3d4437f/lib/libcryptsetup.h#L2096
    let mut token_data: Option<Fido2LuksToken> = None;
    fn open_token(
        mut device: CryptDevice,
        id: i32,
        data: Option<&mut Box<Fn(Vec<String>) -> Fido2LuksResult<Box<[u8]>>>>,
    ) -> Result<Box<[u8]>, LibcryptErr> {
        dbg!("handler");
        let token: Fido2LuksToken = serde_json::from_value( device.token_handle().json_get(id as u32)?).map_err(|e| LibcryptErr::Other(e.to_string()))?;
        if let Some(secret_gen) = data {
            secret_gen(token.credential).map_err(|e| LibcryptErr::Other(dbg!(e).to_string()))
        } else {
            Err(LibcryptErr::Other("No secret_gen".into()))
        }
    }
    //c_token_handler_open!(ext_open_token, Fido2LuksToken, open_token);
    extern "C" fn ext_open_token(
        cd: *mut libcryptsetup_rs_sys::crypt_device,
        token_id: std::os::raw::c_int,
        buffer: *mut *mut std::os::raw::c_char,
        buffer_len: *mut size_t,
        usrptr: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int {
        let device = CryptDevice::from_ptr(cd);
        let generic_ptr = usrptr as *mut Box<Fn(Vec<String>) -> Fido2LuksResult<Box<[u8]>>>;
        let generic_ref = unsafe { generic_ptr.as_mut() };
        match open_token(device, token_id, generic_ref) {
            Ok(secret) => unsafe {
                *buffer = Box::into_raw(secret) as *mut std::os::raw::c_char;
                0
            },
            Err(_) => -1,
        }
    }
    fn free_token(boxed: Box<[u8]>) {}
    c_token_handler_free!(ext_free_token, free_token);

    fn validate_token(
        device: &mut CryptDevice,
        json: serde_json::value::Value,
    ) -> Result<(), LibcryptErr> {
        Ok(())
    }
    c_token_handler_validate!(ext_validate_token, validate_token);


    fn dump_token(device: &mut CryptDevice, json: serde_json::value::Value) {

    }
    c_token_handler_dump!(ext_dump_token, dump_token);*/
    /*CryptLuks2Token::register("fido2luks\0", Some(ext_open_token), None, None, None)?;
    dbg!("here");
    //let mut salt = salt.to_vec().into_boxed_slice();
    match device.token_handle().activate_by_token(Some(&name),None, Some(&mut secret), CryptActivateFlags::empty()) {
        Err(e)  => match e {
            LibcryptErr::IOError(_) => Err(Fido2LuksError::LuksError { cause: LuksError::NoToken}),
            _ => Err(e)?
        },
        ok => Ok(ok?)
    }*/
    let mut creds = Vec::new();
    for i in 0..256 {
        let (status, type_) = device.token_handle().status(i)?;
        if status == CryptTokenInfo::Inactive {
            break;
        }
        if let Some(s) = type_ {
            if &s != "fido2luks" {
                continue;
            }
        } else {
            continue;
        }
        let json = device.token_handle().json_get(i)?;
        let info: Fido2LuksToken =
            serde_json::from_value(json.clone()).map_err(|_| Fido2LuksError::LuksError {
                cause: LuksError::InvalidToken(json.to_string()),
            })?;
        creds.extend_from_slice(&info.credential[..]);
    }
    device
        .activate_handle()
        .activate_by_passphrase(
            Some(name),
            None,
            secret(dbg!(creds))?.as_ref(),
            CryptActivateFlags::empty(),
        )
        .map(|_slot| ())
        .map_err(|_e| Fido2LuksError::WrongSecret)
}

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
        .keyslot_handle()
        .add_by_passphrase(None, old_secret, secret)?;
    if let Some(id) = credential_id {
        /*  if let e @ Err(_) = check_luks2(&mut device) {
            //rollback
            device.keyslot_handle(Some(slot)).destroy()?;
            return e.map(|_| 0u32);
        }*/
        device.token_handle().json_set(
            None,
            Some(&serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap()),
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
        if let Some(s) = type_ {
            if &s != "fido2luks" {
                continue;
            }
        } else {
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
    Ok(None)
}

fn remove_token(device: &mut CryptDevice, slot: u32) -> Fido2LuksResult<()> {
    if let Some((token, _)) = find_token(device, slot)? {
        // remove API??
        device.token_handle().json_set(Some(token), None)?;
    }
    Ok(())
}

pub fn remove_keyslots<P: AsRef<Path>>(path: P, exclude: &[u32]) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    let mut destroyed = 0;
    let mut tokens = Vec::new();
    for slot in 0..256 {
        match device.keyslot_handle().status(slot)? {
            KeyslotInfo::Inactive => continue,
            KeyslotInfo::Active | KeyslotInfo::ActiveLast if !exclude.contains(&slot) => {
                if let Ok(_) = check_luks2(&mut device) {
                    if let Some((token, _)) = dbg!(find_token(&mut device, slot))? {
                        tokens.push(token);
                    }
                }
                device.keyslot_handle().destroy(slot)?;
                destroyed += 1;
            }
            KeyslotInfo::ActiveLast => break,
            _ => (),
        }
        if device.keyslot_handle().status(slot)? == KeyslotInfo::ActiveLast {
            break;
        }
    }
    for token in tokens.iter() {
        device.token_handle().json_set(Some(*token), None)?;
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
        .keyslot_handle()
        .change_by_passphrase(None, None, old_secret, secret)? as u32;
    if let Some(id) = credential_id {
        if check_luks2(&mut device).is_ok() {
            let token = find_token(&mut device, slot)?.map(|(t, _)| t);
            device.token_handle().json_set(
                token,
                Some(&serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap()),
            )?;
        }
    }
    Ok(slot)
}
