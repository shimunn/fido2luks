#![deny(warnings)]
#[warn(unused_must_use)]
extern crate cryptsetup_rs;
extern crate env_logger;

use cryptsetup_rs::*;
use std::env;

fn dump_slot(crypt_device: &Luks1CryptDevice, slot: Keyslot) -> Result<()> {
    let status = match crypt_device.keyslot_status(slot) {
        crypt_keyslot_info::CRYPT_SLOT_INVALID => "INVALID",
        crypt_keyslot_info::CRYPT_SLOT_INACTIVE => "DISABLED",
        crypt_keyslot_info::CRYPT_SLOT_ACTIVE | crypt_keyslot_info::CRYPT_SLOT_ACTIVE_LAST => "ENABLED",
    };

    println!("Key Slot {}: {}", slot, status);
    match status {
        "ENABLED" => /* TODO  add keyslot information */ (),
        _ => (),
    }
    Ok(())
}

fn dump(device_path: &str) -> Result<()> {
    let dev = open(device_path)?.luks1()?;

    println!("LUKS header information for {}", dev.device_name());
    println!();
    println!("{:<16}{}", "Version:", "1");
    println!("{:<16}{}", "Cipher name:", dev.cipher());
    println!("{:<16}{}", "Cipher mode:", dev.cipher_mode());
    println!("{:<16}{}", "Hash spec:", dev.hash_spec());
    println!("{:<16}{}", "Payload offset:", dev.payload_offset());
    println!("{:<16}{}", "MK bits:", dev.mk_bits());

    print!("{:<16}", "MK digest:");
    for b in dev.mk_digest().iter() {
        print!("{:x} ", b);
    }
    println!();

    let salt = dev.mk_salt();
    print!("{:<16}", "MK salt:");
    for b in salt[0..16].iter() {
        print!("{:x} ", b);
    }
    println!();
    print!("{:<16}", "");
    for b in salt[16..32].iter() {
        print!("{:x} ", b);
    }
    println!();

    println!("{:<16}{}", "MK iterations:", dev.mk_iterations());
    println!("{:<16}{}", "UUID:", dev.uuid());

    println!();

    for slot in 0..8 {
        dump_slot(&dev, slot)?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 1 {
        println!("Usage: luks_dump <device path>");
        ::std::process::exit(1);
    }
    let device_path = args[0].as_str();

    if let Err(e) = dump(device_path) {
        println!("Error: {:?}", e);
        ::std::process::exit(2);
    }
}
