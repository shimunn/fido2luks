#![deny(warnings)]

extern crate cryptsetup_rs;
extern crate env_logger;
extern crate log;
extern crate tempdir;
extern crate uuid;

#[macro_use]
extern crate expectest;

use std::process::Command;

use expectest::prelude::*;
use tempdir::TempDir;
use uuid::Uuid;

use cryptsetup_rs::*;

struct TestContext {
    dir: TempDir,
    name: String,
}

impl TestContext {
    fn new(name: String) -> TestContext {
        env_logger::init();
        cryptsetup_rs::enable_debug(true);
        let dir = tempdir::TempDir::new(&name).unwrap();
        TestContext { name, dir }
    }

    fn new_crypt_device(&self) -> api::CryptDeviceFormatBuilder {
        let crypt_file = self.dir.path().join(format!("{}.image", self.name));
        let dd_status = Command::new("dd")
            .arg("if=/dev/zero")
            .arg(format!("of={}", crypt_file.display()))
            .arg("bs=1M")
            .arg("count=10")
            .status()
            .unwrap();
        if !dd_status.success() {
            panic!("Failed to create disk image at {}", crypt_file.display());
        }

        cryptsetup_rs::format(crypt_file).unwrap()
    }
}

#[test]
fn test_create_new_luks1_cryptdevice_no_errors() {
    let ctx = TestContext::new("new_luks1_cryptdevice".to_string());
    let uuid = Uuid::new_v4();

    let device_format = ctx.new_crypt_device()
        .rng_type(crypt_rng_type::CRYPT_RNG_URANDOM)
        .iteration_time(42);

    let mut dev = device_format
        .luks1("aes", "xts-plain", "sha256", 256, Some(&uuid))
        .expect("LUKS format should succeed");

    dev.dump();

    expect!(dev.uuid()).to(be_equal_to(uuid));
    expect!(dev.device_type()).to(be_equal_to(crypt_device_type::LUKS1));
    expect!(dev.cipher()).to(be_equal_to("aes"));
    expect!(dev.cipher_mode()).to(be_equal_to("xts-plain"));
    expect!(dev.volume_key_size()).to(be_equal_to(32));

    expect!(dev.add_keyslot(b"hello world", None, Some(3))).to(be_ok().value(3));
}
