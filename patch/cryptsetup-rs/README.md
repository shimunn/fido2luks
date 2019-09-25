[![Build Status](https://travis-ci.org/solidninja/cryptsetup-rs.svg?branch=master)](https://travis-ci.org/solidninja/cryptsetup-rs)
[![crates.io Status](https://img.shields.io/crates/v/cryptsetup-rs.svg)](https://crates.io/crates/cryptsetup-rs)
[![docs.rs build](https://docs.rs/cryptsetup-rs/badge.svg)](https://docs.rs/crate/cryptsetup-rs/)

# cryptsetup-rs - Rust bindings to `libcryptsetup` on Linux

A safe binding to `libcryptsetup` that allows working with encrypted disks on Linux.

Features:
  * High-level API for open/format/other operations


Documentation for the bindings can be found on [docs.rs](https://docs.rs/crate/cryptsetup-rs/).

The example [`luks_dump.rs`](examples/luks_dump.rs) shows how a command like `cryptsetup luksDump` can
be implemented.

## TODO

* Secure string for passing keys
* High-level API for non-LUKS1 disks (truecrypt, verity)
* LUKS2 and cryptsetup2 support

## Contributing

`cryptsetup-rs` is the work of its contributors and is a free software project licensed under the
LGPLv3 or later.

If you would like to contribute, please follow the [C4](https://rfc.zeromq.org/spec:42/C4/) process.
