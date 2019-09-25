// The following code has been ported from libcryptsetup

extern crate byteorder;
extern crate uuid;

use std::convert;
use std::io;
use std::io::Read;
use std::mem;
use std::str;

pub trait LuksHeader {
    fn version(&self) -> u16;
    fn cipher_name(&self) -> Result<&str, Error>;
    fn cipher_mode(&self) -> Result<&str, Error>;
    fn hash_spec(&self) -> Result<&str, Error>;
    fn payload_offset(&self) -> u32;
    fn key_bytes(&self) -> u32;
    fn mk_digest(&self) -> &[u8];
    fn mk_digest_salt(&self) -> &[u8];
    fn mk_digest_iterations(&self) -> u32;
    fn uuid(&self) -> Result<uuid::Uuid, Error>;
}

#[derive(Debug)]
pub enum Error {
    InvalidMagic,
    InvalidStringEncoding(str::Utf8Error),
    InvalidVersion,
    InvalidUuid(uuid::ParseError),
    ReadError(io::Error),
    ReadIncorrectHeaderSize,
    HeaderProcessingError,
}

pub struct BlockDevice;

impl BlockDevice {
    pub fn read_luks_header<R: Read>(reader: R) -> Result<raw::luks_phdr, Error> {
        let luks_phdr_size = mem::size_of::<raw::luks_phdr>();
        let mut buf = Vec::<u8>::with_capacity(luks_phdr_size);
        let read_size = try!(reader.take(luks_phdr_size as u64).read_to_end(&mut buf));
        if read_size != luks_phdr_size {
            Err(Error::ReadIncorrectHeaderSize)
        } else {
            raw::luks_phdr::from_buf(&buf)
        }
    }
}

impl convert::From<str::Utf8Error> for Error {
    fn from(error: str::Utf8Error) -> Error {
        Error::InvalidStringEncoding(error)
    }
}

impl convert::From<uuid::ParseError> for Error {
    fn from(error: uuid::ParseError) -> Error {
        Error::InvalidUuid(error)
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::ReadError(error)
    }
}
/* FIXME
impl convert::From<byteorder::Error> for Error {
    fn from(error: byteorder::Error) -> Error {
        match error {
            byteorder::Error::UnexpectedEOF => Error::HeaderProcessingError,
            byteorder::Error::Io(io_error) => Error::ReadError(io_error),
        }
    }
}
*/

pub mod raw {
    #![allow(non_snake_case)]

    use std::convert::From;
    use std::io::{Cursor, Read};
    use std::mem;
    use std::str;

    use byteorder::{BigEndian, ReadBytesExt};
    use uuid;

    const LUKS_VERSION_SUPPORTED: u16 = 1;

    const LUKS_MAGIC_L: usize = 6;
    const LUKS_CIPHERNAME_L: usize = 32;
    const LUKS_CIPHERMODE_L: usize = 32;
    const LUKS_HASHSPEC_L: usize = 32;
    const LUKS_DIGESTSIZE: usize = 20;
    const LUKS_SALTSIZE: usize = 32;
    const UUID_STRING_L: usize = 40;

    const LUKS_MAGIC: &'static [u8; LUKS_MAGIC_L] = b"LUKS\xba\xbe";

    #[repr(C, packed)]
    pub struct luks_phdr {
        pub magic: [u8; LUKS_MAGIC_L],
        pub version: u16,
        pub cipherName: [u8; LUKS_CIPHERNAME_L],
        pub cipherMode: [u8; LUKS_CIPHERMODE_L],
        pub hashSpec: [u8; LUKS_HASHSPEC_L],
        pub payloadOffset: u32,
        pub keyBytes: u32,
        pub mkDigest: [u8; LUKS_DIGESTSIZE],
        pub mkDigestSalt: [u8; LUKS_SALTSIZE],
        pub mkDigestIterations: u32,
        pub uuid: [u8; UUID_STRING_L],
    }

    impl luks_phdr {
        pub fn from_buf(buf: &[u8]) -> Result<luks_phdr, super::Error> {
            // FIXME - this is not particularly pretty

            if buf.len() != mem::size_of::<luks_phdr>() {
                return Err(super::Error::ReadIncorrectHeaderSize);
            }
            let mut cursor = Cursor::new(buf);
            let mut magic_buf = [0u8; LUKS_MAGIC_L];
            let magic_len = try!(cursor.read(&mut magic_buf));

            if magic_len != LUKS_MAGIC_L || magic_buf != &LUKS_MAGIC[..] {
                return Err(super::Error::InvalidMagic);
            }

            let version = try!(cursor.read_u16::<BigEndian>());
            if version != LUKS_VERSION_SUPPORTED {
                return Err(super::Error::InvalidVersion);
            }

            let mut cipher_name_buf = [0u8; LUKS_CIPHERNAME_L];
            let cipher_name_len = try!(cursor.read(&mut cipher_name_buf));
            if cipher_name_len != LUKS_CIPHERNAME_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut cipher_mode_buf = [0u8; LUKS_CIPHERMODE_L];
            let cipher_mode_len = try!(cursor.read(&mut cipher_mode_buf));
            if cipher_mode_len != LUKS_CIPHERMODE_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut hash_spec_buf = [0u8; LUKS_HASHSPEC_L];
            let hash_spec_len = try!(cursor.read(&mut hash_spec_buf));
            if hash_spec_len != LUKS_HASHSPEC_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let payload_offset = try!(cursor.read_u32::<BigEndian>());
            let key_bytes = try!(cursor.read_u32::<BigEndian>());

            let mut mk_digest_buf = [0u8; LUKS_DIGESTSIZE];
            let mk_digest_len = try!(cursor.read(&mut mk_digest_buf));
            if mk_digest_len != LUKS_DIGESTSIZE {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut mk_digest_salt_buf = [0u8; LUKS_SALTSIZE];
            let mk_digest_salt_len = try!(cursor.read(&mut mk_digest_salt_buf));
            if mk_digest_salt_len != LUKS_SALTSIZE {
                return Err(super::Error::HeaderProcessingError);
            }

            let mk_digest_iterations = try!(cursor.read_u32::<BigEndian>());

            let mut uuid_buf = [0u8; UUID_STRING_L];
            let uuid_len = try!(cursor.read(&mut uuid_buf));
            if uuid_len != UUID_STRING_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let res = luks_phdr {
                magic: magic_buf,
                version: version,
                cipherName: cipher_name_buf,
                cipherMode: cipher_mode_buf,
                hashSpec: hash_spec_buf,
                payloadOffset: payload_offset,
                keyBytes: key_bytes,
                mkDigest: mk_digest_buf,
                mkDigestSalt: mk_digest_salt_buf,
                mkDigestIterations: mk_digest_iterations,
                uuid: uuid_buf,
            };

            Ok(res)
        }
    }

    fn u8_buf_to_str(buf: &[u8]) -> Result<&str, super::Error> {
        if let Some(pos) = buf.iter().position(|&c| c == 0) {
            str::from_utf8(&buf[0..pos]).map_err(From::from)
        } else {
            str::from_utf8(buf).map_err(From::from)
        }
    }

    impl super::LuksHeader for luks_phdr {
        fn version(&self) -> u16 {
            self.version
        }

        fn cipher_name(&self) -> Result<&str, super::Error> {
            u8_buf_to_str(&self.cipherName)
        }

        fn cipher_mode(&self) -> Result<&str, super::Error> {
            u8_buf_to_str(&self.cipherMode)
        }

        fn hash_spec(&self) -> Result<&str, super::Error> {
            u8_buf_to_str(&self.hashSpec)
        }

        fn payload_offset(&self) -> u32 {
            self.payloadOffset
        }

        fn key_bytes(&self) -> u32 {
            self.keyBytes
        }

        fn mk_digest(&self) -> &[u8] {
            &self.mkDigest
        }

        fn mk_digest_salt(&self) -> &[u8] {
            &self.mkDigestSalt
        }

        fn mk_digest_iterations(&self) -> u32 {
            self.mkDigestIterations
        }

        fn uuid(&self) -> Result<uuid::Uuid, super::Error> {
            let uuid_str = try!(u8_buf_to_str(&self.uuid));
            uuid::Uuid::parse_str(uuid_str).map_err(From::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use uuid;

    #[test]
    fn test_luks_header_from_byte_buffer() {
        let header = b"LUKS\xba\xbe\x00\x01aes\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ecb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00sha256\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00 \xcf^\xb4\xc00q\xbe\xd5\xe6\x90\xc8G\xb3\x00\xbe\xba\xd052qp\x92\x0c\x9c\xa9\x07R\\y_D\x08b\xf1\xe6\x8f\x0c\xa95\xad\xdb\x15+\xa5\xd7\xa7\xbf^\x96B\x90z\x00\x00\x03\xe8a1b49d2d-8a7e-4b04-ab2a-89f3408fd198\x00\x00\x00\x00";
        let mut cursor: Cursor<&[u8]> = Cursor::new(header);
        let luks_header = BlockDevice::read_luks_header(&mut cursor).unwrap();

        assert_eq!(luks_header.version(), 1);
        assert_eq!(luks_header.cipher_name().unwrap(), "aes");
        assert_eq!(luks_header.cipher_mode().unwrap(), "ecb");
        assert_eq!(luks_header.hash_spec().unwrap(), "sha256");
        assert_eq!(luks_header.payload_offset(), 4096);
        assert_eq!(luks_header.key_bytes(), 32);
        assert_eq!(
            luks_header.mk_digest(),
            &[
                207, 94, 180, 192, 48, 113, 190, 213, 230, 144, 200, 71, 179, 0, 190, 186, 208, 53,
                50, 113
            ]
        );
        assert_eq!(
            luks_header.mk_digest_salt(),
            &[
                112, 146, 12, 156, 169, 7, 82, 92, 121, 95, 68, 8, 98, 241, 230, 143, 12, 169, 53,
                173, 219, 21, 43, 165, 215, 167, 191, 94, 150, 66, 144, 122
            ]
        );
        assert_eq!(luks_header.mk_digest_iterations(), 1000);
        assert_eq!(
            luks_header.uuid().unwrap(),
            uuid::Uuid::parse_str("a1b49d2d-8a7e-4b04-ab2a-89f3408fd198").unwrap()
        )
    }
}
