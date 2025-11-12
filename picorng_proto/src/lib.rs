/*
    This file is part of picorng-proto.

    Copyright (C) 2021 ReimuNotMoe <reimu@sudomaker.com>
    Copyright (C) 2023 Ian McLinden

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use binrw::{BinRead, BinWrite, binrw, io::Cursor};
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

use tiny_ecdh::sect163k1;

pub const RAND_DATA_BLOCK_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid payload length for packet type {0}")]
    InvalidPayloadLength(u8),

    #[error("unknown packet type {0}")]
    UnknownType(u8),

    #[error("empty buffer")]
    Empty,

    #[error("an unknown error")]
    Unknown,
}

impl Error {
    fn from_binrw(error: binrw::Error, variant: u8) -> Self {
        match error {
            // Base type is an enum, all errors shoudl be EnumErrors
            binrw::Error::EnumErrors {
                pos: _,
                variant_errors,
            } => match variant_errors.get(variant as usize) {
                Some((_, e)) => {
                    if e.is_eof() {
                        Self::InvalidPayloadLength(variant)
                    } else {
                        Self::Unknown
                    }
                }
                None => Self::UnknownType(variant),
            },
            _ => Self::Unknown,
        }
    }
}

#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
#[binrw(little)]
pub struct PICoInfoResponseStatus {
    value: u32,
}

impl PICoInfoResponseStatus {
    #[must_use]
    /// Returns true if the least significant byte of the value is nonzero
    pub fn is_configured(&self) -> bool {
        (self.value & 0xFF) != 0
    }

    /// returns a [`PICoInfoResponseStatus`] with the configured bit set
    #[must_use]
    pub fn configured() -> Self {
        Self { value: 1u32 }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
#[binrw]
#[brw(little)]
pub enum PICoPacket {
    #[default]
    #[brw(magic(b"\x00\x00"))] // [magic, reserved]
    None,

    #[brw(magic(b"\x01\x00"))]
    InfoRequest,

    #[brw(magic(b"\x02\x00"))]
    InfoResponse {
        version: u32,
        status: PICoInfoResponseStatus,
    },

    #[brw(magic(b"\x03\x00"))]
    RandomDataRequest,
    #[brw(magic(b"\x04\x00"))]
    RandomDataResponse {
        random_data: [u8; RAND_DATA_BLOCK_SIZE],
    },

    #[brw(magic(b"\x05\x00"))]
    IdentityConfigureRequest {
        #[bw(map = sect163k1::PrivKey::as_bytes)]
        #[br(try_map = |x: [u8; sect163k1::PrivKey::size()]| sect163k1::PrivKey::try_from(&x[..]))]
        ecc_priv_key: sect163k1::PrivKey,
    },
    #[brw(magic(b"\x06\x00"))]
    IdentityConfigureResponse {
        status: u16,
        #[bw(map = sect163k1::PrivKey::as_bytes)]
        #[br(try_map = |x: [u8; sect163k1::PrivKey::size()]| sect163k1::PrivKey::try_from(&x[..]))]
        ecc_priv_key: sect163k1::PrivKey,
    },
    #[brw(magic(b"\x07\x00"))]
    IdentityVerifyRequest {
        #[bw(map = sect163k1::PubKey::as_bytes)]
        #[br(try_map = |x: [u8; sect163k1::PubKey::size()]| sect163k1::PubKey::try_from(&x[..]))]
        ecc_pub_key: sect163k1::PubKey,
    },
    #[brw(magic(b"\x08\x00"))]
    IdentityVerifyResponse {
        #[bw(map = sect163k1::SharedSecret::as_bytes)]
        #[br(try_map = |x: [u8; sect163k1::SharedSecret::size()]| sect163k1::SharedSecret::try_from(&x[..]))]
        ecc_shared_secret: sect163k1::SharedSecret,
    },
}

impl PICoPacket {
    #[must_use]
    pub const fn max_buffer_size() -> usize {
        // [type, reserved, ECC_PUB_KEY_SIZE]
        1 + 1 + sect163k1::PubKey::size()
    }

    /// Serialize the packet as a byte array
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::max_buffer_size()] {
        let mut buf = [0u8; Self::max_buffer_size()];
        let mut cursor = Cursor::new(&mut buf[..]);
        let _ = self.write(&mut cursor); // Nothing should be fallible here
        buf
    }

    /// Serialize the packet as a byte vector
    #[cfg(feature = "std")]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        let _ = self.write(&mut cursor); // Nothing should be fallible here
        cursor.into_inner()
    }

    /// Parse a [`PICoPacket`] from bytes
    ///
    /// # Errors
    /// Returns an [`enum@Error`] if parsing errors occur
    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        if buffer.is_empty() {
            return Err(Error::Empty);
        }
        let mut cursor = Cursor::new(buffer);
        let packet = Self::read(&mut cursor).map_err(|e| Error::from_binrw(e, buffer[0]))?;
        Ok(packet)
    }
}

#[cfg(test)]
pub mod test {
    use super::{PICoInfoResponseStatus, PICoPacket};
    use tiny_ecdh::sect163k1;

    #[test]
    fn test_none() {
        let packet = PICoPacket::None;
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, PICoPacket::None);
    }

    #[test]
    fn test_info_request() {
        let packet = PICoPacket::InfoRequest;
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, PICoPacket::InfoRequest);
    }

    #[test]
    fn test_info_response_status() {
        let status = PICoInfoResponseStatus { value: 0 };
        assert!(!status.is_configured());

        let status = PICoInfoResponseStatus::configured();
        assert!(status.is_configured());

        let status = PICoInfoResponseStatus { value: 0xFFFF_FF00 };
        assert!(!status.is_configured());
    }

    #[test]
    fn test_info_response() {
        let packet = PICoPacket::InfoResponse {
            version: 0xDEAD_BEEF,
            status: PICoInfoResponseStatus { value: 0 },
        };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                2, 0, 239, 190, 173, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);

        let packet = PICoPacket::InfoResponse {
            version: 0xDEAD_BEEF,
            status: PICoInfoResponseStatus::configured(),
        };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                2, 0, 239, 190, 173, 222, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_random_data_request() {
        let packet = PICoPacket::RandomDataRequest;
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, PICoPacket::RandomDataRequest);
    }

    #[test]
    fn test_random_data_response() {
        let random_data: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let packet = PICoPacket::RandomDataResponse { random_data };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_configure_request() {
        let ecc_priv_key = sect163k1::PrivKey::try_from(
            [
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ]
            .as_slice(),
        )
        .unwrap();
        let packet = PICoPacket::IdentityConfigureRequest { ecc_priv_key };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_configure_response() {
        let ecc_priv_key = sect163k1::PrivKey::try_from(
            [
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ]
            .as_slice(),
        )
        .unwrap();
        let packet = PICoPacket::IdentityConfigureResponse {
            status: 0xBEEF,
            ecc_priv_key,
        };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                6, 0, 239, 190, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_verify_request() {
        let ecc_pub_key = sect163k1::PubKey::try_from(
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48,
            ]
            .as_slice(),
        )
        .unwrap();
        let packet = PICoPacket::IdentityVerifyRequest { ecc_pub_key };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                43, 44, 45, 46, 47, 48,
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_verify_response() {
        let ecc_shared_secret = sect163k1::SharedSecret::try_from(
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48,
            ]
            .as_slice(),
        )
        .unwrap();
        let packet = PICoPacket::IdentityVerifyResponse { ecc_shared_secret };
        let buf = PICoPacket::to_bytes(&packet);
        assert_eq!(
            buf.as_slice(),
            &[
                8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                43, 44, 45, 46, 47, 48,
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }
}
