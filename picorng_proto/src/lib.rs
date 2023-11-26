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
use core::array::TryFromSliceError;
#[cfg(feature = "std")]
use std::array::TryFromSliceError;
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

use tiny_ecdh::sect163k1;

pub const RAND_DATA_BLOCK_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid payload length for {0:?}")]
    InvalidPayloadLength(PacketName),

    #[error("invalid field length")]
    InvalidFieldLength(#[from] TryFromSliceError),

    #[error("invalid payload: {0}")]
    InvalidKey(#[from] tiny_ecdh::Error),

    #[error("invalid packet type {0}")]
    InvalidType(u8),

    #[error("empty buffer")]
    Empty,
}

#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PICoInfoResponseStatus {
    value: u32,
}

impl PICoInfoResponseStatus {
    #[must_use]
    pub fn size() -> usize {
        4
    }

    #[must_use]
    /// Returns true if the least significant bit of the
    /// value is 1
    pub fn is_configured(&self) -> bool {
        (self.value & 1u32) != 0
    }

    /// returns a [`PICoInfoResponseStatus`] with the configured bit set
    #[must_use]
    pub fn configured() -> Self {
        Self { value: 1u32 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketName {
    None,
    InfoRequest,
    InfoResponse,
    RandomDataRequest,
    RandomDataResponse,
    IdentityConfigureRequest,
    IdentityConfigureResponse,
    IdentityVerifyRequest,
    IdentityVerifyResponse,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum PICoPacket {
    #[default]
    None,

    InfoRequest,
    InfoResponse {
        version: u32,
        status: PICoInfoResponseStatus,
    },

    RandomDataRequest,
    RandomDataResponse {
        random_data: [u8; RAND_DATA_BLOCK_SIZE],
    },

    IdentityConfigureRequest {
        ecc_priv_key: sect163k1::PrivKey,
    },
    IdentityConfigureResponse {
        status: u16,
        ecc_priv_key: sect163k1::PrivKey,
    },
    IdentityVerifyRequest {
        ecc_pub_key: sect163k1::PubKey,
    },
    IdentityVerifyResponse {
        ecc_shared_secret: sect163k1::SharedSecret,
    },
}

impl PICoPacket {
    fn type_id(&self) -> u8 {
        match self {
            PICoPacket::None => 0,
            PICoPacket::InfoRequest => 1,
            PICoPacket::InfoResponse {
                version: _,
                status: _,
            } => 2,
            PICoPacket::RandomDataRequest => 3,
            PICoPacket::RandomDataResponse { random_data: _ } => 4,
            PICoPacket::IdentityConfigureRequest { ecc_priv_key: _ } => 5,
            PICoPacket::IdentityConfigureResponse {
                status: _,
                ecc_priv_key: _,
            } => 6,
            PICoPacket::IdentityVerifyRequest { ecc_pub_key: _ } => 7,
            PICoPacket::IdentityVerifyResponse {
                ecc_shared_secret: _,
            } => 8,
        }
    }

    #[must_use]
    pub fn buffer_size(&self) -> usize {
        // [type, reserved, DATA_SIZE]
        2 + match self {
            PICoPacket::None | PICoPacket::InfoRequest | PICoPacket::RandomDataRequest => 0,
            PICoPacket::InfoResponse {
                version: _,
                status: _,
            } => 4 + PICoInfoResponseStatus::size(),
            PICoPacket::RandomDataResponse { random_data: _ } => RAND_DATA_BLOCK_SIZE,
            PICoPacket::IdentityConfigureRequest { ecc_priv_key: _ } => sect163k1::PrivKey::size(),
            PICoPacket::IdentityConfigureResponse {
                status: _,
                ecc_priv_key: _,
            } => 2 + sect163k1::PrivKey::size(),
            PICoPacket::IdentityVerifyRequest { ecc_pub_key: _ } => sect163k1::PubKey::size(),
            PICoPacket::IdentityVerifyResponse {
                ecc_shared_secret: _,
            } => sect163k1::SharedSecret::size(),
        }
    }

    #[must_use]
    pub const fn max_buffer_size() -> usize {
        // [type, reserved, ECC_PUB_KEY_SIZE]
        1 + 1 + sect163k1::PubKey::size()
    }

    /// Returns the memory representation of this packet in little-endian byte order
    #[must_use]
    pub fn as_bytes(&self) -> [u8; Self::max_buffer_size()] {
        let mut buf = [0u8; Self::max_buffer_size()];
        buf[0] = self.type_id();
        buf[1] = 0; // 1-byte reserved
        match self {
            PICoPacket::None | PICoPacket::InfoRequest | PICoPacket::RandomDataRequest => (), // No additional packing
            PICoPacket::InfoResponse { version, status } => {
                let ver = version.to_le_bytes();
                buf[2..][..ver.len()].copy_from_slice(&ver);
                let stat = status.value.to_le_bytes();
                buf[2 + ver.len()..][..stat.len()].copy_from_slice(&stat);
            }
            PICoPacket::RandomDataResponse { random_data } => {
                buf[2..][..random_data.len()].copy_from_slice(random_data.as_slice());
            }
            PICoPacket::IdentityConfigureRequest { ecc_priv_key } => {
                let k = ecc_priv_key.as_bytes();
                buf[2..][..k.len()].copy_from_slice(k);
            }
            PICoPacket::IdentityConfigureResponse {
                status,
                ecc_priv_key,
            } => {
                let status = status.to_le_bytes();
                buf[2..][..status.len()].copy_from_slice(&status);
                let k = ecc_priv_key.as_bytes();
                buf[2 + status.len()..][..k.len()].copy_from_slice(k);
            }
            PICoPacket::IdentityVerifyRequest { ecc_pub_key } => {
                let k = ecc_pub_key.as_bytes();
                buf[2..][..k.len()].copy_from_slice(k);
            }
            PICoPacket::IdentityVerifyResponse { ecc_shared_secret } => {
                let s = ecc_shared_secret.as_bytes();
                buf[2..][..s.len()].copy_from_slice(s);
            }
        }
        buf
    }

    /// Attempt to parse a [`PICoPacket`] from bytes in little-endian byte order
    ///
    /// # Errors
    /// Returns an [`enum@Error`] if parsing errors occur
    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        let payload = &buffer[2..];
        match buffer.first() {
            Some(0) => Ok(PICoPacket::None),

            Some(1) => Ok(PICoPacket::InfoRequest),

            // C prefers the first variant (flags) here. TODO: both
            Some(2) => match (payload.get(0..=3), payload.get(4..=7)) {
                (Some(version), Some(status)) => Ok(PICoPacket::InfoResponse {
                    version: u32::from_le_bytes(version.try_into()?),
                    status: PICoInfoResponseStatus {
                        value: u32::from_le_bytes(status.try_into()?),
                    },
                }),
                _ => Err(Error::InvalidPayloadLength(PacketName::InfoResponse)),
            },

            Some(3) => Ok(Self::RandomDataRequest),

            Some(4) => match payload.get(0..RAND_DATA_BLOCK_SIZE) {
                Some(random_data) => Ok(PICoPacket::RandomDataResponse {
                    random_data: random_data.try_into()?,
                }),
                None => Err(Error::InvalidPayloadLength(PacketName::RandomDataResponse)),
            },

            Some(5) => match payload.get(0..sect163k1::PrivKey::size()) {
                Some(ecc_priv_key) => Ok(Self::IdentityConfigureRequest {
                    ecc_priv_key: ecc_priv_key.try_into()?,
                }),
                None => Err(Error::InvalidPayloadLength(
                    PacketName::IdentityConfigureRequest,
                )),
            },

            Some(6) => match (
                payload.get(0..2),
                payload.get(2..sect163k1::PrivKey::size() + 2),
            ) {
                (Some(status), Some(ecc_priv_key)) => Ok(Self::IdentityConfigureResponse {
                    status: u16::from_le_bytes(status.try_into()?),
                    ecc_priv_key: ecc_priv_key.try_into()?,
                }),
                (_, _) => Err(Error::InvalidPayloadLength(
                    PacketName::IdentityConfigureResponse,
                )),
            },

            Some(7) => match payload.get(0..sect163k1::PubKey::size()) {
                Some(ecc_pub_key) => Ok(PICoPacket::IdentityVerifyRequest {
                    ecc_pub_key: ecc_pub_key.try_into()?,
                }),
                None => Err(Error::InvalidPayloadLength(
                    PacketName::IdentityVerifyRequest,
                )),
            },

            Some(8) => match payload.get(0..sect163k1::SharedSecret::size()) {
                Some(ecc_shared_secret) => Ok(PICoPacket::IdentityVerifyResponse {
                    ecc_shared_secret: ecc_shared_secret.try_into()?,
                }),
                None => Err(Error::InvalidPayloadLength(
                    PacketName::IdentityVerifyResponse,
                )),
            },

            Some(t) => Err(Error::InvalidType(*t)),
            None => Err(Error::Empty),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::{PICoInfoResponseStatus, PICoPacket};
    use tiny_ecdh::sect163k1;

    #[test]
    fn test_none() {
        let packet = PICoPacket::None;
        assert_eq!(packet.buffer_size(), 2);
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2);
        let buf = PICoPacket::as_bytes(&packet);
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

        let status = PICoInfoResponseStatus { value: 0xFFFF_FFFE };
        assert!(!status.is_configured());
    }

    #[test]
    fn test_info_response() {
        let packet = PICoPacket::InfoResponse {
            version: 0xDEAD_BEEF,
            status: PICoInfoResponseStatus { value: 0 },
        };
        assert_eq!(packet.buffer_size(), 2 + 4 + 4);
        let buf = PICoPacket::as_bytes(&packet);
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
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2);
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2 + 32);
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2 + sect163k1::PrivKey::size());
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2 + 2 + sect163k1::PrivKey::size());
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2 + sect163k1::PubKey::size());
        let buf = PICoPacket::as_bytes(&packet);
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
        assert_eq!(packet.buffer_size(), 2 + sect163k1::SharedSecret::size());
        let buf = PICoPacket::as_bytes(&packet);
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
