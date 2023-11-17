/*
    This file is part of picorng-rs.

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

use std::error::Error;

use tiny_ecdh::sect163k1;

pub const RAND_DATA_BLOCK_SIZE: usize = 32;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub(crate) enum PICoInfoResponseStatus {
    Flags { configured: bool },
    Value(u32),
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) enum PICoPacket {
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

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.type_id(), 0]; // 1-byte reserved
        match self {
            PICoPacket::None | PICoPacket::InfoRequest | PICoPacket::RandomDataRequest => (), // No additional packing
            PICoPacket::InfoResponse { version, status } => {
                buf.extend_from_slice(&version.to_le_bytes());
                match status {
                    PICoInfoResponseStatus::Flags { configured } => buf.push(*configured as u8),
                    PICoInfoResponseStatus::Value(value) => {
                        buf.extend_from_slice(&value.to_le_bytes())
                    }
                }
            }
            PICoPacket::RandomDataResponse { random_data } => {
                buf.extend_from_slice(random_data);
            }
            PICoPacket::IdentityConfigureRequest { ecc_priv_key } => {
                buf.extend_from_slice(ecc_priv_key.as_bytes());
            }
            PICoPacket::IdentityConfigureResponse {
                status,
                ecc_priv_key,
            } => {
                buf.extend_from_slice(&status.to_le_bytes());
                buf.extend_from_slice(ecc_priv_key.as_bytes())
            }
            PICoPacket::IdentityVerifyRequest { ecc_pub_key } => {
                buf.extend_from_slice(ecc_pub_key.as_bytes());
            }
            PICoPacket::IdentityVerifyResponse { ecc_shared_secret } => {
                buf.extend_from_slice(ecc_shared_secret.as_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(buffer: &[u8]) -> Result<Self, Box<dyn Error>> {
        let payload = &buffer[2..];
        match buffer.first() {
            Some(0) => Ok(PICoPacket::None),

            Some(1) => Ok(PICoPacket::InfoRequest),

            // C prefers the first variant (flags) here. TODO: both
            Some(2) => match (payload.get(0..=3), payload.get(4)) {
                (Some(version), Some(flags)) => {
                    let version = u32::from_le_bytes(version.try_into()?);
                    Ok(PICoPacket::InfoResponse {
                        version,
                        status: PICoInfoResponseStatus::Flags {
                            configured: flags != &0,
                        },
                    })
                }
                _ => Err("Invalid payload length for InfoReponse".into()),
            },

            Some(3) => Ok(Self::RandomDataRequest),

            Some(4) => match payload.get(0..RAND_DATA_BLOCK_SIZE) {
                Some(random_data) => Ok(PICoPacket::RandomDataResponse {
                    random_data: random_data.try_into()?,
                }),
                None => Err("Invalid payload length for RandomDataResponse".into()),
            },

            Some(5) => match payload.get(0..sect163k1::PrivKey::size()) {
                Some(ecc_priv_key) => Ok(Self::IdentityConfigureRequest {
                    ecc_priv_key: ecc_priv_key.try_into()?,
                }),
                None => Err("Invalid payload length for IdentityConfigureRequest".into()),
            },

            Some(6) => match (
                payload.get(0..2),
                payload.get(2..sect163k1::PrivKey::size() + 2),
            ) {
                (Some(status), Some(ecc_priv_key)) => Ok(Self::IdentityConfigureResponse {
                    status: u16::from_le_bytes(status.try_into()?),
                    ecc_priv_key: ecc_priv_key.try_into()?,
                }),
                (_, _) => Err("Invalid payload length for IdentityConfigureResponse".into()),
            },

            Some(7) => match payload.get(0..sect163k1::PubKey::size()) {
                Some(ecc_pub_key) => Ok(PICoPacket::IdentityVerifyRequest {
                    ecc_pub_key: ecc_pub_key.try_into()?,
                }),
                None => Err("Invalid payload length for IdentityVerifyRequest".into()),
            },

            Some(8) => match payload.get(0..sect163k1::SharedSecret::size()) {
                Some(ecc_shared_secret) => Ok(PICoPacket::IdentityVerifyResponse {
                    ecc_shared_secret: ecc_shared_secret.try_into()?,
                }),
                None => Err("Invalid payload length for IdentityVerifyRequest".into()),
            },

            Some(t) => Err(format!("Invalid packet type {t}").into()),
            None => Err("Empty buffer".into()),
        }
    }

    pub fn buffer_size() -> usize {
        // [type, reserved, ECC_PUB_KEY_SIZE]
        1 + 1 + sect163k1::PubKey::size()
    }
}

#[cfg(test)]
pub mod test {
    use super::{PICoInfoResponseStatus, PICoPacket};
    use tiny_ecdh::sect163k1;

    #[test]
    fn test_none() {
        let packet = PICoPacket::None;
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(buf, &[0, 0]);

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, PICoPacket::None);
    }

    #[test]
    fn test_info_request() {
        let packet = PICoPacket::InfoRequest;
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(&buf, &[1, 0]);

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, PICoPacket::InfoRequest);
    }

    #[test]
    fn test_info_response() {
        let packet = PICoPacket::InfoResponse {
            version: 0xDEADBEEF,
            status: PICoInfoResponseStatus::Flags { configured: false },
        };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(buf, &[2, 0, 239, 190, 173, 222, 0]);

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);

        let packet = PICoPacket::InfoResponse {
            version: 0xDEADBEEF,
            status: PICoInfoResponseStatus::Flags { configured: true },
        };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(buf, &[2, 0, 239, 190, 173, 222, 1]);

        // TODO: Not supported right now
        // let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        // assert_eq!(r_packet, packet);

        // let packet = PICoPacket::InfoResponse {
        //     version: 0xDEADBEEF,
        //     status: PICoInfoResponseStatus::Value(0xDEADFEED),
        // };
        // let buf = PICoPacket::as_bytes(&packet);
        // assert_eq!(buf, &[2, 0, 239, 190, 173, 222, 237, 254, 173, 222]);

        // let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        // assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_random_data_request() {
        let packet = PICoPacket::RandomDataRequest;
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(&buf, &[3, 0]);

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
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(
            &buf,
            &[
                4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_configure_request() {
        let ecc_priv_key = sect163k1::PrivKey::try_from(vec![
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        ])
        .unwrap();
        let packet = PICoPacket::IdentityConfigureRequest { ecc_priv_key };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(
            &buf,
            &[
                5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_configure_response() {
        let ecc_priv_key = sect163k1::PrivKey::try_from(vec![
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        ])
        .unwrap();
        let packet = PICoPacket::IdentityConfigureResponse {
            status: 0xBEEF,
            ecc_priv_key,
        };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(
            &buf,
            &[
                6, 0, 239, 190, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                20, 21, 22, 23, 24
            ]
        );

        let r_packet = PICoPacket::from_bytes(&buf).unwrap();
        assert_eq!(r_packet, packet);
    }

    #[test]
    fn test_identity_verify_request() {
        let ecc_pub_key = sect163k1::PubKey::try_from(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48,
        ])
        .unwrap();
        let packet = PICoPacket::IdentityVerifyRequest { ecc_pub_key };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(
            &buf,
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
        let ecc_shared_secret = sect163k1::SharedSecret::try_from(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48,
        ])
        .unwrap();
        let packet = PICoPacket::IdentityVerifyResponse { ecc_shared_secret };
        let buf = PICoPacket::as_bytes(&packet);
        assert_eq!(
            &buf,
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
