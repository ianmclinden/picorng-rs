/*
    This file is part of tiny_ecdh.

    Copyright (C) 2020 kokke
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

//! This is a small and portable implementation of the [Elliptic-Curve Diffie-Hellman key agreement algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
//!
//! # Example
//! ```
//! // Use the K-163/sect163k1 elliptic curve
//! use tiny_ecdh::sect163k1;
//!
//! // Generate ECC keypairs
//! let key1 = sect163k1::Key::generate();
//! let key2 = sect163k1::Key::generate();
//! assert_ne!(key1, key2);
//!
//! // Extract keys
//! let (pubkey1, privkey1) = (key1.public_key(), key1.private_key());
//! let (pubkey2, privkey2) = (key2.public_key(), key2.private_key());
//!
//! // Generate 1->2 shared secret
//! let shared_1_2 = privkey1.diffie_hellman(&pubkey2);
//! // Generate 2->1 shared secret
//! let shared_2_1 = privkey2.diffie_hellman(&pubkey1);
//!
//! assert_eq!(shared_1_2, shared_2_1);
//! ```

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

mod bindings {
    // scope the base library to this crate
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not parse key from slice: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error("could not parse key from vec")]
    TryFromVecError,
}

// TODO : conditional compilation for other ec sizes
pub mod sect163k1 {
    use crate::{
        bindings::{ECC_PRV_KEY_SIZE, ECC_PUB_KEY_SIZE},
        Error,
    };

    use rand::RngCore;

    /// An ECC Private Key
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct PrivKey {
        data: [u8; ECC_PRV_KEY_SIZE as usize],
    }

    impl PrivKey {
        /// Generate a new [PrivKey]
        pub fn generate() -> Self {
            let mut data = [0u8; ECC_PRV_KEY_SIZE as usize];
            rand::thread_rng().fill_bytes(&mut data);

            // Generate mutates the privkey, so make sure it conforms
            let mut _pubkey = PubKey::new();
            unsafe {
                crate::bindings::ecdh_generate_keys(_pubkey.data.as_mut_ptr(), data.as_mut_ptr());
            }

            Self { data }
        }

        /// Get the expected size of the [PrivKey] in bytes
        pub fn size() -> usize {
            ECC_PRV_KEY_SIZE as usize
        }

        /// Get the actual length of the [PrivKey] in bytes
        pub fn len(&self) -> usize {
            self.data.len()
        }

        pub fn to_hex_string(&self) -> String {
            hex::encode(self.data)
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.data
        }

        /// Generate a new [PubKey] derived from a [PrivKey]
        pub fn generate_pubkey(&self) -> PubKey {
            let mut pubkey = PubKey::new();

            let mut privkey_copy = self.data.clone();
            unsafe {
                crate::bindings::ecdh_generate_keys(
                    pubkey.data.as_mut_ptr(),
                    privkey_copy.as_mut_ptr(),
                );
            }
            // base lib should not mutate this if it's initialized correctly
            assert_eq!(privkey_copy, self.data);
            pubkey
        }

        /// Calcualte a Diffie-Hellman shared secret from this [PrivKey] and a given [PubKey]
        pub fn diffie_hellman(&self, public_key: &PubKey) -> SharedSecret {
            let mut ecc_shared_secret = SharedSecret::new();
            unsafe {
                crate::bindings::ecdh_shared_secret(
                    self.data.as_ptr(),
                    public_key.data.as_ptr(),
                    ecc_shared_secret.data.as_mut_ptr(),
                );
            }
            ecc_shared_secret
        }
    }

    impl TryFrom<&[u8]> for PrivKey {
        type Error = Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            Ok(Self {
                data: value.try_into()?,
            })
        }
    }

    impl TryFrom<Vec<u8>> for PrivKey {
        type Error = Error;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(Self {
                data: value.try_into().map_err(|_| Error::TryFromVecError)?,
            })
        }
    }

    /// An ECC Public Key
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct PubKey {
        data: [u8; ECC_PUB_KEY_SIZE as usize],
    }

    impl PubKey {
        pub(crate) fn new() -> Self {
            Self {
                data: [0u8; ECC_PUB_KEY_SIZE as usize],
            }
        }

        /// Get the expected size of the [PubKey] in bytes
        pub fn size() -> usize {
            ECC_PUB_KEY_SIZE as usize
        }

        /// Get the actual length of the [PubKey] in bytes
        pub fn len(&self) -> usize {
            self.data.len()
        }

        pub fn to_hex_string(&self) -> String {
            hex::encode(self.data)
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.data
        }
    }

    impl TryFrom<&[u8]> for PubKey {
        type Error = Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            Ok(Self {
                data: value.try_into()?,
            })
        }
    }

    impl TryFrom<Vec<u8>> for PubKey {
        type Error = Error;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(Self {
                data: value.try_into().map_err(|_| Error::TryFromVecError)?,
            })
        }
    }

    /// An ECDH Shared Secret
    pub type SharedSecret = PubKey;

    /// An ECC KeyPair
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Key {
        pub(crate) privkey: PrivKey,
        pub(crate) pubkey: PubKey,
    }

    impl Key {
        /// Generate a new ECC [Key], with a randomly generated [PrivKey] and a derived [PubKey]
        pub fn generate() -> Self {
            let privkey = PrivKey::generate();
            let pubkey = privkey.generate_pubkey();

            Self { privkey, pubkey }
        }

        /// Get this key's [PrivKey]
        pub fn private_key(&self) -> PrivKey {
            self.privkey
        }

        /// Get this key's [PubKey]
        pub fn public_key(&self) -> PubKey {
            self.pubkey
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Key, PrivKey, PubKey};
        use crate::bindings::{ECC_PRV_KEY_SIZE, ECC_PUB_KEY_SIZE};

        #[test]
        fn test_generate() {
            // Calls assert during generation of privkey
            let key = Key::generate();
            assert_ne!(key.private_key().data, [0u8; ECC_PRV_KEY_SIZE as usize]);
            assert_eq!(key.private_key().len(), ECC_PRV_KEY_SIZE as usize);
            assert_eq!(key.private_key().len(), PrivKey::size());
            assert_ne!(key.public_key().data, [0u8; ECC_PUB_KEY_SIZE as usize]);
            assert_eq!(key.public_key().len(), ECC_PUB_KEY_SIZE as usize);
            assert_eq!(key.public_key().len(), PubKey::size());
        }

        #[test]
        fn test_parse_privkey() {
            let mut data = vec![
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23,
            ];
            let prikey = PrivKey::try_from(data.clone());
            assert!(prikey.is_ok());
            assert_eq!(prikey.unwrap().as_bytes(), &data);

            data.truncate(22);
            let prikey = PrivKey::try_from(data.clone());
            assert!(prikey.is_err());
        }

        #[test]
        fn test_parse_pubkey() {
            let mut data = vec![
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47,
            ];
            let pubkey = PubKey::try_from(data.clone());
            assert!(pubkey.is_ok());
            assert_eq!(pubkey.unwrap().as_bytes(), &data);

            data.truncate(43);
            let prikey = PrivKey::try_from(data.clone());
            assert!(prikey.is_err());
        }

        #[test]
        fn test_dh() {
            let key1 = Key::generate();
            let key2 = Key::generate();
            assert_ne!(key1, key2);

            let privkey1 = key1.private_key();
            let pubkey1 = key1.public_key();

            let privkey2 = key2.private_key();
            let pubkey2 = key2.public_key();

            let ss12 = privkey1.diffie_hellman(&pubkey2);
            let ss21 = privkey2.diffie_hellman(&pubkey1);
            assert_eq!(ss12, ss21);
        }
    }
}
