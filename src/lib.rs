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

use std::{
    error::Error,
    fs,
    io::Write,
    os::unix::prelude::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use expanduser::expanduser;
use protocol::PICoPacket;
use rusb::{
    constants::{LIBUSB_ENDPOINT_IN, LIBUSB_ENDPOINT_OUT},
    Device, GlobalContext,
};
use tiny_ecdh::sect163k1::{self, PubKey, SharedSecret};

use crate::{entropy::Entropy, protocol::RAND_DATA_BLOCK_SIZE};

mod entropy;
mod protocol;

#[derive(Debug)]
pub struct PICoRNGClient {
    devices: Vec<Device<GlobalContext>>,
    cfg_dir: PathBuf,
    dev_number: usize,
    usb_timeout: Duration,
}

impl PICoRNGClient {
    const VENDOR_ID: u16 = 0x04D8;
    const PRODUCT_ID: u16 = 0xE8B5;
    const DESCRIPTOR_INDEX: u8 = 1;
    const INTERFACE_NUM: u8 = 0;

    pub fn new(cfg_dir: String, dev_number: usize, timeout: u64) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            devices: Self::find_devices()?,
            cfg_dir: expanduser(cfg_dir)?,
            dev_number,
            usb_timeout: Duration::from_millis(timeout),
        })
    }

    fn create_cfg_dir(&self) -> Result<&PathBuf, Box<dyn Error>> {
        fs::create_dir_all(&self.cfg_dir)?;
        fs::set_permissions(&self.cfg_dir, fs::Permissions::from_mode(0o700))?;
        log::info!("Config directory: {}", self.cfg_dir.to_string_lossy());
        Ok(&self.cfg_dir)
    }

    fn find_devices() -> Result<Vec<Device<GlobalContext>>, Box<dyn Error>> {
        Ok(rusb::devices()?
            .iter()
            .filter(|d| match d.device_descriptor() {
                Ok(desc) => {
                    desc.vendor_id() == Self::VENDOR_ID && desc.product_id() == Self::PRODUCT_ID
                }
                Err(_) => false,
            })
            .collect())
    }

    fn send_and_receive(
        &self,
        packet: PICoPacket,
        timeout: Duration,
    ) -> Result<PICoPacket, Box<dyn Error>> {
        let device = self
            .devices
            .get(self.dev_number)
            .ok_or(format!("No such device number: {}", self.dev_number))?;

        let mut handle = device.open()?;
        handle.claim_interface(Self::INTERFACE_NUM)?;

        log::trace!("Sending {:?}", packet);
        handle.write_bulk(1 | LIBUSB_ENDPOINT_OUT, &packet.as_bytes(), timeout)?;

        log::trace!("Waiting for response...");
        let mut buf: Vec<u8> = vec![0; PICoPacket::buffer_size()];
        handle.read_bulk(1 | LIBUSB_ENDPOINT_IN, &mut buf, timeout)?;
        let rx_packet = PICoPacket::from_bytes(&buf)?;
        log::trace!("Received {:?}", rx_packet);
        Ok(rx_packet)
    }

    /// List all PICoRNG devices with debug information
    pub fn list_devices(&self) -> Result<(), Box<dyn Error>> {
        for (i, device) in self.devices.iter().enumerate() {
            let path = match device.port_numbers() {
                Ok(ports) => {
                    ", path ".to_string()
                        + &ports
                            .into_iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<String>>()
                            .join(".")
                }
                Err(_) => "".to_string(),
            };

            let descriptor = device
                .open()?
                .read_string_descriptor_ascii(Self::DESCRIPTOR_INDEX)?;

            println!(
                "#{i} (bus {:03}, device {:03}{path}) {descriptor}",
                device.bus_number(),
                device.address(),
            );
        }
        Ok(())
    }

    /// Print info about the currently selected device
    pub fn print_info(&self) -> Result<(), Box<dyn Error>> {
        match self.send_and_receive(PICoPacket::InfoRequest, self.usb_timeout)? {
            PICoPacket::InfoResponse { version, status } => {
                println!("Version: {:#010x}", version);
                println!();
                let configured = match status {
                    protocol::PICoInfoResponseStatus::Flags { configured } => configured,
                    protocol::PICoInfoResponseStatus::Value(_) => false,
                };
                Ok(println!("Configured: {configured}"))
            }
            _ => Err("Got wrong packet type as response".into()),
        }
    }

    /// Generate and install an ECDH keypair onto the selected device
    pub fn pair(&self) -> Result<(), Box<dyn Error>> {
        log::trace!("Generating sect163k1 keypair");
        let key = sect163k1::Key::generate();
        let ecc_priv_key = key.private_key();
        let ecc_pub_key = key.public_key();

        match self.send_and_receive(
            PICoPacket::IdentityConfigureRequest { ecc_priv_key },
            self.usb_timeout,
        )? {
            PICoPacket::IdentityConfigureResponse {
                status,
                ecc_priv_key: _,
            } if status != 0 => Err("Device already configured".into()),
            PICoPacket::IdentityConfigureResponse {
                status: _,
                ecc_priv_key: new_priv_key,
            } if ecc_priv_key != new_priv_key => {
                println!(
                    "> [{}] {}",
                    ecc_priv_key.len(),
                    ecc_priv_key.to_hex_string()
                );
                println!(
                    "< [{}] {}",
                    new_priv_key.len(),
                    new_priv_key.to_hex_string()
                );
                Err("Data verification failed".into())
            }
            PICoPacket::IdentityConfigureResponse {
                status: _,
                ecc_priv_key: _,
            } => {
                println!(
                    "% [{}] {}",
                    ecc_priv_key.len(),
                    ecc_priv_key.to_hex_string()
                );

                let mut cfg_file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(self.create_cfg_dir()?.join(ecc_pub_key.to_hex_string()))?;
                cfg_file.set_permissions(fs::Permissions::from_mode(0o644))?;

                log::trace!("Writing public key to '{}'", ecc_pub_key.to_hex_string());
                cfg_file.write_all(ecc_pub_key.as_bytes())?;
                cfg_file.flush()?;
                Ok(println!("Success"))
            }
            _ => Err("Got wrong packet type as response".into()),
        }
    }

    /// Verify that the configured device generates a valid shared secret
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        log::trace!("Generating sect163k1 challenge keypair");
        let key = sect163k1::Key::generate();
        let rand_priv_key = key.private_key();
        let rand_pub_key = key.public_key();

        // 2. Load all device pubkeys
        // 3. Calculate expected shared secret for each device pubkey
        let mut ecc_shared_secrets: Vec<SharedSecret> = Vec::new();
        let cfg_dir = fs::read_dir(self.create_cfg_dir()?)?;
        for file in cfg_dir {
            let key_path = file?.path();
            let ecc_pub_key: PubKey = fs::read(&key_path)?.try_into().map_err(|_| {
                format!("Key '{}' has invalid length", key_path.to_string_lossy()).to_string()
            })?;
            log::trace!("Loaded public key '{}'", key_path.to_string_lossy());
            let ecc_shared_secret = rand_priv_key.diffie_hellman(&ecc_pub_key);
            log::trace!(
                "Generated shared secret: {}",
                ecc_shared_secret.to_hex_string()
            );
            ecc_shared_secrets.push(ecc_shared_secret);
        }

        if ecc_shared_secrets.is_empty() {
            return Err("Config directory did not contain any valid pubkeys".into());
        }

        println!("The verification process will take at least a minute.");
        println!("Do not terminate the program, or unplug the PICoRNG during this time\n");

        // 4. Send random pubkey to device
        // 5. Receive device calculated shared secret
        match self.send_and_receive(
            PICoPacket::IdentityVerifyRequest {
                ecc_pub_key: rand_pub_key,
            },
            Duration::from_secs(240),
        )? {
            PICoPacket::IdentityVerifyResponse { ecc_shared_secret } => {
                log::info!(
                    "Received shared secret: {}",
                    ecc_shared_secret.to_hex_string()
                );
                // 6. Check if there are matches
                match ecc_shared_secrets.contains(&ecc_shared_secret) {
                    true => Ok(println!("Success")),
                    false => Err("Failed".into()),
                }
            }
            _ => Err("Got wrong packet type as response".into()),
        }
    }

    /// Get blocks of random data from the device, and output to [std::io::stdout()].
    ///
    /// # Aguments
    /// * `blocks` - If [Some(size)], then get `size` blocks, otherwise fetch until interrupted
    pub fn get_random_blocks(&self, blocks: Option<usize>) -> Result<(), Box<dyn Error>> {
        let mut sent: usize = 0;
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        while running.load(Ordering::SeqCst) {
            match self.send_and_receive(PICoPacket::RandomDataRequest, self.usb_timeout)? {
                PICoPacket::RandomDataResponse { random_data } => {
                    std::io::stdout().write_all(&random_data)?;
                }
                _ => return Err("Got wrong packet type as response".into()),
            };

            if let Some(blocks) = blocks {
                sent += 1;
                if sent >= blocks {
                    running.store(false, Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }

    /// Sample and analyze the quality of random blocks from the configured device
    ///
    /// # Aguments
    /// * `blocks` - The number of blocks to be analyzed
    pub fn check_quality(&self, blocks: usize) -> Result<(), Box<dyn Error>> {
        println!(
            "Gathering {} blocks ({} bytes) of random data ...\n",
            blocks,
            blocks * RAND_DATA_BLOCK_SIZE
        );

        let mut received: usize = 0;
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        let mut entropy = Entropy::default();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        while running.load(Ordering::SeqCst) {
            match self.send_and_receive(PICoPacket::RandomDataRequest, self.usb_timeout)? {
                PICoPacket::RandomDataResponse { random_data } => {
                    entropy.add_from_slice(&random_data);
                }
                _ => return Err("Got wrong packet type as response".into()),
            };

            received += 1;
            if received >= blocks {
                running.store(false, Ordering::SeqCst);
            }
        }

        let report = entropy.generate_report();
        println!("Entropy = {:.8} bits per byte\n", report.shannon_entropy());
        println!(
            "Optimum compression would reduce the size of this {} byte stream by {:.2} percent.\n",
            report.bytes(),
            100.0 * (8.0 - report.shannon_entropy()) / 8.0,
        );
        println!(
            "Chi squared distribution for {} samples is {:.8}\n",
            report.bytes(),
            report.chi_squared()
        );
        println!(
            "Arithmetic mean value of data is {:.6} (127.5 = random).",
            report.mean()
        );
        println!(
            "Monte Carlo value for Pi is {:.8} (error {:.2} percent).",
            report.monte_carlo(),
            report.monte_carlo_error() * 100.0
        );
        println!(
            "Serial correlation coefficient is {} (totally uncorrelated = 0.0).",
            report.serial_correlation()
        );
        Ok(())
    }

    /// Seed `/dev/urandom` with data from the configured device
    ///
    /// # Aguments
    /// * `skip_verify` - If `true` then device verification will be skipped
    pub fn feed_rngd(&self, skip_verify: bool) -> Result<(), Box<dyn Error>> {
        if !skip_verify {
            log::info!("Verifying device");
            self.verify()?;
        }

        let mut urandom = fs::OpenOptions::new().append(true).open("/dev/urandom")?;

        const BLOCKS: usize = 1024;
        log::debug!(
            "Gathering data in {} blocks ({} bytes) at a time",
            BLOCKS,
            BLOCKS * RAND_DATA_BLOCK_SIZE
        );
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        while running.load(Ordering::SeqCst) {
            let mut rnd_buf: Vec<u8> = Vec::new();

            let mut received: usize = 0;
            while running.load(Ordering::SeqCst) {
                match self.send_and_receive(PICoPacket::RandomDataRequest, self.usb_timeout)? {
                    PICoPacket::RandomDataResponse { random_data } => {
                        rnd_buf.extend_from_slice(&random_data);
                    }
                    _ => return Err("Got wrong packet type as response".into()),
                }

                received += 1;
                if received >= BLOCKS {
                    break;
                }
            }

            log::debug!("Checking quality of {} bytes", rnd_buf.len());

            let entropy = Entropy::from(&rnd_buf);
            let report = entropy.generate_report();

            let mce = report.monte_carlo_error();
            if mce > 0.01 {
                log::warn!("Monte carlo pi estimate error is too high ({mce}), skipping");
                continue;
            }

            let shan = report.shannon_entropy();
            if shan < 0.799 {
                log::warn!("Shannon entropy is too low ({shan}), skipping");
                continue;
            }

            log::info!("Writing {} bytes to rand pool", rnd_buf.len());
            urandom.write_all(&rnd_buf)?;
        }
        Ok(())
    }
}
