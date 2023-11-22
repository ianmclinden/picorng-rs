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

use clap::{ArgAction, Parser, Subcommand};
use log::LevelFilter;
use picorng::PICoRNGClient;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Specify device number
    #[arg(short = 'n', long, value_name = "NUM", default_value_t = 0)]
    device_number: usize,

    /// Specify configuration directory
    #[arg(short, long, value_name = "DIR", default_value = "~/.picorng/")]
    config_dir: String,

    /// Specify usb timeout (ms)
    #[arg(short, long, value_name = "MS", default_value_t = 500)]
    timeout: u64,

    /// Increase output verbosity
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all devices
    List,

    /// Show device info
    Info,

    /// Pair device
    Pair,

    /// Verify device
    Verify,

    /// Read random data into stdout
    Cat {
        /// Number of blocks to output
        #[arg(index = 1)]
        blocks: Option<usize>,
    },

    /// Check random data quality
    Quality {
        /// Number of blocks to assess
        #[arg(index = 1, default_value_t = 1024)]
        blocks: usize,
    },

    /// Feed random data to the system
    Rngd {
        /// Skip device verification
        #[arg(short, long = "no-verify", default_value_t = false)]
        no_verify: bool,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let console_log_level = match args.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    simplelog::SimpleLogger::init(console_log_level, simplelog::Config::default())?;

    if !nix::unistd::geteuid().is_root() {
        log::warn!("You may encounter problems without root permissions");
    }

    let cli = PICoRNGClient::new(args.config_dir, args.device_number, args.timeout)?;

    let result = match args.command {
        Commands::List => cli.list_devices(),
        Commands::Info => cli.print_info(),
        Commands::Pair => cli.pair(),
        Commands::Verify => cli.verify(),
        Commands::Cat { blocks } => cli.get_random_blocks(blocks),
        Commands::Quality { blocks } => cli.check_quality(blocks),
        Commands::Rngd { no_verify } => cli.feed_rngd(no_verify),
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("{e}").into()),
    }
}
