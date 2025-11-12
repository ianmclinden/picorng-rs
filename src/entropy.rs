/*
    This file is part of picorng-rs.

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

#![allow(clippy::cast_precision_loss)]

use std::{collections::HashMap, f64::consts::PI};

#[derive(Default, Clone)]
pub struct Entropy {
    data: Vec<u8>,
}

impl Entropy {
    pub fn from(data: &[u8]) -> Self {
        Self { data: data.into() }
    }

    pub fn add_from_slice(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn generate_report(&self) -> Report {
        let distribution = self
            .data
            .iter()
            .copied()
            .fold(HashMap::new(), |mut map, val| {
                map.entry(val).and_modify(|frq| *frq += 1u32).or_insert(1);
                map
            });
        let bytes = self.data.len();
        let shannon = self.shannon_entropy(&distribution);
        let chi_squared = self.chi_squared(&distribution);
        let mean = self.data.iter().map(|i| f64::from(*i)).sum::<f64>() / self.data.len() as f64;
        let monte_carlo = self.monte_carlo();
        let monte_carlo_error = (PI - monte_carlo).abs() / PI;

        Report {
            bytes,
            shannon,
            chi_squared,
            mean,
            monte_carlo,
            monte_carlo_error,
            // TODO
            serial_correlation: 0.0,
        }
    }

    fn shannon_entropy(&self, distribution: &HashMap<u8, u32>) -> f64 {
        let len = self.data.len() as f64;
        distribution
            .values()
            .filter(|&&v| v != 0)
            .fold(0.0f64, |acc, v| {
                let p: f64 = f64::from(*v) / len;
                acc - p * p.log(2.0)
            })
    }

    fn monte_carlo(&self) -> f64 {
        let pairs: Vec<(u8, u8)> = self
            .data
            .chunks(2)
            .filter(|v| v.len() == 2)
            .map(|dat| (*dat.first().unwrap_or(&0), *dat.last().unwrap_or(&0)))
            .collect();

        let count = pairs.iter().fold(0u32, |acc, (x, y)| {
            let x: f64 = f64::from(*x) / 255.0;
            let y: f64 = f64::from(*y) / 255.0;
            let p: f64 = x * x + y * y;
            if p <= 1.0 { acc + 1 } else { acc }
        });
        f64::from(count) * 4.0 / (pairs.len() as f64)
    }

    fn chi_squared(&self, distribution: &HashMap<u8, u32>) -> f64 {
        let expected = self.data.len() as f64 / f64::from(u8::MAX);

        distribution
            .values()
            .map(|o| (f64::from(*o) - expected).powf(2.0) / expected)
            .sum()
    }
}

#[derive(Copy, Clone)]
pub struct Report {
    bytes: usize,
    shannon: f64,
    chi_squared: f64,
    mean: f64,
    monte_carlo: f64,
    monte_carlo_error: f64,
    serial_correlation: f64,
}

impl Report {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn shannon_entropy(&self) -> f64 {
        self.shannon
    }

    pub fn chi_squared(&self) -> f64 {
        self.chi_squared
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn monte_carlo(&self) -> f64 {
        self.monte_carlo
    }

    pub fn monte_carlo_error(&self) -> f64 {
        self.monte_carlo_error
    }

    pub fn serial_correlation(&self) -> f64 {
        self.serial_correlation
    }
}
