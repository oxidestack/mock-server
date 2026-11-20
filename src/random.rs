//! Random numbers: `java.util.Random` for reproducible (seeded) draws, and the OS generator otherwise.

use rand_core::{OsRng, RngCore};

/// `java.util.Random`'s linear congruential generator.
pub struct JavaRandom(i64);

impl JavaRandom {
    pub fn new(seed: i64) -> JavaRandom {
        JavaRandom((seed ^ 0x5DEECE66D) & ((1 << 48) - 1))
    }

    fn next(&mut self, bits: u32) -> i64 {
        self.0 = (self.0.wrapping_mul(0x5DEECE66D).wrapping_add(0xB)) & ((1 << 48) - 1);
        self.0 >> (48 - bits)
    }

    pub fn next_double(&mut self) -> f64 {
        (((self.next(26)) << 27) + self.next(27)) as f64 * (1.0 / (1i64 << 53) as f64)
    }
}

/// A uniform draw from [0, 1) (`ThreadLocalRandom.nextDouble`).
pub fn uniform() -> f64 {
    (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}
