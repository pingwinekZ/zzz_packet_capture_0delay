//! MT19937-64, matching `std::mt19937_64`.
//!
//! `crypto::xorpad::generate` constructs `std::mt19937_64 mt(seed)`, which is the
//! standard `init_genrand64` seeding plus the 64-bit tempered output. The
//! sequence must match the C++ build exactly or every decrypt fails, so the
//! parameters and the seeding path are spelled out rather than pulled from a PRNG
//! crate.

const NN: usize = 312;
const MM: usize = 156;
const MATRIX_A: u64 = 0xB502_6F5A_A966_19E9;
const UM: u64 = 0xFFFF_FFFF_8000_0000; // most significant 33 bits
const LM: u64 = 0x0000_0000_7FFF_FFFF; // least significant 31 bits

pub struct Mt19937_64 {
    mt: [u64; NN],
    idx: usize,
}

impl Mt19937_64 {
    /// `init_genrand64`.
    pub fn new(seed: u64) -> Self {
        let mut mt = [0u64; NN];
        mt[0] = seed;
        for i in 1..NN {
            mt[i] = 6_364_136_223_846_793_005u64
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62))
                .wrapping_add(i as u64);
        }
        Self { mt, idx: NN }
    }

    fn generate(&mut self) {
        for i in 0..NN {
            let x = (self.mt[i] & UM) | (self.mt[(i + 1) % NN] & LM);
            let mut xa = x >> 1;
            if x & 1 == 1 {
                xa ^= MATRIX_A;
            }
            self.mt[i] = self.mt[(i + MM) % NN] ^ xa;
        }
        self.idx = 0;
    }

    /// `operator()` — one tempered 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        if self.idx >= NN {
            self.generate();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;

        y ^= (y >> 29) & 0x5555_5555_5555_5555;
        y ^= (y << 17) & 0x71D6_7FFF_EDA6_0000;
        y ^= (y << 37) & 0xFFF7_EEE0_0000_0000;
        y ^= y >> 43;
        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_sequence_for_the_default_seed() {
        // The values std::mt19937_64 produces when seeded with 5489, its own
        // default seed. This is the cross-check that our init/temper path is the
        // standard one; if the C++ build ever disagrees with this, the bug is in
        // the port, not in the reference.
        let mut mt = Mt19937_64::new(5489);
        assert_eq!(mt.next_u64(), 14_514_284_786_278_117_030);
        assert_eq!(mt.next_u64(), 4_620_546_740_167_642_908);
        assert_eq!(mt.next_u64(), 13_109_570_281_517_897_720);
    }

    #[test]
    fn is_deterministic_and_seed_dependent() {
        let mut a = Mt19937_64::new(0x1234_5678_9ABC_DEF0);
        let mut b = Mt19937_64::new(0x1234_5678_9ABC_DEF0);
        let mut c = Mt19937_64::new(0x1234_5678_9ABC_DEF1);
        let a1 = a.next_u64();
        assert_eq!(a1, b.next_u64());
        assert_ne!(a1, c.next_u64());
    }

    #[test]
    fn crosses_a_full_state_refill() {
        // 312 words per block; make sure the twist happens without panicking and
        // stays deterministic across the boundary.
        let mut a = Mt19937_64::new(7);
        let mut b = Mt19937_64::new(7);
        for _ in 0..(NN * 2 + 5) {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
