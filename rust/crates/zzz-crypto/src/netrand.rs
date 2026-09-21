//! Port of `src/crypto/crandom.hpp` — the `.NET System.Random` subset the game
//! uses to derive `client_rand_key` from the login timestamp.
//!
//! The original is itself a port of `cs_rand.rs`, so the arithmetic here is
//! deliberately C#-shaped: a 56-entry subtractive generator over `int32` with
//! `wrapping_*` everywhere the C++ relies on two's-complement wraparound.

/// `crypto::Random::mBig` — `Int32.MaxValue`.
const M_BIG: i32 = i32::MAX;
/// `crypto::Random::mSeed` — the golden-ratio seed constant.
const M_SEED: i32 = 161_803_398;
/// `Random.seedArray` is length 56 in the original; index 0 is never read.
const SEED_ARRAY_LEN: usize = 56;

pub struct NetRandom {
    seed_array: [i32; SEED_ARRAY_LEN],
    inext: i32,
    inextp: i32,
}

impl NetRandom {
    /// `new System.Random(seed)`, i.e. the legacy Knuth subtractive generator.
    /// (.NET only switched to xoshiro for the *parameterless* constructor, so a
    /// seeded instance still matches this algorithm.)
    pub fn new(seed: i32) -> Self {
        let subtraction = if seed == i32::MIN {
            M_BIG
        } else {
            seed.wrapping_abs()
        };
        let mut mj = M_SEED.wrapping_sub(subtraction);
        let mut seed_array = [0i32; SEED_ARRAY_LEN];
        seed_array[55] = mj;

        let mut mk: i32 = 1;
        for i in 1..55usize {
            let ii = (21 * i) % 55;
            seed_array[ii] = mk;
            mk = mj.wrapping_sub(mk);
            if mk < 0 {
                mk = mk.wrapping_add(M_BIG);
            }
            mj = seed_array[ii];
        }

        for _ in 0..4 {
            for i in 1..SEED_ARRAY_LEN {
                let n = 1 + (i + 30) % 55;
                seed_array[i] = seed_array[i].wrapping_sub(seed_array[n]);
                if seed_array[i] < 0 {
                    seed_array[i] = seed_array[i].wrapping_add(M_BIG);
                }
            }
        }

        Self {
            seed_array,
            inext: 0,
            inextp: 21,
        }
    }

    /// `Random.InternalSample`.
    ///
    /// .NET advances the two indices *and wraps them into 1..=55* before reading.
    /// The C++ port reads `seedArray[inext + 1]` before wrapping, so on its 56th
    /// sample it indexes element 56 of a 56-element array — undefined behaviour
    /// whose result depends on struct layout. Only one sample is ever taken per
    /// seed (`client_rand_key`), the first sample is identical under both
    /// orderings, and the .NET test below pins that value, so this follows .NET
    /// rather than reproducing an out-of-bounds read.
    fn internal_sample(&mut self) -> i32 {
        let mut loc_inext = self.inext + 1;
        let mut loc_inextp = self.inextp + 1;

        if loc_inext >= 56 {
            loc_inext = 1;
        }
        if loc_inextp >= 56 {
            loc_inextp = 1;
        }

        let mut ret =
            self.seed_array[loc_inext as usize].wrapping_sub(self.seed_array[loc_inextp as usize]);

        if ret == M_BIG {
            ret -= 1;
        }
        if ret < 0 {
            ret = ret.wrapping_add(M_BIG);
        }

        self.seed_array[loc_inext as usize] = ret;

        self.inext = loc_inext;
        self.inextp = loc_inextp;

        ret
    }

    /// `Random.NextDouble`.
    pub fn next_double(&mut self) -> f64 {
        f64::from(self.internal_sample()) * (1.0 / f64::from(M_BIG))
    }

    /// `Random.Next(int maxValue)` — the overload the game uses.
    pub fn next_max(&mut self, max_value: i32) -> i32 {
        (self.next_double() * f64::from(max_value)) as i32
    }

    /// `Random.Next()` — named `next_sample` so it cannot be mistaken for
    /// [`Iterator::next`].
    pub fn next_sample(&mut self) -> i32 {
        self.internal_sample()
    }
}

/// `crypto::seedFromUnixSeconds`: seconds since 0001-01-01, truncated to 32 bits
/// and reinterpreted as a signed `int32`.
pub fn seed_from_unix_seconds(unix_seconds: i64) -> i32 {
    const UNIX_EPOCH_OFFSET_SECONDS: i64 = 62_135_596_800;
    let total = unix_seconds.wrapping_add(UNIX_EPOCH_OFFSET_SECONDS);
    (total & 0xFFFF_FFFF) as u32 as i32
}

/// `crypto::clientRandKey`: high half from the generator, low half from the seed.
pub fn client_rand_key(seed: i32) -> u64 {
    let mut rng = NetRandom::new(seed);
    let next_v = rng.next_max(i32::MAX);
    (u64::from(next_v as u32) << 32) | u64::from(seed as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_dotnet_for_seed_zero() {
        // Documented System.Random output for new Random(0): the first Next() is
        // 1559595546, and the first NextDouble() is 0.7262432699679598.
        let mut rng = NetRandom::new(0);
        assert_eq!(rng.next_sample(), 1_559_595_546);

        let mut rng = NetRandom::new(0);
        assert!(
            (rng.next_double() - 0.726_243_269_967_959_8).abs() < 1e-9,
            "first NextDouble() drifted: {}",
            {
                let mut r = NetRandom::new(0);
                r.next_double()
            }
        );
    }

    #[test]
    fn is_deterministic_and_seed_dependent() {
        let mut a = NetRandom::new(12345);
        let mut b = NetRandom::new(12345);
        let mut c = NetRandom::new(12346);
        for _ in 0..8 {
            assert_eq!(a.next_sample(), b.next_sample());
        }
        assert!((0..8).any(|_| a.next_sample() != c.next_sample()));
    }

    #[test]
    fn next_max_stays_in_range() {
        // Deliberately takes many samples, past the point where the C++ port
        // reads out of bounds (see `internal_sample`).
        let mut rng = NetRandom::new(999);
        for _ in 0..1000 {
            let v = rng.next_max(i32::MAX);
            assert!((0..i32::MAX).contains(&v));
        }
    }

    #[test]
    fn seed_offset_and_key_layout() {
        // The seed is *not* the timestamp: the offset to 0001-01-01 is added and
        // the result is truncated to 32 bits, reinterpreted as an i32. For any
        // modern date that lands on a negative value.
        assert_eq!(seed_from_unix_seconds(1_704_067_200), -584_845_440);
        // Only the low 32 bits of the offset timestamp survive.
        let total = 1_704_067_200u64 + 62_135_596_800;
        assert_eq!(
            u64::from(seed_from_unix_seconds(1_704_067_200) as u32),
            total & 0xFFFF_FFFF
        );
        assert_eq!(seed_from_unix_seconds(0), 62_135_596_800u64 as i64 as i32);

        let seed = seed_from_unix_seconds(1_704_067_200);
        let key = client_rand_key(seed);
        assert_eq!(key as u32 as i32, seed, "low half must be the seed");
        let expected_high = NetRandom::new(seed).next_max(i32::MAX) as u32;
        assert_eq!((key >> 32) as u32, expected_high);
    }
}
