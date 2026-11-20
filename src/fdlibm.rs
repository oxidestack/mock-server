//! The JDK's fdlibm functions where the last bit is observable: `Math.log` on the oracle's JVM rounds as fdlibm's
//! `__ieee754_log` (`java.lang.FdLibm.Log`), which differs from the platform `ln` by an ulp for some arguments
//! (`log(3)`).

const LN2_HI: f64 = 6.931_471_803_691_238e-1; // 0x3fe62e42 fee00000
const LN2_LO: f64 = 1.908_214_929_270_587_7e-10; // 0x3dea39ef 35793c76
const TWO54: f64 = 1.801_439_850_948_198_4e16; // 0x43500000 00000000
const LG1: f64 = 6.666_666_666_666_735e-1; // 0x3FE55555 55555593
const LG2: f64 = 3.999_999_999_940_942e-1; // 0x3FD99999 9997FA04
const LG3: f64 = 2.857_142_874_366_239e-1; // 0x3FD24924 94229359
const LG4: f64 = 2.222_219_843_214_978_4e-1; // 0x3FCC71C5 1D8E78AF
const LG5: f64 = 1.818_357_216_161_805e-1; // 0x3FC74664 96CB03DE
const LG6: f64 = 1.531_383_769_920_937_3e-1; // 0x3FC39A09 D078C69F
const LG7: f64 = 1.479_819_860_511_658_6e-1; // 0x3FC2F112 DF3E5244

fn high(x: f64) -> i32 {
    (x.to_bits() >> 32) as i32
}

fn low(x: f64) -> u32 {
    x.to_bits() as u32
}

fn with_high(x: f64, hi: i32) -> f64 {
    f64::from_bits(((hi as u32 as u64) << 32) | (x.to_bits() & 0xffff_ffff))
}

/// `__ieee754_log(x)`, as `java.lang.FdLibm.Log.compute`.
pub fn log(mut x: f64) -> f64 {
    let mut hx = high(x);
    let lx = low(x);
    let mut k: i32 = 0;
    if hx < 0x0010_0000 {
        // x < 2**-1022
        if ((hx & 0x7fff_ffff) as u32 | lx) == 0 {
            return -TWO54 / 0.0; // log(+-0) = -inf
        }
        if hx < 0 {
            return f64::NAN; // log(-#) = NaN
        }
        k -= 54;
        x *= TWO54; // subnormal number, scale up x
        hx = high(x);
    }
    if hx >= 0x7ff0_0000 {
        return x + x;
    }
    k += (hx >> 20) - 1023;
    hx &= 0x000f_ffff;
    let i = (hx + 0x95f64) & 0x0010_0000;
    x = with_high(x, hx | (i ^ 0x3ff0_0000)); // normalize x or x/2
    k += i >> 20;
    let f = x - 1.0;
    if (0x000f_ffff & (2 + hx)) < 3 {
        // |f| < 2**-20
        if f == 0.0 {
            if k == 0 {
                return 0.0;
            }
            let dk = k as f64;
            return dk * LN2_HI + dk * LN2_LO;
        }
        let r = f * f * (0.5 - 0.333_333_333_333_333_3 * f);
        if k == 0 {
            return f - r;
        }
        let dk = k as f64;
        return dk * LN2_HI - ((r - dk * LN2_LO) - f);
    }
    let s = f / (2.0 + f);
    let dk = k as f64;
    let z = s * s;
    let mut i = hx - 0x6147a;
    let w = z * z;
    let j = 0x6b851 - hx;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    i |= j;
    let r = t2 + t1;
    if i > 0 {
        let hfsq = 0.5 * f * f;
        if k == 0 {
            f - (hfsq - s * (hfsq + r))
        } else {
            dk * LN2_HI - ((hfsq - (s * (hfsq + r) + dk * LN2_LO)) - f)
        }
    } else if k == 0 {
        f - s * (f - r)
    } else {
        dk * LN2_HI - ((s * (f - r) - dk * LN2_LO) - f)
    }
}

#[cfg(test)]
mod tests {
    use super::log;

    #[test]
    fn rounds_as_fdlibm() {
        // `StrictMath.log` on Temurin 25.
        assert_eq!(log(3.0).to_bits(), 1.0986122886681096f64.to_bits());
        assert_eq!((3.0f64).ln().to_bits(), 1.0986122886681098f64.to_bits());
        assert_eq!(log(1.0), 0.0);
        assert_eq!(log(2.0), std::f64::consts::LN_2);
        assert_eq!(log(0.0), f64::NEG_INFINITY);
        assert!(log(-1.0).is_nan());
        assert_eq!(log(f64::INFINITY), f64::INFINITY);
    }

    /// `Math.log` on Temurin 25 (aarch64, equal to `StrictMath.log` on every vector): 1..1000, uniform [0, 4) and
    /// random positive bit patterns, as `<x bits> <log bits>` in hex.
    #[test]
    fn matches_the_jdk_vectors() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/fdlibm/log.txt")).unwrap();
        for line in text.lines() {
            let (x, expected) = line.split_once(' ').unwrap();
            let x = f64::from_bits(u64::from_str_radix(x, 16).unwrap());
            let expected = u64::from_str_radix(expected, 16).unwrap();
            assert_eq!(log(x).to_bits(), expected, "log({x:e})");
        }
    }
}
