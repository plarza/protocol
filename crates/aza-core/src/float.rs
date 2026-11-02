//! Shortest-form floats for deterministic CBOR: a float is canonical only if no narrower width
//! holds the same value, and NaN is only ever half-precision 0x7e00.

/// Whether `value` (finite or infinite, not NaN) fits exactly in a float with `mantissa` explicit
/// bits, smallest subnormal exponent `min_exp` and largest exponent `max_exp`.
fn fits(value: f64, mantissa: u32, min_exp: i32, max_exp: i32) -> bool {
    if value == 0.0 || value.is_infinite() {
        return true;
    }
    let bits = value.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    // value = m * 2^e with m an integer
    let (mut m, mut e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let tz = m.trailing_zeros();
    m >>= tz;
    e += tz as i32;
    let len = 64 - m.leading_zeros() as i32;
    len <= mantissa as i32 + 1 && e >= min_exp && e + len - 1 <= max_exp
}

fn f16_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let frac = (h & 0x3ff) as f64;
    match exp {
        0 => sign * frac * 2f64.powi(-24),
        31 => {
            if frac == 0.0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => sign * (1024.0 + frac) * 2f64.powi(exp - 25),
    }
}

pub fn shortest(width: u8, bits: u64) -> bool {
    match width {
        2 => !f16_to_f64(bits as u16).is_nan() || bits == 0x7e00,
        4 => {
            let v = f32::from_bits(bits as u32) as f64;
            !v.is_nan() && !fits(v, 10, -24, 15)
        }
        8 => {
            let v = f64::from_bits(bits);
            !v.is_nan() && !fits(v, 23, -149, 127)
        }
        _ => false,
    }
}
