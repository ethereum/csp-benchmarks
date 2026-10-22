//! Prover-side auxiliary inputs for the comb and fake-GLV ECDSA circuits.
//!
//! The circuit independently constrains every value produced here. Keeping the
//! decomposition in Rust avoids implementing signed 256-bit witness arithmetic
//! in KoalaBear's 31-bit field; callers run this during witness generation.

use anyhow::{Result, bail, ensure};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, ToPrimitive, Zero};

type Point = Option<(BigInt, BigInt)>;

struct Curve {
    p: BigInt,
    n: BigInt,
    a: BigInt,
    b: BigInt,
    g: Point,
}

fn integer(hex: &str) -> BigInt {
    BigInt::parse_bytes(hex.as_bytes(), 16).expect("constant integer")
}

impl Curve {
    fn new(p256: bool) -> Self {
        if p256 {
            Self {
                p: integer("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                n: integer("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                a: BigInt::from(-3),
                b: integer("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                g: Some((
                    integer("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                    integer("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                )),
            }
        } else {
            Self {
                p: integer("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
                n: integer("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                a: BigInt::zero(),
                b: BigInt::from(7),
                g: Some((
                    integer("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                    integer("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
                )),
            }
        }
    }

    fn add(&self, lhs: &Point, rhs: &Point) -> Point {
        let (Some((x, y)), Some((xx, yy))) = (lhs, rhs) else {
            return lhs.as_ref().or(rhs.as_ref()).cloned();
        };
        let (numerator, denominator) = if x == xx {
            if modulo(y + yy, &self.p).is_zero() {
                return None;
            }
            (3 * x * x + &self.a, 2 * y)
        } else {
            (yy - y, xx - x)
        };
        let slope = modulo(
            numerator * inverse(&denominator, &self.p).expect("nonzero curve denominator"),
            &self.p,
        );
        let rx = modulo(&slope * &slope - x - xx, &self.p);
        let ry = modulo(slope * (x - &rx) - y, &self.p);
        Some((rx, ry))
    }

    fn mul(&self, point: &Point, scalar: &BigInt) -> Point {
        let mut scalar = modulo(scalar.clone(), &self.n)
            .to_biguint()
            .expect("nonnegative scalar");
        let mut power = point.clone();
        let mut out = None;
        while !scalar.is_zero() {
            if scalar.bit(0) {
                out = self.add(&out, &power);
            }
            scalar >>= 1;
            if !scalar.is_zero() {
                power = self.add(&power, &power);
            }
        }
        out
    }

    fn valid(&self, x: &BigInt, y: &BigInt) -> bool {
        x.sign() != Sign::Minus
            && y.sign() != Sign::Minus
            && x < &self.p
            && y < &self.p
            && modulo(y * y - x * x * x - &self.a * x - &self.b, &self.p).is_zero()
    }
}

fn modulo(value: BigInt, modulus: &BigInt) -> BigInt {
    let value = value % modulus;
    if value.is_negative() {
        value + modulus
    } else {
        value
    }
}

fn inverse(value: &BigInt, modulus: &BigInt) -> Result<BigInt> {
    let (mut r0, mut r1) = (modulus.clone(), modulo(value.clone(), modulus));
    let (mut t0, mut t1) = (BigInt::zero(), BigInt::one());
    while !r1.is_zero() {
        let quotient = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 - &quotient * r1);
        (t0, t1) = (t1.clone(), t0 - quotient * t1);
    }
    ensure!(r0.is_one(), "ECDSA inverse of a noninvertible integer");
    Ok(modulo(t0, modulus))
}

#[derive(Clone, Debug)]
struct Eisenstein(BigInt, BigInt);

impl Eisenstein {
    fn sub(&self, rhs: &Self) -> Self {
        Self(&self.0 - &rhs.0, &self.1 - &rhs.1)
    }

    fn add(&self, rhs: &Self) -> Self {
        Self(&self.0 + &rhs.0, &self.1 + &rhs.1)
    }

    fn mul(&self, rhs: &Self) -> Self {
        // omega^2 = -omega - 1.
        Self(
            &self.0 * &rhs.0 - &self.1 * &rhs.1,
            &self.0 * &rhs.1 + &self.1 * &rhs.0 - &self.1 * &rhs.1,
        )
    }

    fn norm(&self) -> BigInt {
        &self.0 * &self.0 - &self.0 * &self.1 + &self.1 * &self.1
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero() && self.1.is_zero()
    }

    fn quotient(&self, rhs: &Self) -> Self {
        let conjugate = Self(&rhs.0 - &rhs.1, -&rhs.1);
        let numerator = self.mul(&conjugate);
        let denominator = rhs.norm();
        Self(
            round_div(&numerator.0, &denominator),
            round_div(&numerator.1, &denominator),
        )
    }
}

// Round to nearest, breaking ties away from zero, as in signed_func.circom.
fn round_div(numerator: &BigInt, denominator: &BigInt) -> BigInt {
    let quotient: BigInt = (numerator.abs() + denominator / 2) / denominator;
    if numerator.is_negative() {
        -quotient
    } else {
        quotient
    }
}

/// Port of the Eisenstein extended-Euclid search in Circom's
/// `eisenstein_func.circom`. Components are signed integers of at most 64 bits.
fn decompose_k1(scalar: &BigInt, order: &BigInt) -> Result<[BigInt; 4]> {
    if scalar.is_zero() {
        return Ok([0.into(), 0.into(), 1.into(), 0.into()]);
    }
    ensure!(
        scalar >= &BigInt::zero() && scalar < order,
        "unreduced scalar"
    );
    let mut r0 = Eisenstein(
        BigInt::parse_bytes(b"367917413016453100223835821029139468248", 10).unwrap(),
        BigInt::parse_bytes(b"64502973549206556628585045361533709077", 10).unwrap(),
    );
    let mut r1 = Eisenstein(scalar.clone(), 0.into());
    let mut t0 = Eisenstein(0.into(), 0.into());
    let mut t1 = Eisenstein(1.into(), 0.into());
    let threshold = BigInt::one() << 128;
    let mut convergents = Vec::new();
    let mut cross = None;
    while !r1.is_zero() {
        if cross.is_none() && r1.norm() < threshold {
            cross = Some(convergents.len());
        }
        convergents.push((r1.clone(), t1.clone()));
        let quotient = r0.quotient(&r1);
        (r0, r1) = (r1.clone(), r0.sub(&quotient.mul(&r1)));
        (t0, t1) = (t1.clone(), t0.sub(&quotient.mul(&t1)));
    }
    let cross = cross.unwrap_or(convergents.len() - 1);
    let lo = cross.saturating_sub(1);
    let hi = (cross + 1).min(convergents.len() - 1);
    let mut best = None;
    let mut best_bits = u64::MAX;
    let mut consider = |u: Eisenstein, v: Eisenstein| {
        if v.is_zero() {
            return;
        }
        let values = [u.0, u.1, v.0, v.1];
        let bits = values.iter().map(|x| x.magnitude().bits()).max().unwrap();
        if bits < best_bits {
            best_bits = bits;
            best = Some(values);
        }
    };
    for i in lo..=hi {
        let (u, v) = &convergents[i];
        for x in -1..=1 {
            for y in -1..=1 {
                if x != 0 || y != 0 {
                    let alpha = Eisenstein(x.into(), y.into());
                    consider(u.mul(&alpha), v.mul(&alpha));
                }
            }
        }
        if i < hi {
            let (uu, vv) = &convergents[i + 1];
            for x in -1..=1 {
                for y in -1..=1 {
                    let alpha = Eisenstein(x.into(), y.into());
                    let (au, av) = (u.mul(&alpha), v.mul(&alpha));
                    for xx in -1..=1 {
                        for yy in -1..=1 {
                            if x != 0 || y != 0 || xx != 0 || yy != 0 {
                                let beta = Eisenstein(xx.into(), yy.into());
                                consider(au.add(&uu.mul(&beta)), av.add(&vv.mul(&beta)));
                            }
                        }
                    }
                }
            }
        }
    }
    ensure!(best_bits <= 64, "fake-GLV decomposition exceeds 64 bits");
    let result = best.expect("nonzero scalar has a convergent");
    let lambda = integer("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
    let denominator = modulo(&result[2] + &result[3] * &lambda, order);
    ensure!(!denominator.is_zero(), "zero fake-GLV denominator");
    ensure!(
        modulo(
            &result[0] + &result[1] * lambda - scalar * denominator,
            order
        )
        .is_zero(),
        "invalid fake-GLV relation"
    );
    Ok(result)
}

/// Extended Euclid stops at sqrt(n), giving both components below 2^128.
fn decompose_p256(scalar: &BigInt, order: &BigInt) -> Result<[BigInt; 4]> {
    ensure!(
        scalar >= &BigInt::zero() && scalar < order,
        "unreduced scalar"
    );
    let threshold = BigInt::from(order.magnitude().sqrt());
    let (mut r0, mut r1) = (order.clone(), scalar.clone());
    let (mut t0, mut t1) = (BigInt::zero(), BigInt::one());
    while r1 > threshold {
        let quotient = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 - &quotient * r1);
        (t0, t1) = (t1.clone(), t0 - quotient * t1);
    }
    ensure!(
        r1.magnitude().bits() <= 128 && t1.magnitude().bits() <= 128,
        "fake-GLV decomposition exceeds 128 bits"
    );
    ensure!(!t1.is_zero(), "zero fake-GLV denominator");
    Ok([r1, t1, 0.into(), 0.into()])
}

fn append_limbs(out: &mut Vec<u8>, value: &BigUint, count: usize) {
    for limb in 0..count {
        let digit = ((value >> (12 * limb)) & BigUint::from(4095u32))
            .to_u32()
            .unwrap();
        out.extend_from_slice(&digit.to_le_bytes());
    }
}

/// Adds R, four signed scalar magnitudes, and their signs in the circuit's
/// private-input declaration order. The original 160 fields are byte limbs,
/// encoded as u32LE; auxiliary magnitudes use 12-bit limbs instead.
pub(crate) fn augment(p256: bool, input: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        input.len() == 160 * 4,
        "ECDSA input must contain 160 byte fields"
    );
    let bytes: Result<Vec<u8>> = input
        .chunks_exact(4)
        .map(|word| {
            let value = u32::from_le_bytes(word.try_into().unwrap());
            u8::try_from(value).map_err(Into::into)
        })
        .collect();
    let bytes = bytes?;
    let values: Vec<BigInt> = bytes
        .chunks_exact(32)
        .map(|word| BigInt::from_bytes_le(Sign::Plus, word))
        .collect();
    let curve = Curve::new(p256);
    let [digest, qx, qy, r, s] = values.as_slice() else {
        unreachable!()
    };
    ensure!(
        curve.valid(qx, qy),
        "ECDSA public key is not a canonical curve point"
    );
    ensure!(
        r > &BigInt::zero() && r < &curve.n,
        "ECDSA r is outside the scalar range"
    );
    ensure!(
        s > &BigInt::zero() && s < &curve.n,
        "ECDSA s is outside the scalar range"
    );
    let inv_s = inverse(s, &curve.n)?;
    let u1 = modulo(digest * &inv_s, &curve.n);
    let u2 = modulo(r * inv_s, &curve.n);
    let q = Some((qx.clone(), qy.clone()));
    let result = curve.add(&curve.mul(&curve.g, &u1), &curve.mul(&q, &u2));
    let Some((rx, ry)) = result else {
        bail!("ECDSA verification result is the point at infinity");
    };
    let decomposition = if p256 {
        decompose_p256(&u2, &curve.n)?
    } else {
        decompose_k1(&u2, &curve.n)?
    };
    let mut out = input.to_vec();
    out.reserve(92 * 4);
    for value in [&rx, &ry] {
        append_limbs(&mut out, value.magnitude(), 22);
    }
    for value in &decomposition {
        append_limbs(&mut out, value.magnitude(), 11);
    }
    for value in &decomposition {
        out.extend_from_slice(&u32::from(value.is_negative()).to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_sample(order: &BigInt) -> Vec<BigInt> {
        let mut values = vec![0.into(), 1.into(), 2.into(), order - 1, order - 2];
        for bit in [63usize, 64, 127, 128, 129, 254, 255] {
            let power = BigInt::one() << bit;
            values.extend([&power - 1, power.clone(), power + 1]);
        }
        let mut state = 0x463f67be65d2198bu64;
        for _ in 0..2048 {
            let mut bytes = [0u8; 32];
            for word in bytes.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                word.copy_from_slice(&state.to_le_bytes());
            }
            values.push(BigInt::from_bytes_le(Sign::Plus, &bytes) % order);
        }
        values
    }

    #[test]
    fn decomposition_relations_and_bounds() -> Result<()> {
        for p256 in [false, true] {
            let curve = Curve::new(p256);
            let lambda = if p256 {
                BigInt::zero()
            } else {
                integer("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72")
            };
            for scalar in scalar_sample(&curve.n) {
                let result = if p256 {
                    decompose_p256(&scalar, &curve.n)?
                } else {
                    decompose_k1(&scalar, &curve.n)?
                };
                let (numerator, denominator) = if p256 {
                    (result[0].clone(), result[1].clone())
                } else {
                    (
                        &result[0] + &lambda * &result[1],
                        &result[2] + &lambda * &result[3],
                    )
                };
                assert!(!modulo(denominator.clone(), &curve.n).is_zero());
                assert!(modulo(numerator - scalar * denominator, &curve.n).is_zero());
                assert!(
                    result
                        .iter()
                        .all(|x| x.magnitude().bits() <= if p256 { 128 } else { 64 })
                );
            }
        }
        Ok(())
    }

    #[test]
    fn signed_decomposition_group_relations() -> Result<()> {
        let beta = integer("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
        for p256 in [false, true] {
            let curve = Curve::new(p256);
            for scalar in scalar_sample(&curve.n).into_iter().take(29) {
                let result = if p256 {
                    decompose_p256(&scalar, &curve.n)?
                } else {
                    decompose_k1(&scalar, &curve.n)?
                };
                let point = curve.mul(&curve.g, &scalar);
                let (lhs, rhs) = if p256 {
                    (
                        curve.mul(&curve.g, &result[0]),
                        curve.mul(&point, &result[1]),
                    )
                } else {
                    let phi = |p: &Point| {
                        p.as_ref()
                            .map(|(x, y)| (modulo(x * &beta, &curve.p), y.clone()))
                    };
                    (
                        curve.add(
                            &curve.mul(&curve.g, &result[0]),
                            &curve.mul(&phi(&curve.g), &result[1]),
                        ),
                        curve.add(
                            &curve.mul(&point, &result[2]),
                            &curve.mul(&phi(&point), &result[3]),
                        ),
                    )
                };
                assert_eq!(lhs, rhs);
            }
        }
        Ok(())
    }

    #[test]
    fn encoded_hints_and_invalid_inputs() -> Result<()> {
        for p256 in [false, true] {
            let (input, _) = crate::ecdsa_input::input(p256);
            let augmented = augment(p256, &input)?;
            assert_eq!(augmented.len(), 252 * 4);
            assert_eq!(&augmented[..640], input);
            let fields: Vec<_> = augmented
                .chunks_exact(4)
                .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
                .collect();
            assert!(fields[160..248].iter().all(|&x| x < 4096));
            assert!(fields[248..].iter().all(|&x| x < 2));
            let curve = Curve::new(p256);
            let from_limbs = |limbs: &[u32]| {
                limbs
                    .iter()
                    .rev()
                    .fold(BigInt::zero(), |value, &limb| (value << 12) + limb)
            };
            let rx = from_limbs(&fields[160..182]);
            let ry = from_limbs(&fields[182..204]);
            assert!(curve.valid(&rx, &ry));
            let signature_r = BigInt::from_bytes_le(
                Sign::Plus,
                &fields[96..128].iter().map(|&x| x as u8).collect::<Vec<_>>(),
            );
            assert_eq!(modulo(rx, &curve.n), signature_r);
            if p256 {
                assert!(fields[226..248].iter().all(|&x| x == 0));
                assert_eq!(&fields[250..], &[0, 0]);
            } else {
                for magnitude in fields[204..248].chunks_exact(11) {
                    assert!(magnitude[5] < 16);
                    assert!(magnitude[6..].iter().all(|&x| x == 0));
                }
            }
            let mut invalid = input.clone();
            invalid[0..4].copy_from_slice(&256u32.to_le_bytes());
            assert!(augment(p256, &invalid).is_err());
            invalid = input.clone();
            invalid[512..640].fill(0);
            assert!(augment(p256, &invalid).is_err());
            invalid = input;
            invalid[128..384].fill(0);
            assert!(augment(p256, &invalid).is_err());
        }
        assert!(augment(false, &[]).is_err());
        Ok(())
    }
}
