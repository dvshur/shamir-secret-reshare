use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

// Secret sharing parameters
// Parties number
const N: usize = 3;
// Threshold
const T: usize = 2;

fn to_canonical_bytes(s: &str) -> Option<[u8; 32]> {
    let mut res = [0u8; 32];

    let bytes = s.as_bytes();

    if bytes.len() > 32 {
        return None;
    }

    for (i, b) in bytes.iter().enumerate() {
        res[i] = b.clone();
    }

    Some(res)
}

fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<String> {
    let s2 = bytes
        .iter()
        .take_while(|b| **b != 0u8)
        .map(|b| b.clone())
        .collect::<Vec<_>>();

    match String::from_utf8(s2) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

trait Pow<T> {
    fn pow(&self, power: u64) -> T;
}

impl Pow<Scalar> for Scalar {
    // todo faster
    fn pow(&self, power: u64) -> Scalar {
        let mut res = Scalar::from(1u8);
        for _ in 0..power {
            res *= self;
        }
        res
    }
}

struct Polynom {
    coeffs: Vec<Scalar>,
}

impl Polynom {
    fn random<R: RngCore + CryptoRng>(rng: &mut R, zero_coeff: &Scalar, order: usize) -> Self {
        let mut p = Polynom {
            coeffs: Vec::with_capacity(order),
        };

        p.coeffs.push(zero_coeff.clone());

        for _ in 1..order {
            p.coeffs.push(Scalar::random(rng));
        }

        p
    }

    fn at(&self, x: &Scalar) -> Scalar {
        let mut res = self.coeffs[0].clone();
        for (i, c) in self.coeffs.iter().enumerate().skip(1) {
            res += c * x.pow(i as u64);
        }
        res
    }
}

fn lagrange_coeffs_at_zero(xs: &[Scalar]) -> Vec<Scalar> {
    let mut cs = Vec::with_capacity(xs.len());
    for xi in xs {
        let mut res = Scalar::from(1u8);
        for xj in xs {
            if xi == xj {
                continue;
            }

            res *= xj * (xj - xi).invert();
        }
        cs.push(res);
    }
    cs
}

fn main() {
    // todo secure random
    let mut rng = rand::thread_rng();

    // secret to share
    let secret = "Hello, world!";

    // Parties indexes
    let xs: Vec<Scalar> = (1..(N + 1)).map(|i| Scalar::from(i as u8)).collect();

    let s = to_canonical_bytes(secret).unwrap();
    let a0 = Scalar::from_bytes_mod_order(s);

    // create a random polynom or order 2
    let polynom = Polynom::random(&mut rng, &a0, T - 1);

    let shares = xs
        .iter()
        .map(|xi| (xi.clone(), polynom.at(&xi)))
        .collect::<Vec<_>>();

    // reconstructing parties xs: 1, 2, 3
    // Lagrange coeffs
    let lagrange_coeffs = lagrange_coeffs_at_zero(&xs[0..T]);

    let a0_reconstructed = {
        let mut res = Scalar::zero();
        for i in 0..T {
            res += lagrange_coeffs[i] * shares[i].1;
        }
        res
    };

    let s2 = a0_reconstructed.as_bytes();
    let s_reconstructed = from_canonical_bytes(&s2).unwrap();

    println!("{}", s_reconstructed);
}
