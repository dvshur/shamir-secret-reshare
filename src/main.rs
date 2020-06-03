// use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

fn to_canonical_bytes(s: &str) -> Option<[u8; 32]> {
    let mut res = [0u8; 32];

    let bytes = s.as_bytes();

    for (i, b) in bytes.iter().enumerate() {
        if i > 31 {
            return None;
        }
        res[i] = b.clone();
    }

    Some(res)
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
    fn random<R: RngCore + CryptoRng>(rng: &mut R, order: usize, zero_coeff: Scalar) -> Self {
        let mut p = Polynom {
            coeffs: Vec::with_capacity(order),
        };

        p.coeffs[0] = zero_coeff;

        for i in 1..order {
            p.coeffs[i] = Scalar::random(rng);
        }

        p
    }

    fn at_zero(&self) -> Scalar {
        self.coeffs[0]
    }

    fn at(&self, x: &Scalar) -> Scalar {
        let mut res = self.coeffs[0].clone();
        for (i, c) in self.coeffs.iter().enumerate().skip(1) {
            res += c * x.pow(i as u64);
        }
        res
    }
}

fn main() {
    // todo secure random
    let mut rng = rand::thread_rng();

    // generate secret to share
    let secret = "Hello, world!";

    // Shamir secret sharing parameters
    const T: usize = 3;
    const N: usize = 4;
    const xs: [Scalar; N] = [
        Scalar::from(1u8),
        Scalar::from(2u8),
        Scalar::from(3u8),
        Scalar::from(4u8),
    ];

    let s = to_canonical_bytes(secret).unwrap();
    let a0 = Scalar::from_bytes_mod_order(s);

    // create a random polynom or order 2
    let polynom = Polynom::random(&mut rng, T - 1, a0);

    let shares = xs
        .iter()
        .map(|xi| (xi.clone(), polynom.at(&xi)))
        .collect::<Vec<_>>();

    // reconstructing parties xs: 1, 2, 3
    let reconstruction_participants = &shares[0..2];

    // Lagrange coeffs
    let lagrange_coeffs = {
        let mut cs = Vec::with_capacity(T);
        for (xi, yi) in reconstruction_participants {
            let mut res = Scalar::from(1u8);
            for (xj, yj) in reconstruction_participants {
                if xi == xj {
                    continue;
                }

                res *= *xj / (xj - xi);
            }
            cs.push(res);
        }
    }
    // let l1 =

    // lagrange_coeffs = reconstruction_participants.iter().map(|(x, _)| )

    // println!("Hello, world!");
}
