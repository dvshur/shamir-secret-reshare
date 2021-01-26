#![allow(non_snake_case)]

mod polynom;
mod pow;

use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar};
use polynom::Polynom;
use pow::Pow;
use std::convert::TryInto;

// Secret sharing parameters
// Parties number
const N: usize = 5;
// Threshold
const T: usize = 3;

fn main() {
    let mut rng = rand::thread_rng();

    // secret to share
    let secret_string = "Hello, world! Nice day today!";

    // Parties indexes
    let xs: [Scalar; N] = [
        Scalar::from(1u8),
        Scalar::from(2u8),
        Scalar::from(3u8),
        Scalar::from(4u8),
        Scalar::from(5u8),
    ];

    let secret = Scalar::from_bytes_mod_order(to_canonical_bytes(secret_string).unwrap());

    // SHARE
    let shares = {
        let polynom = Polynom::random(&mut rng, &secret, T - 1);
        shamir_share(&xs, &polynom)
    };

    // RESHARE
    // 1. calculate sij
    // i — sender from group 0..T
    // j — recipient from group -0..N'
    // for now consider simple case:
    // T' = T and N' = N
    let senders: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let senders_shares: &[Scalar; T] = &shares[0..T].try_into().expect("fatal error");

    // each redistributing participant generates a random polynom f(x) or order at most T - 1
    // with the participant's secret share as a zero coefficient
    let polynoms: Vec<Polynom> = {
        let mut ps = Vec::with_capacity(T);
        for i in 0..T {
            ps.push(Polynom::random(&mut rng, &senders_shares[i], T - 1))
        }
        ps
    };

    // check, as in Pedersen, for validity of the send s_i_j by checking F_i_j

    // calculate F_i_j
    let Fs: [[EdwardsPoint; T]; T] = {
        let mut fs = [[EdwardsPoint::default(); T]; T];
        for i in 0..T {
            for j in 0..T {
                fs[i][j] = &polynoms[i].coeffs[j] * &constants::ED25519_BASEPOINT_TABLE;
            }
        }
        fs
    };

    // secretly send s_i_j
    let mut ss = [[Scalar::zero(); N]; T];
    for i in 0..T {
        // each sender shares his secret with Shamir SS
        // and sends them to all recipients
        ss[i] = shamir_share(&xs, &polynoms[i]);
    }

    // each P_j verifies that temp shares s_i_j received from all P_i
    // are consistent with previously published F_i_j values
    for j in 0..N {
        for i in 0..T {
            let j_index = xs[j];

            let sum: EdwardsPoint = (0..T)
                .map(|l| j_index.pow(l as u64))
                .zip(Fs[i].iter())
                .map(|(j_pow, F_i_j)| &j_pow * F_i_j)
                .sum();

            assert_eq!(sum, &ss[i][j] * &constants::ED25519_BASEPOINT_TABLE);
        }
    }

    // 2. reconstruct each party from shares sent to it
    let shares_v2 = [
        shamir_reconstruct(&senders, &[ss[0][0], ss[1][0], ss[2][0]]),
        shamir_reconstruct(&senders, &[ss[0][1], ss[1][1], ss[2][1]]),
        shamir_reconstruct(&senders, &[ss[0][2], ss[1][2], ss[2][2]]),
        shamir_reconstruct(&senders, &[ss[0][3], ss[1][3], ss[2][3]]),
        shamir_reconstruct(&senders, &[ss[0][4], ss[1][4], ss[2][4]]),
    ];

    // RECONSTRUCT
    let reconstruct_participants: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let reconstruct_participants_shares: &[Scalar; T] =
        &shares_v2[0..T].try_into().expect("fatal error");

    // check that shares are not equal
    for i in 0..N {
        assert!(shares[i] != shares_v2[i]);
    }

    // check that reconstructed shares are not equal between each other
    for i in 0..N {
        for j in (i + 1)..N {
            assert!(shares_v2[i] != shares_v2[j]);
        }
    }

    let secret_reconstructed =
        shamir_reconstruct(reconstruct_participants, reconstruct_participants_shares);

    // check that original secret can be reconstructed from new shares
    assert_eq!(secret, secret_reconstructed);

    let secret_reconstructed_string =
        from_canonical_bytes(secret_reconstructed.as_bytes()).unwrap();

    println!("{}", secret_reconstructed_string);
}

fn lagrange_coeffs_at_zero(xs: &[Scalar; T]) -> [Scalar; T] {
    let mut cs = [Scalar::one(); T];

    for i in 0..T {
        for j in 0..T {
            if i != j {
                cs[i] *= xs[j] * (xs[j] - xs[i]).invert();
            }
        }
    }

    cs
}

fn shamir_share(xs: &[Scalar; N], polynom: &Polynom) -> [Scalar; N] {
    // create shares for parties as yi = f(xi);
    let mut res = [Scalar::zero(); N];
    for (i, x) in xs.iter().enumerate() {
        res[i] = polynom.at(x);
    }

    res
}

fn shamir_reconstruct(xs: &[Scalar; T], shares: &[Scalar; T]) -> Scalar {
    let lagrange_coeffs = lagrange_coeffs_at_zero(xs);

    let mut res = Scalar::zero();
    for i in 0..T {
        res += lagrange_coeffs[i] * shares[i];
    }

    res
}

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
