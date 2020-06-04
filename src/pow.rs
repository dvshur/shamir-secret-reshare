use curve25519_dalek::scalar::Scalar;

pub trait Pow<T> {
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
