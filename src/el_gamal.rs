use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

pub struct ElGamal {
    pub pk: RistrettoPoint,
    pub sk: Scalar
}

impl ElGamal {

    pub fn new(mut rng: &mut OsRng) -> ElGamal {
        let sk = Scalar::random(&mut rng);
        ElGamal {
            pk: &sk * &constants::RISTRETTO_BASEPOINT_TABLE,
            sk: sk
        }
    }

    pub fn enc(&self, mut rng: &mut OsRng, m: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint) {
        let r = Scalar::random(&mut rng);
        (&r * &constants::RISTRETTO_BASEPOINT_TABLE, (self.pk * r) + m)
    }
    
    pub fn dec(&self, ct: (RistrettoPoint, RistrettoPoint)) -> RistrettoPoint {
        let (c1, c2) = ct;
        c2 - (c1 * self.sk)
    }

    pub fn enc_w_rand(&self, mut rng: &mut OsRng, m: RistrettoPoint) -> ((RistrettoPoint, RistrettoPoint), Scalar) {
        let r = Scalar::random(&mut rng);
        ((&r * &constants::RISTRETTO_BASEPOINT_TABLE, (self.pk * r) + m), r)
    }

    pub fn rerand(&self, mut rng: &mut OsRng, ct: (RistrettoPoint, RistrettoPoint)) -> ((RistrettoPoint, RistrettoPoint), Scalar) {
        let r = Scalar::random(&mut rng);
        ((&r * &constants::RISTRETTO_BASEPOINT_TABLE + ct.0, (self.pk * r)+ ct.1), r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_enc_and_dec() {
        let mut rng = OsRng {};
        let eg = ElGamal::new(&mut rng);
        let m = RistrettoPoint::random(&mut rng);

        let ct = eg.enc(&mut rng, m);
        let pt = eg.dec(ct);

        assert_eq!(m, pt);
    }

    #[test] 
    fn rerand() {
        let mut rng = OsRng {};
        let eg = ElGamal::new(&mut rng);
        let m = RistrettoPoint::random(&mut rng);

        let ct = eg.enc(&mut rng, m);

        let (ct2, r) = eg.rerand(&mut rng, ct);
        
        let pt = eg.dec(ct);
        let pt2 = eg.dec(ct2);

        assert_eq!(m, pt);
        assert_eq!(pt, pt2);
    }
}