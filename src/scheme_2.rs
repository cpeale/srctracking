#![allow(non_snake_case)]

use crate::amac::*;
use crate::d_ratchet::*;
use crate::el_gamal::ElGamal;
use crate::proofs::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use double_ratchet::Header;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng as OtherRng;
use sha2::{Digest, Sha512};
use zkp::Transcript;

pub struct Platform {
    algm: AMAC,
    eg: ElGamal,
    bot: Scalar,
}

impl Platform {
    //new plat
    //gen mac keys
    //gen eg keys
    pub fn new(mut rng: &mut OsRng) -> Platform {
        let algm = AMAC::init(&mut rng);
        let eg = ElGamal::new(&mut rng);
        Platform {
            algm: algm,
            eg: eg,
            bot: Scalar::hash_from_bytes::<Sha512>(b"unused value"),
        }
    }

    //process message
    pub fn process_send(
        &self,
        mut rng: &mut OsRng,
        uid: RistrettoPoint,
        Cf: (
            CompressedRistretto,
            CompressedRistretto,
            CompressedRistretto,
        ),
        pf: (
            Vec<u8>,
            (
                CompressedRistretto,
                CompressedRistretto,
                CompressedRistretto,
                CompressedRistretto,
                CompressedRistretto,
                CompressedRistretto,
            ),
        )
    ) -> (RistrettoPoint, RistrettoPoint) {
        //verify proof
        let parsed_proof: present::CompactProof = bincode::deserialize(&pf.0).unwrap();

        let (nCv, nCx0, nCx1, nCm, nCe1, nCe2) = (
            pf.1.0.decompress().unwrap(),
            pf.1.1.decompress().unwrap(),
            pf.1.2.decompress().unwrap(),
            pf.1.3.decompress().unwrap(),
            pf.1.4.decompress().unwrap(),
            pf.1.5.decompress().unwrap(),
        );

        let plat_Z = nCv
            - (self.algm.secrets[W] * self.algm.params[G_W]
                + self.algm.secrets[X_0] * nCx0
                + self.algm.secrets[X_1] * nCx1
                + self.algm.secrets[Y_1] * nCe1
                + self.algm.secrets[Y_2] * nCe2
                + self.algm.secrets[Y_3] * nCm);

        let mut transcript = Transcript::new(b"Present Test");
        assert!(present::verify_compact(
            &parsed_proof,
            &mut transcript,
            present::VerifyAssignments {
                Z: &plat_Z.compress(),
                Cx1: &pf.1.2,
                Cx0: &pf.1.1,
                Cm: &pf.1.3,
                Ce1: &pf.1.4,
                Ce2: &pf.1.5,
                Cm_p: &Cf.0,
                Ce1_p: &Cf.1,
                Ce2_p: &Cf.2,
                I: &self.algm.i.compress(),
                Gx0: &self.algm.params[G_X0].compress(),
                Gx1: &self.algm.params[G_X1].compress(),
                Gy1: &self.algm.params[G_Y1].compress(),
                Gy2: &self.algm.params[G_Y2].compress(),
                Gy3: &self.algm.params[G_Y3].compress(),
                Gm: &self.algm.params[G_M].compress(),
                G: &self.algm.g.compress(),
                Y: &self.eg.pk.compress(),
            },
        )
        .is_ok());

        //encrypt source
        let src = self.eg.enc(&mut rng, uid);

        //pass to receiver
        src
    }

    //validate receipt
    //verify proof
    //create new cert
    //pass to user

    //validate report
    //verify proof
    //decrypt
}

pub struct User {
    pub userid: RistrettoPoint,
    pub msg_scheme: SignalDR,
    ad: FD,
    pub rng: OtherRng,
}

pub struct PresentOut {
    proof: Vec<u8>,
    info: (
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
    ),
    Cf: (
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
    ),
    o_f: Vec<u8>,
}

impl User {
    //new pair of users
    //ratchet keys
    //MAC creds
    pub fn new(mut rng: &mut OsRng, plat: &Platform) -> (User, User) {
        let uid1 = RistrettoPoint::random(&mut rng);
        let uid2 = RistrettoPoint::random(&mut rng);

        let ct1 = plat.eg.enc(rng, uid1);
        let mac1 = plat.algm.mac(rng, ct1.0, ct1.1, plat.bot);
        let ct2 = plat.eg.enc(rng, uid2);
        let mac2 = plat.algm.mac(rng, ct2.0, ct2.1, plat.bot);

        let (user1, user2) = pair_setup();

        (
            User {
                userid: uid1,
                msg_scheme: user1,
                ad: FD {
                    m: plat.bot,
                    mac: mac1,
                    src: ct1,
                },
                rng: OtherRng::new().unwrap(),
            },
            User {
                userid: uid2,
                msg_scheme: user2,
                ad: FD {
                    m: plat.bot,
                    mac: mac2,
                    src: ct2,
                },
                rng: OtherRng::new().unwrap(),
            },
        )
    }

    fn present_auth(&mut self, mut rng: &mut OsRng, plat: &Platform) -> PresentOut {
        let (t, U, V) = self.ad.mac;
        let (e1, e2) = self.ad.src;

        let (z, z_p, r) = (
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        );
        let z0 = -z * t;
        let Z = plat.algm.i * z;
        let Cx1 = z * plat.algm.params[G_X1] + U * t;
        let Cx0 = z * plat.algm.params[G_X0] + U;
        let Cm = plat.algm.params[G_Y3] * z + plat.algm.params[G_M] * self.ad.m;
        let Ce1 = (z * plat.algm.params[G_Y1]) + e1;
        let Ce2 = (z * plat.algm.params[G_Y2]) + e2;

        let fCm = Cm + (z_p * plat.algm.params[G_Y3]);
        let fCe1 = (z_p * plat.algm.params[G_Y1]) + (plat.algm.g * r) + Ce1;
        let fCe2 = (z_p * plat.algm.params[G_Y2]) + (plat.eg.pk * r) + Ce2;

        let (Cm_p, Ce1_p, Ce2_p) = (fCm - Cm, fCe1 - Ce1, fCe2 - Ce2);

        let Cv = z * plat.algm.params[G_V] + V;

        // Prover's scope
        let (proof, points) = {
            let mut transcript = Transcript::new(b"Present Test");
            present::prove_compact(
                &mut transcript,
                present::ProveAssignments {
                    z: &z,
                    z0: &z0,
                    m: &self.ad.m,
                    z_p: &z_p,
                    r: &r,
                    t: &t,
                    Z: &Z,
                    Cx1: &Cx1,
                    Cx0: &Cx0,
                    Cm: &Cm,
                    Ce1: &Ce1,
                    Ce2: &Ce2,
                    Cm_p: &Cm_p,
                    Ce1_p: &Ce1_p,
                    Ce2_p: &Ce2_p,
                    I: &plat.algm.i,
                    Gx0: &plat.algm.params[G_X0],
                    Gx1: &plat.algm.params[G_X1],
                    Gy1: &plat.algm.params[G_Y1],
                    Gy2: &plat.algm.params[G_Y2],
                    Gy3: &plat.algm.params[G_Y3],
                    Gm: &plat.algm.params[G_M],
                    G: &plat.algm.g,
                    Y: &plat.eg.pk,
                },
            )
        };

        // Serialize and parse bincode representation

        PresentOut {
            proof: bincode::serialize(&proof).unwrap(),
            info: (
                Cv.compress(),
                points.Cx0,
                points.Cx1,
                points.Cm,
                points.Ce1,
                points.Ce2,
            ),
            Cf: (points.Cm_p, points.Ce1_p, points.Ce2_p),
            o_f: vec![
                (z + z_p).to_bytes(),
                self.ad.m.to_bytes(),
                (self.ad.src.0 + (plat.algm.g * r)).compress().to_bytes(),
                (self.ad.src.1 + (plat.eg.pk * r)).compress().to_bytes(),
            ]
            .concat(),
        }
    }

    //author message (non-interactive)
    pub fn author(
        &mut self,
        mut rng: &mut OsRng,
        plat: &Platform,
        plaintext: &[u8],
    ) -> (
        CompressedRistretto,
        (RistrettoPoint, RistrettoPoint),
        (
            CompressedRistretto,
            CompressedRistretto,
            CompressedRistretto,
        ),
        (Header<PublicKey>, Vec<u8>),
    ) {
        //construct proof
        let out = self.present_auth(&mut rng, plat);

        //author commitment
        let z = Scalar::random(&mut rng);
        let m = Scalar::hash_from_bytes::<Sha512>(plaintext);
        let M = plat.algm.params[G_M] * m;
        let Ca = plat.algm.params[G_Y3] * z + M;
        let cmpCa = Ca.compress();

        //encrypt openings
        let o_a = vec![m.to_bytes(), z.to_bytes()].concat();
        let msg = vec![o_a, out.o_f].concat(); //todo: remove to vec
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, &mut self.rng); //todo: how to get rid of this other rng?

        //pass to plat
        let pf = (out.proof, out.info);
        let src = plat.process_send(
        &mut rng,
        self.userid,
        out.Cf,
        pf);
        let src = plat.eg.enc(&mut rng, self.userid);


        (cmpCa, src, out.Cf, e)
    }

    //forward message (NI)
    //construct proof
    //encrypt openings
    //pass to plat
    //receive
    //construct proof
    //pass to plat
    //get new cert from plat
    //verify cert
    //decrypt cert

    //generate report
    //create proof
}

pub struct FD {
    m: Scalar,
    mac: (Scalar, RistrettoPoint, RistrettoPoint),
    src: (RistrettoPoint, RistrettoPoint),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand_os::OsRng as OtherRng;

    #[test]
    fn scalar_test() {
        let mut rng = OsRng {};
        let s = Scalar::random(&mut rng);

        let bytes1 = s.as_bytes();
        let bytes2 = s.to_bytes();

        println!("as bytes: {:?}", bytes1);
        println!("to bytes: {:?}", bytes2);
        let s2 = Scalar::from_bits(*bytes1);
        let s3 = Scalar::from_bits(bytes2);

        assert_eq!(s, s2);
        assert_eq!(s, s3);
    }

    #[test]
    fn user_setup_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (u1, u2) = User::new(&mut rng, &plat);

        plat.algm
            .verify(u1.ad.src.0, u1.ad.src.1, plat.bot, u1.ad.mac);
        plat.algm
            .verify(u2.ad.src.0, u2.ad.src.1, plat.bot, u2.ad.mac);
        let rsrc1 = plat.eg.dec(u1.ad.src);
        let rsrc2 = plat.eg.dec(u2.ad.src);
        assert_eq!(rsrc1, u1.userid);
        assert_eq!(rsrc2, u2.userid);
    }

    #[test]
    fn author_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (mut u1, mut u2) = User::new(&mut rng, &plat);
        u1.author(&mut rng, &plat, b"test");
        u1.author(&mut rng, &plat, b"another test");
    }
}
