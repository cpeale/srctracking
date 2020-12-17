#![allow(non_snake_case)]

use crate::amac::*;
use crate::d_ratchet::*;
use crate::el_gamal::ElGamal;
use crate::proofs::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use double_ratchet::Header;
use rand::rngs::OsRng;
use rand_os::OsRng as OtherRng;
use sha2::{Digest, Sha512};
use zkp::Transcript;
use std::convert::TryInto;
use crate::or_prover::OrProver;
use crate::or_verifier::OrVerifier;

pub struct Platform {
    algm: AMAC,
    eg: ElGamal,
    bot: Scalar,
}

impl Platform {
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
                Cm_p: &(Cf.0.decompress().unwrap() - nCm).compress(),
                Ce1_p: &(Cf.1.decompress().unwrap() - nCe1).compress(),
                Ce2_p: &(Cf.2.decompress().unwrap() - nCe2).compress(),
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

    pub fn verify_receive(&self, proof_bytes: Vec<u8>, 
        H: CompressedRistretto,
        attributes: ((CompressedRistretto, CompressedRistretto), (CompressedRistretto, CompressedRistretto), (CompressedRistretto, CompressedRistretto)),
        Ca: CompressedRistretto,
        Cf: CompressedRistretto,
        Ce1: CompressedRistretto,
        Ce2: CompressedRistretto,
        src: (CompressedRistretto, CompressedRistretto)
    ) {
        let parsed_proof: OrProof = bincode::deserialize(&proof_bytes).unwrap();
        let (a, b, c) = attributes;

        let mut transcript = Transcript::new(b"receive test");
        let mut verifier = OrVerifier::new(b"rec_proof", &mut transcript);

        let var_h = verifier.allocate_scalar(b"h");
        let var_r1 = verifier.allocate_scalar(b"r1");
        let var_r2 = verifier.allocate_scalar(b"r2");
        let var_r3 = verifier.allocate_scalar(b"r3");
        let var_ma = verifier.allocate_scalar(b"ma");
        let var_za = verifier.allocate_scalar(b"za");
        let var_mf = verifier.allocate_scalar(b"mf");
        let var_zf = verifier.allocate_scalar(b"zf");
        let var_rnd = verifier.allocate_scalar(b"rnd");

        let var_H = verifier.allocate_point(b"H", H).unwrap();
        let var_G = verifier.allocate_point(b"G", self.algm.g.compress()).unwrap();
        let var_Y = verifier.allocate_point(b"Y", self.eg.pk.compress()).unwrap();
        let var_Gm = verifier.allocate_point(b"Gm", self.algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier.allocate_point(b"Gy3", self.algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier.allocate_point(b"Ca", Ca).unwrap();
        let var_Cm = verifier.allocate_point(b"Cm", Cf).unwrap();
        let var_A1 = verifier.allocate_point(b"A1", a.0).unwrap();
        let var_A2 = verifier.allocate_point(b"A2", a.1).unwrap();
        let var_B1 = verifier.allocate_point(b"B1", b.0).unwrap();
        let var_B2_over_E1 = verifier.allocate_point(b"B2_over_E1", (b.1.decompress().unwrap() - src.0.decompress().unwrap()).compress()).unwrap();
        let var_C1 = verifier.allocate_point(b"C1", c.0).unwrap();
        let var_C2_over_E2 = verifier.allocate_point(b"C2_over_E2", (c.1.decompress().unwrap() - src.1.decompress().unwrap()).compress()).unwrap();

        receive_author(&mut verifier, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        
        verifier.add_comms(parsed_proof.subchallenge, parsed_proof.resp1);

        let mut verifier2 = OrVerifier::new(b"rec_proof", &mut transcript);
        
        let var_h = verifier2.allocate_scalar(b"h");
        let var_r1 = verifier2.allocate_scalar(b"r1");
        let var_r2 = verifier2.allocate_scalar(b"r2");
        let var_r3 = verifier2.allocate_scalar(b"r3");
        let var_ma = verifier2.allocate_scalar(b"ma");
        let var_za = verifier2.allocate_scalar(b"za");
        let var_mf = verifier2.allocate_scalar(b"mf");
        let var_zf = verifier2.allocate_scalar(b"zf");
        let var_rnd = verifier2.allocate_scalar(b"rnd");

        let var_H = verifier2.allocate_point(b"H", H).unwrap();
        let var_G = verifier2.allocate_point(b"G", self.algm.g.compress()).unwrap();
        let var_Y = verifier2.allocate_point(b"Y", self.eg.pk.compress()).unwrap();
        let var_Gm = verifier2.allocate_point(b"Gm", self.algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier2.allocate_point(b"Gy3", self.algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier2.allocate_point(b"Ca", Ca).unwrap();
        let var_Cm = verifier2.allocate_point(b"Cm", Cf).unwrap();
        let var_A1 = verifier2.allocate_point(b"A1", a.0).unwrap();
        let var_A2 = verifier2.allocate_point(b"A2", a.1).unwrap();
        let var_B1 = verifier2.allocate_point(b"B1", b.0).unwrap();
        let var_B2_over_Ce1 = verifier2.allocate_point(b"B2_over_Ce1", (b.1.decompress().unwrap() - Ce1.decompress().unwrap()).compress()).unwrap();
        let var_C1 = verifier2.allocate_point(b"C1", c.0).unwrap();
        let var_C2_over_Ce2 = verifier2.allocate_point(b"C2_over_Ce2", (c.1.decompress().unwrap() - Ce2.decompress().unwrap()).compress()).unwrap();
        let var_neg_Gy1 = verifier2.allocate_point(b"neg_Gy1", (-self.algm.params[G_Y1]).compress()).unwrap();
        let var_neg_Gy2 = verifier2.allocate_point(b"neg_Gy2", (-self.algm.params[G_Y2]).compress()).unwrap();

        receive_forward(&mut verifier2, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);
        
        verifier2.add_comms(parsed_proof.challenge - parsed_proof.subchallenge, parsed_proof.resp2);
        verifier2.overall_check(parsed_proof.challenge);
    }

    //issue new mac
    pub fn issue_cert(&self, mut rng: &mut OsRng,
        H: RistrettoPoint, 
        attributes: ((RistrettoPoint, RistrettoPoint), (RistrettoPoint, RistrettoPoint), (RistrettoPoint, RistrettoPoint)),
    ) -> ( Vec<u8>, (Scalar, RistrettoPoint, (RistrettoPoint, RistrettoPoint))) {
        let (a, b, c) = attributes;
        let ((t, U, ct), r) = self.algm.blind_issue(&mut rng, H, b, c, a); //TODO: Fix blind issue to be the correct order

        let Ut = U * t;
        let Gv_over_I = self.algm.params[G_V] - self.algm.i;

        // Prover
        let (proof, _points) = {
            let mut transcript = Transcript::new(b"Blind Issue Test");
            blind_issue::prove_compact(
                &mut transcript,
                blind_issue::ProveAssignments {
                    w: &self.algm.secrets[W],
                    wp: &self.algm.secrets[W_P],
                    x0: &self.algm.secrets[X_0],
                    x1: &self.algm.secrets[X_1],
                    y1: &self.algm.secrets[Y_1],
                    y2: &self.algm.secrets[Y_2],
                    y3: &self.algm.secrets[Y_3],
                    r: &r,
                    Cw: &self.algm.cw,
                    U: &U,
                    Ut: &Ut,
                    S1: &ct.0,
                    S2: &ct.1,
                    A1: &a.0, 
                    A2: &a.1, 
                    B1: &b.0,
                    B2: &b.1,
                    C1: &c.0,
                    C2: &c.1,
                    H: &H,
                    G: &self.algm.g,
                    Gw: &self.algm.params[G_W],
                    Gwp: &self.algm.params[G_W_P],
                    GvOverI: &Gv_over_I,
                    Gx0: &self.algm.params[G_X0],
                    Gx1: &self.algm.params[G_X1],
                    Gy1: &self.algm.params[G_Y1],
                    Gy2: &self.algm.params[G_Y2],
                    Gy3: &self.algm.params[G_Y3],
                },
            )
        };

        // Serialize bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();

        (proof_bytes, (t, U, ct))
    }


    pub fn validate_report(&self, plaintext: &[u8], out: PresentOut) -> RistrettoPoint {
        //check proof
        let parsed_proof: present::CompactProof = bincode::deserialize(&out.proof).unwrap();

        let (nCv, nCx0, nCx1, nCm, nCe1, nCe2) = (
            out.info.0.decompress().unwrap(),
            out.info.1.decompress().unwrap(),
            out.info.2.decompress().unwrap(),
            out.info.3.decompress().unwrap(),
            out.info.4.decompress().unwrap(),
            out.info.5.decompress().unwrap(),
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
                Cx1: &out.info.2,
                Cx0: &out.info.1,
                Cm: &out.info.3,
                Ce1: &out.info.4,
                Ce2: &out.info.5,
                Cm_p: &(out.Cf.0.decompress().unwrap() - nCm).compress(),
                Ce1_p: &(out.Cf.1.decompress().unwrap() - nCe1).compress(),
                Ce2_p: &(out.Cf.2.decompress().unwrap() - nCe2).compress(),
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

        //check commitments
        let (zf, rest) = out.o_f.split_at(SCALAR_SIZE);
        let (mf, rest) = rest.split_at(SCALAR_SIZE);
        let (e1, e2) = rest.split_at(PT_SIZE);
        let ct = (CompressedRistretto::from_slice(e1).decompress().unwrap(), CompressedRistretto::from_slice(e2).decompress().unwrap());

        let (mf, zf) = (Scalar::from_bits(mf.try_into().unwrap()), Scalar::from_bits(zf.try_into().unwrap()));
        let (Cm, Ce1, Ce2) = (out.Cf.0.decompress().unwrap(), out.Cf.1.decompress().unwrap(), out.Cf.2.decompress().unwrap());

        assert_eq!(Cm, (self.algm.params[G_Y3] * zf) + (self.algm.params[G_M] * mf));
        assert_eq!(Ce1, self.algm.params[G_Y1] * zf + ct.0);
        assert_eq!(Ce2, self.algm.params[G_Y2] * zf + ct.1);

        //check message matches report
        assert_eq!(mf, Scalar::hash_from_bytes::<Sha512>(plaintext));

        //decrypt
        self.eg.dec(ct)
    }
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

    fn present(&mut self, mut rng: &mut OsRng, plat: &Platform, fd: Option<FD>) -> PresentOut {
        //unpack correct credentials for forwarding vs authoring
        let (t, U, V) = fd.as_ref().map_or(self.ad.mac, |f| f.mac);
        let (e1, e2) = fd.as_ref().map_or(self.ad.src, |f| f.src);
        let m = fd.as_ref().map_or(self.ad.m, |f| f.m);

        //construct commitments
        let (z, z_p, r) = (
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        );
        let z0 = -z * t;
        let Z = plat.algm.i * z;
        let Cx1 = z * plat.algm.params[G_X1] + U * t;
        let Cx0 = z * plat.algm.params[G_X0] + U;
        let Cm = plat.algm.params[G_Y3] * z + plat.algm.params[G_M] * m;
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
                    m: &m,
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
            Cf: (fCm.compress(), fCe1.compress(), fCe2.compress()),
            o_f: vec![
                (z + z_p).to_bytes(),
                m.to_bytes(),
                (e1 + (plat.algm.g * r)).compress().to_bytes(),
                (e2 + (plat.eg.pk * r)).compress().to_bytes(),
            ]
            .concat(),
        }
    }

    pub fn author(
        &mut self,
        mut rng: &mut OsRng,
        plat: &Platform,
        plaintext: &[u8],
    ) -> PlatformData {
        //construct proof
        let out = self.present(&mut rng, plat, None);

        //author commitment
        let z = Scalar::random(&mut rng);
        let m = Scalar::hash_from_bytes::<Sha512>(plaintext);
        let M = plat.algm.params[G_M] * m;
        let Ca = plat.algm.params[G_Y3] * z + M;
        let cmpCa = Ca.compress();

        //encrypt openings
        let o_a = vec![m.to_bytes(), z.to_bytes()].concat();
        let msg = vec![o_a, out.o_f, plaintext.to_vec()].concat(); 
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, &mut self.rng); //todo: how to get rid of this other rng?

        //pass to plat
        let pf = (out.proof, out.info);
        let src = plat.process_send(
        &mut rng,
        self.userid,
        out.Cf,
        pf);

        PlatformData {
            Ca: cmpCa,
            src: src, 
            Cf: out.Cf,
            e: e,
        }
    }

    pub fn forward(&mut self,
        mut rng: &mut OsRng,
        plat: &Platform,
        plaintext: &[u8],
        fd: FD
    ) ->  PlatformData
     {
        //construct proof
        let out = self.present(&mut rng, plat, Some(fd));

        //author commitment
        let z = Scalar::random(&mut rng);
        let M = plat.algm.params[G_M] * plat.bot;
        let Ca = plat.algm.params[G_Y3] * z + M;
        let cmpCa = Ca.compress();

        //encrypt openings
        let o_a = vec![plat.bot.to_bytes(), z.to_bytes()].concat();
        let msg = vec![o_a, out.o_f, plaintext.to_vec()].concat(); 
        let e = self.msg_scheme.ratchet_encrypt(&msg, AD, &mut self.rng); //todo: how to get rid of this other rng?

        //pass to plat
        let pf = (out.proof, out.info);
        let src = plat.process_send(
        &mut rng,
        self.userid,
        out.Cf,
        pf);

        PlatformData {
            Ca: cmpCa,
            src: src, 
            Cf: out.Cf,
            e: e,
        }
    }
    

    //receive
    pub fn receive(&mut self, pd: PlatformData, plat: &Platform, mut rng: &mut OsRng) -> (Vec<u8>, FD) {
        //get contents
        let pt = self.msg_scheme.ratchet_decrypt(&pd.e.0, &pd.e.1, AD).unwrap();
        let (o_a, rest) = pt.split_at(OA_SIZE);
        let (o_f, plaintext) = rest.split_at(OF_SIZE);

        let (ma, za) = o_a.split_at(SCALAR_SIZE);

        let (zf, rest) = o_f.split_at(SCALAR_SIZE);
        let (mf, rest) = rest.split_at(SCALAR_SIZE);
        let (e1, e2) = rest.split_at(PT_SIZE);

        //check comms
        let (ma, za) = (Scalar::from_bits(ma.try_into().unwrap()), Scalar::from_bits(za.try_into().unwrap()));
        let Ca = pd.Ca.decompress().unwrap();
        assert_eq!(Ca, plat.algm.params[G_Y3] * za + plat.algm.params[G_M] * ma);

        let (mf, zf) = (Scalar::from_bits(mf.try_into().unwrap()), Scalar::from_bits(zf.try_into().unwrap()));
        let (Cm, Ce1, Ce2) = (pd.Cf.0.decompress().unwrap(), pd.Cf.1.decompress().unwrap(), pd.Cf.2.decompress().unwrap());

        assert_eq!(Cm, (plat.algm.params[G_Y3] * zf) + (plat.algm.params[G_M] * mf));
        assert_eq!(Ce1, plat.algm.params[G_Y1] * zf + CompressedRistretto::from_slice(e1).decompress().unwrap());
        assert_eq!(Ce2, plat.algm.params[G_Y2] * zf + CompressedRistretto::from_slice(e2).decompress().unwrap());

        let data = ProofData {
            Ca: Ca,
            srca: pd.src,
            Cm: Cm,
            Ce1: Ce1,
            Ce2: Ce2,
            ma: ma,
            za: za,
            mf: mf,
            zf: zf,
            srcf: (CompressedRistretto::from_slice(e1).decompress().unwrap(), CompressedRistretto::from_slice(e2).decompress().unwrap()),
        };

        //forward or author
        if ma == plat.bot {
            println!("Got a forward");
            assert_eq!(mf, Scalar::hash_from_bytes::<Sha512>(plaintext));
            let fd = self.receive_forward_proof(&mut rng, plat, data);
            (plaintext.to_vec(), fd)
        } else {
            assert_eq!(ma, Scalar::hash_from_bytes::<Sha512>(plaintext));
            let fd = self.receive_author_proof(&mut rng, plat, data);
            (plaintext.to_vec(), fd)
        }

    }

    fn receive_author_proof(&self, mut rng: &mut OsRng, plat: &Platform, data: ProofData) -> FD {
        let rec_eg = ElGamal::new(&mut rng);

        let Ma = plat.algm.params[G_M] * data.ma;
        let Mf = plat.algm.params[G_M] * data.mf;

        let (rand_src, rnd) = plat.eg.rerand(&mut rng, data.srca);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Ma);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) = (data.za, data.zf);
        let (Ca, Cf, Ce1, Ce2) = (data.Ca, data.Cm, data.Ce1, data.Ce2);

        let mut transcript = Transcript::new(b"receive test");
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", data.ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", data.mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", plat.algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat.eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", plat.algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", plat.algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_E1, _) = prover.allocate_point(b"B2_over_E1", b.1 - data.srca.0);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_E2, _) = prover.allocate_point(b"C2_over_E2", c.1 - data.srca.1);

        receive_author(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        
        let proof = prover.prove_impl();

        
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", data.ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", data.mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, cmpH) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", plat.algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat.eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", plat.algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", plat.algm.params[G_Y3]);
        let (var_Ca, cmpCa) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, cmpCf) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, cmpA1) = prover.allocate_point(b"A1", a.0);
        let (var_A2, cmpA2) = prover.allocate_point(b"A2", a.1);
        let (var_B1, cmpB1) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_Ce1, _) = prover.allocate_point(b"B2_over_Ce1", b.1 - Ce1);
        let (var_C1, cmpC1) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_Ce2, _) = prover.allocate_point(b"C2_over_Ce2", c.1 - Ce2);
        let (var_neg_Gy1, _) = prover.allocate_point(b"neg_Gy1", -plat.algm.params[G_Y1]);
        let (var_neg_Gy2, _) = prover.allocate_point(b"neg_Gy2", -plat.algm.params[G_Y2]);

        receive_forward(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

        let (sub_challenge, resp2, commitments) = prover.sim_impl(&mut rng);
        let (resp1, challenge) = prover.finish_up(sub_challenge, proof.1, proof.2);

        let first_chall = challenge - sub_challenge;

        let pf = OrProof {
            challenge: challenge,
            subchallenge: first_chall,
            resp1: resp1,
            resp2: resp2,
        };

        let proof_bytes = bincode::serialize(&pf).unwrap();

        plat.verify_receive(proof_bytes, cmpH, 
            ((cmpA1, cmpA2), (cmpB1, b.1.compress()), (cmpC1, c.1.compress())), 
            cmpCa, cmpCf, Ce1.compress(), 
            Ce2.compress(), (data.srca.0.compress(), data.srca.1.compress()));

        let cert = plat.issue_cert(&mut rng, rec_eg.pk, 
        (a, b, c));

        let mac = self.verify_cert(cert.0, cert.1, plat, rec_eg, (a, b, c));
        plat.algm
            .verify(rand_src.0, rand_src.1, data.ma, mac);

        FD {
            m: data.ma,
            src: (rand_src.0, rand_src.1),
            mac: mac,
        }
        
    }

    fn receive_forward_proof(&self, mut rng: &mut OsRng, plat: &Platform, data: ProofData) -> FD {
        let rec_eg = ElGamal::new(&mut rng);

        let Ma = plat.algm.params[G_M] * data.ma;
        let Mf = plat.algm.params[G_M] * data.mf;

        let (rand_src, rnd) = plat.eg.rerand(&mut rng, data.srcf);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Mf);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) = (data.za, data.zf);
        let (Ca, Cf, Ce1, Ce2) = (data.Ca, data.Cm, data.Ce1, data.Ce2);

        let mut transcript = Transcript::new(b"receive test");
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", data.ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", data.mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", plat.algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat.eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", plat.algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", plat.algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_E1, _) = prover.allocate_point(b"B2_over_E1", b.1 - data.srca.0);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_E2, _) = prover.allocate_point(b"C2_over_E2", c.1 - data.srca.1);

        receive_author(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        
        let proof = prover.sim_impl(&mut rng);

        
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", data.ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", data.mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, cmpH) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", plat.algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat.eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", plat.algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", plat.algm.params[G_Y3]);
        let (var_Ca, cmpCa) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, cmpCf) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, cmpA1) = prover.allocate_point(b"A1", a.0);
        let (var_A2, cmpA2) = prover.allocate_point(b"A2", a.1);
        let (var_B1, cmpB1) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_Ce1, _) = prover.allocate_point(b"B2_over_Ce1", b.1 - Ce1);
        let (var_C1, cmpC1) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_Ce2, _) = prover.allocate_point(b"C2_over_Ce2", c.1 - Ce2);
        let (var_neg_Gy1, _) = prover.allocate_point(b"neg_Gy1", -plat.algm.params[G_Y1]);
        let (var_neg_Gy2, _) = prover.allocate_point(b"neg_Gy2", -plat.algm.params[G_Y2]);

        receive_forward(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

            let (comms, blindings, _) = prover.prove_impl();
            let (new_resp, challenge) = prover.recompute_responses(proof.0, blindings);

        let pf = OrProof {
            challenge: challenge,
            subchallenge: proof.0,
            resp1: proof.1,
            resp2: new_resp,
        };

        let proof_bytes = bincode::serialize(&pf).unwrap();

        plat.verify_receive(proof_bytes, cmpH, 
            ((cmpA1, cmpA2), (cmpB1, b.1.compress()), (cmpC1, c.1.compress())), 
            cmpCa, cmpCf, Ce1.compress(), 
            Ce2.compress(), (data.srca.0.compress(), data.srca.1.compress()));
            
        let cert = plat.issue_cert(&mut rng, rec_eg.pk, 
        (a, b, c));

        let mac = self.verify_cert(cert.0, cert.1, plat, rec_eg, (a, b, c));
        plat.algm
            .verify(rand_src.0, rand_src.1, data.mf, mac);

        FD {
            m: data.mf,
            src: (rand_src.0, rand_src.1),
            mac: mac,
        }
        
    }

    fn verify_cert(&self, proof_bytes: Vec<u8>, 
        bmac: (Scalar, RistrettoPoint, (RistrettoPoint, RistrettoPoint)),
        plat: &Platform,
        eg: ElGamal,
        attributes: ((RistrettoPoint, RistrettoPoint), (RistrettoPoint, RistrettoPoint), (RistrettoPoint, RistrettoPoint)),
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        let parsed_proof: blind_issue::CompactProof = bincode::deserialize(&proof_bytes).unwrap();
        let (t, U, ct) = bmac;
        let Ut = U*t;
        let Gv_over_I = plat.algm.params[G_V] - plat.algm.i;
        let (a, b, c) = attributes;

        // Verifier logic
        let mut transcript = Transcript::new(b"Blind Issue Test");
        assert!(blind_issue::verify_compact(
            &parsed_proof,
            &mut transcript,
            blind_issue::VerifyAssignments {
                Cw: &plat.algm.cw.compress(),
                U: &U.compress(),
                Ut: &Ut.compress(),
                S1: &ct.0.compress(),
                S2: &ct.1.compress(),
                A1: &a.0.compress(),
                A2: &a.1.compress(),
                B1: &b.0.compress(),
                B2: &b.1.compress(),
                C1: &c.0.compress(),
                C2: &c.1.compress(),
                H: &eg.pk.compress(),
                G: &plat.algm.g.compress(),
                Gw: &plat.algm.params[G_W].compress(),
                Gwp: &plat.algm.params[G_W_P].compress(),
                GvOverI: &Gv_over_I.compress(),
                Gx0: &plat.algm.params[G_X0].compress(),
                Gx1: &plat.algm.params[G_X1].compress(),
                Gy1: &plat.algm.params[G_Y1].compress(),
                Gy2: &plat.algm.params[G_Y2].compress(),
                Gy3: &plat.algm.params[G_Y3].compress(),
            },
        )
        .is_ok());

        (t, U, eg.dec(ct))
    }
    

    pub fn report(&mut self, fd: FD, mut rng: &mut OsRng, plat: &Platform) -> PresentOut {
        self.present(&mut rng, plat, Some(fd))
    }

}

pub struct FD {
    m: Scalar,
    mac: (Scalar, RistrettoPoint, RistrettoPoint),
    src: (RistrettoPoint, RistrettoPoint),
}

pub struct PlatformData {
    Ca: CompressedRistretto,
    src: (RistrettoPoint, RistrettoPoint),
    Cf: (CompressedRistretto, CompressedRistretto, CompressedRistretto),
    e: (Header<PublicKey>, Vec<u8>),
}

pub struct ProofData {
    Ca: RistrettoPoint,
    srca: (RistrettoPoint, RistrettoPoint),
    Cm: RistrettoPoint,
    Ce1: RistrettoPoint,
    Ce2: RistrettoPoint,
    ma: Scalar,
    za: Scalar,
    mf: Scalar,
    zf: Scalar,
    srcf: (RistrettoPoint, RistrettoPoint),
}

const SCALAR_SIZE: usize = 32;
const PT_SIZE: usize = 32;
const OA_SIZE: usize = SCALAR_SIZE + SCALAR_SIZE;
const OF_SIZE: usize = 2 * SCALAR_SIZE + 2 * PT_SIZE;

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

    #[test]
    fn forward_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (mut u1, mut u2) = User::new(&mut rng, &plat);
        u1.forward(&mut rng, &plat, b"test", u2.ad);
    }

    #[test]
    fn author_and_receive_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (mut u1, mut u2) = User::new(&mut rng, &plat);
        let pd = u1.author(&mut rng, &plat, b"test");
        let (msg, fd) = u2.receive(pd, &plat, &mut rng);
        assert_eq!(msg, b"test".to_vec());
        assert_eq!(Scalar::hash_from_bytes::<Sha512>(b"test"), fd.m);
        assert_eq!(u1.userid, plat.eg.dec(fd.src));
        plat.algm.verify(fd.src.0, fd.src.1, fd.m, fd.mac);
    }

    #[test]
    fn author_and_forward_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (mut u1, mut u2) = User::new(&mut rng, &plat);
        let pd = u1.author(&mut rng, &plat, b"test");
        let (msg, fd) = u2.receive(pd, &plat, &mut rng);

        assert_eq!(msg, b"test".to_vec());
        assert_eq!(Scalar::hash_from_bytes::<Sha512>(b"test"), fd.m);
        assert_eq!(u1.userid, plat.eg.dec(fd.src));
        plat.algm.verify(fd.src.0, fd.src.1, fd.m, fd.mac);

        let pd = u2.forward(&mut rng, &plat, &msg, fd);
        let (msg, fd) = u1.receive(pd, &plat, &mut rng);

        assert_eq!(msg, b"test".to_vec());
        assert_eq!(Scalar::hash_from_bytes::<Sha512>(b"test"), fd.m);
        assert_eq!(u1.userid, plat.eg.dec(fd.src));
        plat.algm.verify(fd.src.0, fd.src.1, fd.m, fd.mac);
    }

    #[test]
    fn report_test() {
        let mut rng = OsRng {};
        let plat = Platform::new(&mut rng);
        let (mut u1, mut u2) = User::new(&mut rng, &plat);
        let pd = u1.author(&mut rng, &plat, b"test");
        let (msg, fd) = u2.receive(pd, &plat, &mut rng);
        
        let rep = u2.report(fd, &mut rng, &plat);
        let uid = plat.validate_report(b"test", rep);
        assert_eq!(uid, u1.userid);
    }

}
