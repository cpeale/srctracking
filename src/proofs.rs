/*
* Proofs for scheme 2
*/
#![allow(non_snake_case)]

use zkp::toolbox::SchnorrCS;
use curve25519_dalek::scalar::Scalar;

//presenting a msg
define_proof! {
    present,
    "Proof for presenting forward credentials",
    (z, z0, m, z_p, r, t),
    (Z, Cx1, Cx0, Cm, Ce1, Ce2, Cm_p, Ce1_p, Ce2_p),
    (I, Gx0, Gx1, Gy1, Gy2, Gy3, Gm, G, Y):
    Z = (z * I),
    Cx1 = (t * Cx0 + z0 * Gx0 + z * Gx1),
    Cm = (z * Gy3 + m * Gm),
    Cm_p = (z_p * Gy3),
    Ce1_p = (z_p * Gy1 + r * G),
    Ce2_p = (z_p * Gy2 + r * Y)
}

pub fn receive_author<CS: SchnorrCS>(
    cs: &mut CS,
    h: CS::ScalarVar,
    r1: CS::ScalarVar,
    r2: CS::ScalarVar,
    r3: CS::ScalarVar,
    ma: CS::ScalarVar,
    za: CS::ScalarVar,
    mf: CS::ScalarVar,
    zf: CS::ScalarVar,
    rnd: CS::ScalarVar,
    H: CS::PointVar,
    G: CS::PointVar,
    Y: CS::PointVar,
    Gm: CS::PointVar,
    Gy3: CS::PointVar,
    Ca: CS::PointVar,
    Cm: CS::PointVar,
    A1: CS::PointVar,
    A2: CS::PointVar,
    B1: CS::PointVar,
    B2_over_E1: CS::PointVar,
    C1: CS::PointVar,
    C2_over_E2: CS::PointVar,
) {
    cs.constrain(H, vec![(h, G)]); //H = G^h
    cs.constrain(A1, vec![(r1, G)]); //A1 = G^r1
    cs.constrain(B1, vec![(r2, G)]); //B1 = G^r2
    cs.constrain(C1, vec![(r3, G)]); //C1 = G^r3
    cs.constrain(Ca, vec![(ma, Gm), (za, Gy3)]); //Ca = Gm^ma * Gy3^za
    cs.constrain(Cm, vec![(mf, Gm), (zf, Gy3)]); //Cf = Gm^mf * Gy3^zf

    cs.constrain(A2, vec![(r1, H), (ma, Gm)]); //A2 = Gm^ma * H^r1
    cs.constrain(B2_over_E1, vec![(r2, H), (rnd, G)]); //B2/E1 = G^rnd * H^r2
    cs.constrain(C2_over_E2, vec![(r3, H), (rnd, Y)]); //C2/E2 = Y^rnd * H^r3
}

pub fn receive_forward<CS: SchnorrCS>(
    cs: &mut CS,
    h: CS::ScalarVar,
    r1: CS::ScalarVar,
    r2: CS::ScalarVar,
    r3: CS::ScalarVar,
    ma: CS::ScalarVar,
    za: CS::ScalarVar,
    mf: CS::ScalarVar,
    zf: CS::ScalarVar,
    rnd: CS::ScalarVar,
    H: CS::PointVar,
    G: CS::PointVar,
    Y: CS::PointVar,
    Gm: CS::PointVar,
    Gy3: CS::PointVar,
    Ca: CS::PointVar,
    Cm: CS::PointVar,
    A1: CS::PointVar,
    A2: CS::PointVar,
    B1: CS::PointVar,
    B2_over_Ce1: CS::PointVar,
    C1: CS::PointVar,
    C2_over_Ce2: CS::PointVar,
    neg_Gy1: CS::PointVar,
    neg_Gy2: CS::PointVar,
) {
    cs.constrain(H, vec![(h, G)]); //H = G^h
    cs.constrain(A1, vec![(r1, G)]); //A1 = G^r1
    cs.constrain(B1, vec![(r2, G)]); //B1 = G^r2
    cs.constrain(C1, vec![(r3, G)]); //C1 = G^r3
    cs.constrain(Ca, vec![(ma, Gm), (za, Gy3)]); //Ca = Gm^ma * Gy3^za
    cs.constrain(Cm, vec![(mf, Gm), (zf, Gy3)]); //Cf = Gm^mf * Gy3^zf

    cs.constrain(A2, vec![(r1, H), (mf, Gm)]); //A2 = Gm^mf * H^r1
    cs.constrain(B2_over_Ce1, vec![(r2, H), (rnd, G), (zf, neg_Gy1)]); //B2/Ce1 = G^rnd * H^r2 / Gy1^zf
    cs.constrain(C2_over_Ce2, vec![(r3, H), (rnd, Y), (zf, neg_Gy2)]); //C2/Ce2 = Y^rnd * H^r3 / Gy2^zf
}

//issuing a cred
define_proof! {
    issue,
    "Proof for issuing MAC in clear",
    (w, wp, x0, x1, y1, y2, y3),
    (V, U, Ut, E1, E2, M),
    (Cw, Gw, Gwp, GvOverI, Gx0, Gx1, Gy1, Gy2, Gy3):
    Cw = (w * Gw + wp * Gwp),
    GvOverI = (x0 * Gx0 + x1 * Gx1 + y1 * Gy1 + y2 * Gy2 + y3 * Gy3),
    V = (w * Gw + x0 * U + x1 * Ut + y1 * E1 + y2 * E2 + y3 * M)
}

define_proof! {
    blind_issue,
    "Proof for blind issuance of mac",
    (w, wp, x0, x1, y1, y2, y3, r),
    (S1, S2, A1, A2, B1, B2, C1, C2, U, Ut, H),
    (Cw, Gw, Gwp, GvOverI, Gx0, Gx1, Gy1, Gy2, Gy3, G):
    Cw = (w * Gw + wp * Gwp),
    GvOverI = (x0 * Gx0 + x1 * Gx1 + y1 * Gy1 + y2 * Gy2 + y3 * Gy3),
    S1 = (y3 * A1 + y1 * B1 + y2 * C1 + r * G),
    S2 = (y3 * A2 + y1 * B2 + y2 * C2 + r * H + w * Gw + x0 * U + x1 * Ut)
}

define_proof! {
    testpf,
    "Simple Test Proof",
    (x),
    (A),
    (B):
    A = (x * B)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OrProof {
    pub challenge: Scalar,
    pub subchallenge: Scalar,
    pub resp1: Vec<Scalar>,
    pub resp2: Vec<Scalar>,
}

#[cfg(test)]
mod tests {
    extern crate bincode;
    use super::*;
    use crate::amac::*;
    use crate::el_gamal::ElGamal;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use zkp::Transcript;
    use zkp::toolbox::{prover::Prover, verifier::Verifier};
    use crate::or_prover::OrProver;
    use crate::or_verifier::OrVerifier;

    #[test]
    fn basic_pf_test() {
        let mut rng = OsRng {};
        let B = RistrettoPoint::random(&mut rng);
        let x = Scalar::random(&mut rng);
        let A = B * x;

        // Prover's scope
        let (proof, _points) = {
            let mut transcript = Transcript::new(b"Test");
            testpf::prove_compact(
                &mut transcript,
                testpf::ProveAssignments {
                    x: &x,
                    A: &A,
                    B: &B,
                },
            )
        };

        // Serialize and parse bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();
        let parsed_proof: testpf::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

        // Verifier logic
        let mut transcript = Transcript::new(b"Test");
        assert!(testpf::verify_compact(
            &parsed_proof,
            &mut transcript,
            testpf::VerifyAssignments {
                A: &A.compress(),
                B: &B.compress(),
            },
        )
        .is_ok());
    }

    #[test]
    #[should_panic]
    fn basic_pf_fail_test() {
        // Prover's scope
        let (proof, points) = {
            let mut rng = OsRng {};
            let B = RistrettoPoint::random(&mut rng);
            let x = Scalar::random(&mut rng);
            let A = B;

            let mut transcript = Transcript::new(b"Test");
            testpf::prove_compact(
                &mut transcript,
                testpf::ProveAssignments {
                    x: &x,
                    A: &A,
                    B: &B,
                },
            )
        };

        // Serialize and parse bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();
        let parsed_proof: testpf::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

        // Verifier logic
        let mut transcript = Transcript::new(b"Test");
        assert!(testpf::verify_compact(
            &parsed_proof,
            &mut transcript,
            testpf::VerifyAssignments {
                A: &points.A,
                B: &points.B,
            },
        )
        .is_ok());
    }

    #[test]
    fn issue_pf_test() {
        let mut rng = OsRng {};
        let algm = AMAC::init(&mut rng);

        let (E1, E2) = (
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
        );
        let m = Scalar::random(&mut rng);

        let (t, U, V) = algm.mac(&mut rng, E1, E2, m);

        let M = algm.params[G_M] * m;
        let Ut = U * t;
        let Gv_over_I = algm.params[G_V] - algm.i;

        // Prover's scope
        let (proof, _points) = {
            let mut transcript = Transcript::new(b"Issue Test");
            issue::prove_compact(
                &mut transcript,
                issue::ProveAssignments {
                    w: &algm.secrets[W],
                    wp: &algm.secrets[W_P],
                    x0: &algm.secrets[X_0],
                    x1: &algm.secrets[X_1],
                    y1: &algm.secrets[Y_1],
                    y2: &algm.secrets[Y_2],
                    y3: &algm.secrets[Y_3],
                    Cw: &algm.cw,
                    V: &V,
                    U: &U,
                    Ut: &Ut,
                    E1: &E1,
                    E2: &E2,
                    M: &M,
                    Gw: &algm.params[G_W],
                    Gwp: &algm.params[G_W_P],
                    GvOverI: &Gv_over_I,
                    Gx0: &algm.params[G_X0],
                    Gx1: &algm.params[G_X1],
                    Gy1: &algm.params[G_Y1],
                    Gy2: &algm.params[G_Y2],
                    Gy3: &algm.params[G_Y3],
                },
            )
        };

        // Serialize and parse bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();
        let parsed_proof: issue::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

        // Verifier logic
        let mut transcript = Transcript::new(b"Issue Test");
        assert!(issue::verify_compact(
            &parsed_proof,
            &mut transcript,
            issue::VerifyAssignments {
                Cw: &algm.cw.compress(),
                V: &V.compress(),
                U: &U.compress(),
                Ut: &Ut.compress(),
                E1: &E1.compress(),
                E2: &E2.compress(),
                M: &M.compress(),
                Gw: &algm.params[G_W].compress(),
                Gwp: &algm.params[G_W_P].compress(),
                GvOverI: &Gv_over_I.compress(),
                Gx0: &algm.params[G_X0].compress(),
                Gx1: &algm.params[G_X1].compress(),
                Gy1: &algm.params[G_Y1].compress(),
                Gy2: &algm.params[G_Y2].compress(),
                Gy3: &algm.params[G_Y3].compress(),
            },
        )
        .is_ok());
    }

    #[test]
    fn blind_issue_pf_test() {
        let mut rng = OsRng {};
        let algm = AMAC::init(&mut rng);

        let (E1, E2) = (
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
        );
        let m = Scalar::random(&mut rng);
        let M = algm.params[G_M] * m;

        let eg = ElGamal::new(&mut rng);
        let (a, b, c) = (
            eg.enc(&mut rng, M),
            eg.enc(&mut rng, E1),
            eg.enc(&mut rng, E2),
        );
        let ((t, U, ct), r) = algm.blind_issue(&mut rng, eg.pk, b, c, a);

        let Ut = U * t;
        let Gv_over_I = algm.params[G_V] - algm.i;

        // Prover
        let (proof, _points) = {
            let mut transcript = Transcript::new(b"Blind Issue Test");
            blind_issue::prove_compact(
                &mut transcript,
                blind_issue::ProveAssignments {
                    w: &algm.secrets[W],
                    wp: &algm.secrets[W_P],
                    x0: &algm.secrets[X_0],
                    x1: &algm.secrets[X_1],
                    y1: &algm.secrets[Y_1],
                    y2: &algm.secrets[Y_2],
                    y3: &algm.secrets[Y_3],
                    r: &r,
                    Cw: &algm.cw,
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
                    H: &eg.pk,
                    G: &algm.g,
                    Gw: &algm.params[G_W],
                    Gwp: &algm.params[G_W_P],
                    GvOverI: &Gv_over_I,
                    Gx0: &algm.params[G_X0],
                    Gx1: &algm.params[G_X1],
                    Gy1: &algm.params[G_Y1],
                    Gy2: &algm.params[G_Y2],
                    Gy3: &algm.params[G_Y3],
                },
            )
        };

        // Serialize and parse bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();
        let parsed_proof: blind_issue::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

        // Verifier logic
        let mut transcript = Transcript::new(b"Blind Issue Test");
        assert!(blind_issue::verify_compact(
            &parsed_proof,
            &mut transcript,
            blind_issue::VerifyAssignments {
                Cw: &algm.cw.compress(),
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
                G: &algm.g.compress(),
                Gw: &algm.params[G_W].compress(),
                Gwp: &algm.params[G_W_P].compress(),
                GvOverI: &Gv_over_I.compress(),
                Gx0: &algm.params[G_X0].compress(),
                Gx1: &algm.params[G_X1].compress(),
                Gy1: &algm.params[G_Y1].compress(),
                Gy2: &algm.params[G_Y2].compress(),
                Gy3: &algm.params[G_Y3].compress(),
            },
        )
        .is_ok());

        let V = eg.dec(ct);
        algm.verify(E1, E2, m, (t, U, V));
    }

    #[test]
    fn present_pf_test() {
        let mut rng = OsRng {};
        let algm = AMAC::init(&mut rng);
        let eg = ElGamal::new(&mut rng);

        let uid = RistrettoPoint::random(&mut rng);
        let m = Scalar::random(&mut rng);

        let (e1, e2) = eg.enc(&mut rng, uid);
        let (t, U, V) = algm.mac(&mut rng, e1, e2, m);

        let (z, z_p, r) = (
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        );
        let z0 = -z * t;
        let Z = algm.i * z;
        let Cx1 = z * algm.params[G_X1] + U * t;
        let Cx0 = z * algm.params[G_X0] + U;
        let Cm = algm.params[G_Y3] * z + algm.params[G_M] * m;
        let Ce1 = (z * algm.params[G_Y1]) + e1;
        let Ce2 = (z * algm.params[G_Y2]) + e2;

        let fCm = Cm + (z_p * algm.params[G_Y3]);
        let fCe1 = (z_p * algm.params[G_Y1]) + (algm.g * r) + Ce1;
        let fCe2 = (z_p * algm.params[G_Y2]) + (eg.pk * r) + Ce2;

        let (Cm_p, Ce1_p, Ce2_p) = (fCm - Cm, fCe1 - Ce1, fCe2 - Ce2);

        let Cv = z * algm.params[G_V] + V;

        // Prover's scope
        let (proof, _points) = {
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
                    I: &algm.i,
                    Gx0: &algm.params[G_X0],
                    Gx1: &algm.params[G_X1],
                    Gy1: &algm.params[G_Y1],
                    Gy2: &algm.params[G_Y2],
                    Gy3: &algm.params[G_Y3],
                    Gm: &algm.params[G_M],
                    G: &algm.g,
                    Y: &eg.pk,
                },
            )
        };

        // Serialize and parse bincode representation
        let proof_bytes = bincode::serialize(&proof).unwrap();
        let parsed_proof: present::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

        // Verifier logic
        let plat_Z = Cv
            - (algm.secrets[W] * algm.params[G_W]
                + algm.secrets[X_0] * Cx0
                + algm.secrets[X_1] * Cx1
                + algm.secrets[Y_1] * Ce1
                + algm.secrets[Y_2] * Ce2
                + algm.secrets[Y_3] * Cm);

        let mut transcript = Transcript::new(b"Present Test");
        assert!(present::verify_compact(
            &parsed_proof,
            &mut transcript,
            present::VerifyAssignments {
                Z: &plat_Z.compress(),
                Cx1: &Cx1.compress(),
                Cx0: &Cx0.compress(),
                Cm: &Cm.compress(),
                Ce1: &Ce1.compress(),
                Ce2: &Ce2.compress(),
                Cm_p: &Cm_p.compress(),
                Ce1_p: &Ce1_p.compress(),
                Ce2_p: &Ce2_p.compress(),
                I: &algm.i.compress(),
                Gx0: &algm.params[G_X0].compress(),
                Gx1: &algm.params[G_X1].compress(),
                Gy1: &algm.params[G_Y1].compress(),
                Gy2: &algm.params[G_Y2].compress(),
                Gy3: &algm.params[G_Y3].compress(),
                Gm: &algm.params[G_M].compress(),
                G: &algm.g.compress(),
                Y: &eg.pk.compress(),
            },
        )
        .is_ok());
    }

    #[test]
    fn receive_author_only_test() {
        let mut rng = OsRng{};
        let algm = AMAC::init(&mut rng);
        let plat_eg = ElGamal::new(&mut rng);
        let rec_eg = ElGamal::new(&mut rng);

        let (ma, mf) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let Ma = algm.params[G_M] * ma;
        let Mf = algm.params[G_M] * mf;
        let uid = RistrettoPoint::random(&mut rng);

        let src = plat_eg.enc(&mut rng, uid);
        let (rand_src, rnd) = plat_eg.rerand(&mut rng, src);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Ma);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) =  (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (Ca, Cf) = (algm.params[G_Y3] * za + Ma, algm.params[G_Y3] * zf + Mf);

        let mut transcript = Transcript::new(b"receive author test");
        let mut prover = Prover::new(b"rec_auth_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_E1, _) = prover.allocate_point(b"B2_over_E1", b.1 - src.0);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_E2, _) = prover.allocate_point(b"C2_over_E2", c.1 - src.1);

        receive_author(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        let proof = prover.prove_compact();

        //verify
        let mut transcript = Transcript::new(b"receive author test");
        let mut verifier = Verifier::new(b"rec_auth_proof", &mut transcript);

        let var_h = verifier.allocate_scalar(b"h");
        let var_r1 = verifier.allocate_scalar(b"r1");
        let var_r2 = verifier.allocate_scalar(b"r2");
        let var_r3 = verifier.allocate_scalar(b"r3");
        let var_ma = verifier.allocate_scalar(b"ma");
        let var_za = verifier.allocate_scalar(b"za");
        let var_mf = verifier.allocate_scalar(b"mf");
        let var_zf = verifier.allocate_scalar(b"zf");
        let var_rnd = verifier.allocate_scalar(b"rnd");

        let var_H = verifier.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_E1 = verifier.allocate_point(b"B2_over_E1", (b.1 - src.0).compress()).unwrap();
        let var_C1 = verifier.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_E2 = verifier.allocate_point(b"C2_over_E2", (c.1 - src.1).compress()).unwrap();

        receive_author(&mut verifier, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);

        assert!(verifier.verify_compact(&proof).is_ok());
    }

    #[test]
    fn receive_forward_only_test() {
        let mut rng = OsRng{};
        let algm = AMAC::init(&mut rng);
        let plat_eg = ElGamal::new(&mut rng);
        let rec_eg = ElGamal::new(&mut rng);

        let (ma, mf) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let Ma = algm.params[G_M] * ma;
        let Mf = algm.params[G_M] * mf;
        let uid = RistrettoPoint::random(&mut rng);

        let src = plat_eg.enc(&mut rng, uid);
        let (rand_src, rnd) = plat_eg.rerand(&mut rng, src);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Mf);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) =  (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (Ca, Cf) = (algm.params[G_Y3] * za + Ma, algm.params[G_Y3] * zf + Mf);

        let (Ce1, Ce2) = (algm.params[G_Y1] * zf + src.0, algm.params[G_Y2]*zf + src.1);

        let mut transcript = Transcript::new(b"receive forward test");
        let mut prover = Prover::new(b"rec_fwd_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_Ce1, _) = prover.allocate_point(b"B2_over_Ce1", b.1 - Ce1);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_Ce2, _) = prover.allocate_point(b"C2_over_Ce2", c.1 - Ce2);
        let (var_neg_Gy1, _) = prover.allocate_point(b"neg_Gy1", -algm.params[G_Y1]);
        let (var_neg_Gy2, _) = prover.allocate_point(b"neg_Gy2", -algm.params[G_Y2]);

        receive_forward(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

        let proof = prover.prove_compact();

        //verify
        let mut transcript = Transcript::new(b"receive forward test");
        let mut verifier = Verifier::new(b"rec_fwd_proof", &mut transcript);

        let var_h = verifier.allocate_scalar(b"h");
        let var_r1 = verifier.allocate_scalar(b"r1");
        let var_r2 = verifier.allocate_scalar(b"r2");
        let var_r3 = verifier.allocate_scalar(b"r3");
        let var_ma = verifier.allocate_scalar(b"ma");
        let var_za = verifier.allocate_scalar(b"za");
        let var_mf = verifier.allocate_scalar(b"mf");
        let var_zf = verifier.allocate_scalar(b"zf");
        let var_rnd = verifier.allocate_scalar(b"rnd");

        let var_H = verifier.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_Ce1 = verifier.allocate_point(b"B2_over_Ce1", (b.1 - Ce1).compress()).unwrap();
        let var_C1 = verifier.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_Ce2 = verifier.allocate_point(b"C2_over_Ce2", (c.1 - Ce2).compress()).unwrap();
        let var_neg_Gy1 = verifier.allocate_point(b"neg_Gy1", (-algm.params[G_Y1]).compress()).unwrap();
        let var_neg_Gy2 = verifier.allocate_point(b"neg_Gy2", (-algm.params[G_Y2]).compress()).unwrap();

        receive_forward(&mut verifier, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

        assert!(verifier.verify_compact(&proof).is_ok());
    }

    #[test]
    fn receive_proof_test_fwd() {
        let mut rng = OsRng{};
        let algm = AMAC::init(&mut rng);
        let plat_eg = ElGamal::new(&mut rng);
        let rec_eg = ElGamal::new(&mut rng);

        let (ma, mf) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let Ma = algm.params[G_M] * ma;
        let Mf = algm.params[G_M] * mf;
        let uid = RistrettoPoint::random(&mut rng);

        let src = plat_eg.enc(&mut rng, uid);
        let (rand_src, rnd) = plat_eg.rerand(&mut rng, src);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Mf);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) =  (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (Ca, Cf) = (algm.params[G_Y3] * za + Ma, algm.params[G_Y3] * zf + Mf);
        let (Ce1, Ce2) = (algm.params[G_Y1] * zf + src.0, algm.params[G_Y2]*zf + src.1);

        let mut transcript = Transcript::new(b"receive test");
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_E1, _) = prover.allocate_point(b"B2_over_E1", b.1 - src.0);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_E2, _) = prover.allocate_point(b"C2_over_E2", c.1 - src.1);

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
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_Ce1, _) = prover.allocate_point(b"B2_over_Ce1", b.1 - Ce1);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_Ce2, _) = prover.allocate_point(b"C2_over_Ce2", c.1 - Ce2);
        let (var_neg_Gy1, _) = prover.allocate_point(b"neg_Gy1", -algm.params[G_Y1]);
        let (var_neg_Gy2, _) = prover.allocate_point(b"neg_Gy2", -algm.params[G_Y2]);

        receive_forward(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

        let (_comms, blindings, _) = prover.prove_impl();
        let (new_resp, challenge) = prover.recompute_responses(proof.0, blindings);

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

        let var_H = verifier.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_E1 = verifier.allocate_point(b"B2_over_E1", (b.1 - src.0).compress()).unwrap();
        let var_C1 = verifier.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_E2 = verifier.allocate_point(b"C2_over_E2", (c.1 - src.1).compress()).unwrap();

        receive_author(&mut verifier, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        
        verifier.add_comms(proof.0, proof.1);

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

        let var_H = verifier2.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier2.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier2.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier2.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier2.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier2.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier2.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier2.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier2.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier2.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_Ce1 = verifier2.allocate_point(b"B2_over_Ce1", (b.1 - Ce1).compress()).unwrap();
        let var_C1 = verifier2.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_Ce2 = verifier2.allocate_point(b"C2_over_Ce2", (c.1 - Ce2).compress()).unwrap();
        let var_neg_Gy1 = verifier2.allocate_point(b"neg_Gy1", (-algm.params[G_Y1]).compress()).unwrap();
        let var_neg_Gy2 = verifier2.allocate_point(b"neg_Gy2", (-algm.params[G_Y2]).compress()).unwrap();

        receive_forward(&mut verifier2, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);
        
        verifier2.add_comms(challenge - proof.0, new_resp);
        verifier2.overall_check(challenge);

    }

    #[test]
    fn receive_proof_test_auth() {
        let mut rng = OsRng{};
        let algm = AMAC::init(&mut rng);
        let plat_eg = ElGamal::new(&mut rng);
        let rec_eg = ElGamal::new(&mut rng);

        let (ma, mf) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let Ma = algm.params[G_M] * ma;
        let Mf = algm.params[G_M] * mf;
        let uid = RistrettoPoint::random(&mut rng);

        let src = plat_eg.enc(&mut rng, uid);
        let (rand_src, rnd) = plat_eg.rerand(&mut rng, src);

        let (a, r1) = rec_eg.enc_w_rand(&mut rng, Ma);
        let (b, r2) = rec_eg.enc_w_rand(&mut rng, rand_src.0);
        let (c, r3) = rec_eg.enc_w_rand(&mut rng, rand_src.1);

        let (za, zf) =  (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (Ca, Cf) = (algm.params[G_Y3] * za + Ma, algm.params[G_Y3] * zf + Mf);
        let (Ce1, Ce2) = (algm.params[G_Y1] * zf + src.0, algm.params[G_Y2]*zf + src.1);

        let mut transcript = Transcript::new(b"receive test");
        let mut prover = OrProver::new(b"rec_proof", &mut transcript);

        let var_h = prover.allocate_scalar(b"h", rec_eg.sk);
        let var_r1 = prover.allocate_scalar(b"r1", r1);
        let var_r2 = prover.allocate_scalar(b"r2", r2);
        let var_r3 = prover.allocate_scalar(b"r3", r3);
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_E1, _) = prover.allocate_point(b"B2_over_E1", b.1 - src.0);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_E2, _) = prover.allocate_point(b"C2_over_E2", c.1 - src.1);

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
        let var_ma = prover.allocate_scalar(b"ma", ma);
        let var_za = prover.allocate_scalar(b"za", za);
        let var_mf = prover.allocate_scalar(b"mf", mf);
        let var_zf = prover.allocate_scalar(b"zf", zf);
        let var_rnd = prover.allocate_scalar(b"rnd", rnd);

        let (var_H, _) = prover.allocate_point(b"H", rec_eg.pk);
        let (var_G, _) = prover.allocate_point(b"G", algm.g);
        let (var_Y, _) = prover.allocate_point(b"Y", plat_eg.pk);
        let (var_Gm, _) = prover.allocate_point(b"Gm", algm.params[G_M]);
        let (var_Gy3, _) = prover.allocate_point(b"Gy3", algm.params[G_Y3]);
        let (var_Ca, _) = prover.allocate_point(b"Ca", Ca);
        let (var_Cm, _) = prover.allocate_point(b"Cm", Cf);
        let (var_A1, _) = prover.allocate_point(b"A1", a.0);
        let (var_A2, _) = prover.allocate_point(b"A2", a.1);
        let (var_B1, _) = prover.allocate_point(b"B1", b.0);
        let (var_B2_over_Ce1, _) = prover.allocate_point(b"B2_over_Ce1", b.1 - Ce1);
        let (var_C1, _) = prover.allocate_point(b"C1", c.0);
        let (var_C2_over_Ce2, _) = prover.allocate_point(b"C2_over_Ce2", c.1 - Ce2);
        let (var_neg_Gy1, _) = prover.allocate_point(b"neg_Gy1", -algm.params[G_Y1]);
        let (var_neg_Gy2, _) = prover.allocate_point(b"neg_Gy2", -algm.params[G_Y2]);

        receive_forward(&mut prover, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);

        let (sub_challenge, resp2, _commitments) = prover.sim_impl(&mut rng);
        let (resp1, challenge) = prover.finish_up(sub_challenge, proof.1, proof.2);

        let first_chall = challenge - sub_challenge;

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

        let var_H = verifier.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_E1 = verifier.allocate_point(b"B2_over_E1", (b.1 - src.0).compress()).unwrap();
        let var_C1 = verifier.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_E2 = verifier.allocate_point(b"C2_over_E2", (c.1 - src.1).compress()).unwrap();

        receive_author(&mut verifier, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_E1, var_C1, var_C2_over_E2);
        
        verifier.add_comms(first_chall, resp1);

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

        let var_H = verifier2.allocate_point(b"H", rec_eg.pk.compress()).unwrap();
        let var_G = verifier2.allocate_point(b"G", algm.g.compress()).unwrap();
        let var_Y = verifier2.allocate_point(b"Y", plat_eg.pk.compress()).unwrap();
        let var_Gm = verifier2.allocate_point(b"Gm", algm.params[G_M].compress()).unwrap();
        let var_Gy3 = verifier2.allocate_point(b"Gy3", algm.params[G_Y3].compress()).unwrap();
        let var_Ca = verifier2.allocate_point(b"Ca", Ca.compress()).unwrap();
        let var_Cm = verifier2.allocate_point(b"Cm", Cf.compress()).unwrap();
        let var_A1 = verifier2.allocate_point(b"A1", a.0.compress()).unwrap();
        let var_A2 = verifier2.allocate_point(b"A2", a.1.compress()).unwrap();
        let var_B1 = verifier2.allocate_point(b"B1", b.0.compress()).unwrap();
        let var_B2_over_Ce1 = verifier2.allocate_point(b"B2_over_Ce1", (b.1 - Ce1).compress()).unwrap();
        let var_C1 = verifier2.allocate_point(b"C1", c.0.compress()).unwrap();
        let var_C2_over_Ce2 = verifier2.allocate_point(b"C2_over_Ce2", (c.1 - Ce2).compress()).unwrap();
        let var_neg_Gy1 = verifier2.allocate_point(b"neg_Gy1", (-algm.params[G_Y1]).compress()).unwrap();
        let var_neg_Gy2 = verifier2.allocate_point(b"neg_Gy2", (-algm.params[G_Y2]).compress()).unwrap();

        receive_forward(&mut verifier2, var_h, var_r1, var_r2, var_r3, 
            var_ma, var_za, var_mf, var_zf, var_rnd,
            var_H, var_G, var_Y, var_Gm, var_Gy3, var_Ca, var_Cm, 
            var_A1, var_A2, var_B1, var_B2_over_Ce1, var_C1, var_C2_over_Ce2, 
            var_neg_Gy1, var_neg_Gy2);
        
        verifier2.add_comms(sub_challenge, resp2);
        verifier2.overall_check(challenge);

    }
}
