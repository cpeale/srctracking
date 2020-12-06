/*
* Proofs for scheme 2
*/
#![allow(non_snake_case)]

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

//redeeming a message
//TODO

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
    S1 = (y1 * A1 + y2 * B1 + y3 * C1 + r * G),
    S2 = (y1 * A2 + y2 * B2 + y3 * C2 + r * H + w * Gw + x0 * U + x1 * Ut)
}

define_proof! {
    testpf,
    "Simple Test Proof",
    (x),
    (A),
    (B):
    A = (x * B)
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
            eg.enc(&mut rng, E1),
            eg.enc(&mut rng, E2),
            eg.enc(&mut rng, M),
        );
        let ((t, U, ct), r) = algm.blind_issue(&mut rng, eg.pk, a, b, c);

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
        
        let (z, z_p, r) = (Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng));
        let z0 = - z * t;

        let Z = algm.i * z;
        let Cx1 = z * algm.params[G_X1] + U *t;
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
        let plat_Z = Cv - (algm.secrets[W] * algm.params[G_W] + algm.secrets[X_0] * Cx0 + algm.secrets[X_1] * Cx1 + algm.secrets[Y_1] * Ce1 + algm.secrets[Y_2] * Ce2 + algm.secrets[Y_3] * Cm);

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
}
