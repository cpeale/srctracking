/*
 * Modified Verifier from dalek-cryptography/zkp that can do a single OR of two statements
 */

use rand::{thread_rng, Rng};
use std::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use zkp::toolbox::{SchnorrCS, TranscriptProtocol};
use zkp::{BatchableProof, CompactProof, ProofError, Transcript};
use curve25519_dalek::traits::MultiscalarMul;

/// Used to produce verification results.
///
/// To use a [`Verifier`], first construct one using [`Verifier::new()`],
/// supplying a domain separation label, as well as the transcript to
/// operate on.
///
/// Then, allocate secret ([`Verifier::allocate_scalar`]) variables
/// and allocate and assign public ([`Verifier::allocate_point`])
/// variables, and use those variables to define the proof statements.
/// Note that no assignments to secret variables are assigned, since
/// the verifier doesn't know the secrets.
///
/// Finally, use [`Verifier::verify_compact`] or
/// [`Verifier::verify_batchable`] to consume the verifier and produce
/// a verification result.
pub struct OrVerifier<'a> {
    transcript: &'a mut Transcript,
    num_scalars: usize,
    points: Vec<CompressedRistretto>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

/// A secret variable used during verification.
///
/// Note that this variable is only a placeholder; it has no
/// assignment, because the verifier doesn't know the secrets.
#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
/// A public variable used during verification.
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a> OrVerifier<'a> {
    /// Construct a verifier for the proof statement with the given
    /// `proof_label`, operating on the given `transcript`.
    pub fn new(proof_label: &'static [u8], transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(proof_label);
        OrVerifier {
            transcript,
            num_scalars: 0,
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    /// Allocate a placeholder scalar variable, without an assignment.
    pub fn allocate_scalar(&mut self, label: &'static [u8]) -> ScalarVar {
        self.transcript.append_scalar_var(label);
        self.num_scalars += 1;
        ScalarVar(self.num_scalars - 1)
    }

    /// Attempt to allocate a point variable, or fail verification if
    /// the assignment is invalid.
    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: CompressedRistretto,
    ) -> Result<PointVar, ProofError> {
        self.transcript
            .validate_and_append_point_var(label, &assignment)?;
        self.points.push(assignment);
        self.point_labels.push(label);
        Ok(PointVar(self.points.len() - 1))
    }

    pub fn add_comms(&mut self, challenge: Scalar, responses: Vec<Scalar>) {
        // Check that there are as many responses as secret variables
        //if responses.len() != self.num_scalars {
         //   return Err(ProofError::VerificationFailure);
        //}
        assert_eq!(responses.len(), self.num_scalars);

        // Decompress all parameters or fail verification.
        let points = self
            .points
            .iter()
            .map(|pt| pt.decompress())
            .collect::<Option<Vec<RistrettoPoint>>>()
            .unwrap();

        // Recompute the prover's commitments based on their claimed challenge value:
        let minus_c = -challenge;
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc
                    .iter()
                    .map(|(sc_var, _pt_var)| responses[sc_var.0])
                    .chain(iter::once(minus_c)),
                rhs_lc
                    .iter()
                    .map(|(_sc_var, pt_var)| points[pt_var.0])
                    .chain(iter::once(points[lhs_var.0])),
            );

            self.transcript
                .append_blinding_commitment(self.point_labels[lhs_var.0], &commitment);
        }
    }
    pub fn overall_check(&mut self, rep_challenge: Scalar) {
        let challenge = self.transcript.get_challenge(b"chal");

        assert_eq!(challenge, rep_challenge);
    }
}

impl<'a> SchnorrCS for OrVerifier<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}

#[cfg(test)]
mod tests {
    extern crate bincode;
    extern crate curve25519_dalek;
    extern crate sha2;
    extern crate zkp;

    use self::sha2::Sha512;

    use curve25519_dalek::constants as dalek_constants;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    use crate::or_prover::OrProver;
    use zkp::toolbox::{
        //batch_verifier::BatchVerifier, prover::Prover,
        verifier::Verifier,
        SchnorrCS,
    };
    use zkp::Transcript;
    use super::*;

    fn dleq_statement<CS: SchnorrCS>(
        cs: &mut CS,
        x: CS::ScalarVar,
        A: CS::PointVar,
        G: CS::PointVar,
        B: CS::PointVar,
        H: CS::PointVar,
    ) {
        cs.constrain(A, vec![(x, B)]);
        cs.constrain(G, vec![(x, H)]);
    }

    #[test]
    fn first_sim_verif() {
        let mut rng = OsRng {};
        let B = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(B.compress().as_bytes());

        let mut transcript = Transcript::new(b"DLEQTest");

        let (proof, cmpr_A, cmpr_G) = {
            let x = Scalar::from(89327492234u64);

            let A = B; //wrong assignments for A and G
            let G = H;

            let mut prover = OrProver::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_B, _) = prover.allocate_point(b"B", B);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_G, cmpr_G) = prover.allocate_point(b"G", G);

            dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

            (prover.sim_impl(&mut rng), cmpr_A, cmpr_G)
        };

        let (challenge, comms, resps, cmpr_A2, cmpr_G2) = {
            let x = Scalar::from(89327492234u64);

            let A = B * x;
            let G = H * x;

            let mut prover = OrProver::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_B, _) = prover.allocate_point(b"B", B);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_G, cmpr_G) = prover.allocate_point(b"G", G);

            dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

            let (commitments, blindings, _) = prover.prove_impl();
            let (new_resp, challenge) = prover.recompute_responses(proof.0, blindings);
            (challenge, commitments, new_resp, cmpr_A, cmpr_G)
        };

        let mut transcript = Transcript::new(b"DLEQTest");
        let mut verifier = OrVerifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier.allocate_scalar(b"x");
        let var_B = verifier.allocate_point(b"B", B.compress()).unwrap();
        let var_H = verifier.allocate_point(b"H", H.compress()).unwrap();
        let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
        let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();

        dleq_statement(&mut verifier, var_x, var_A, var_G, var_B, var_H);

        verifier.add_comms(proof.0, proof.1);

        let mut verifier2 = OrVerifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier2.allocate_scalar(b"x");
        let var_B = verifier2.allocate_point(b"B", B.compress()).unwrap();
        let var_H = verifier2.allocate_point(b"H", H.compress()).unwrap();
        let var_A = verifier2.allocate_point(b"A", cmpr_A2).unwrap();
        let var_G = verifier2.allocate_point(b"G", cmpr_G2).unwrap();

        dleq_statement(&mut verifier2, var_x, var_A, var_G, var_B, var_H);

        verifier2.add_comms(challenge - proof.0, resps);

        verifier2.overall_check(challenge);
    }

    #[test]
    fn second_sim_verif() {
        let mut rng = OsRng {};
        let B = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(B.compress().as_bytes());

        let mut transcript = Transcript::new(b"DLEQTest");

        let (proof, cmpr_A, cmpr_G) = {
            let x = Scalar::from(89327492234u64);

            let A = B*x; 
            let G = H*x;

            let mut prover = OrProver::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_B, _) = prover.allocate_point(b"B", B);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_G, cmpr_G) = prover.allocate_point(b"G", G);

            dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

            (prover.prove_impl(), cmpr_A, cmpr_G)
        };

        let (challenge, sub_challenge, resp1, resp2, cmpr_A2, cmpr_G2) = {
            let x = Scalar::from(89327492234u64);

            let A = B; //wrong assignments for A and G
            let G = H;

            let mut prover = OrProver::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_B, _) = prover.allocate_point(b"B", B);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_G, cmpr_G) = prover.allocate_point(b"G", G);

            dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

            let (challenge, resp2, commitments) = prover.sim_impl(&mut rng);
            let (resp1, overall_chall) = prover.finish_up(challenge, proof.1, proof.2);
            (overall_chall, challenge, resp1, resp2, cmpr_A, cmpr_G)
        };

        let first_chall = challenge - sub_challenge;

        let mut transcript = Transcript::new(b"DLEQTest");
        let mut verifier = OrVerifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier.allocate_scalar(b"x");
        let var_B = verifier.allocate_point(b"B", B.compress()).unwrap();
        let var_H = verifier.allocate_point(b"H", H.compress()).unwrap();
        let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
        let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();

        dleq_statement(&mut verifier, var_x, var_A, var_G, var_B, var_H);

        verifier.add_comms(first_chall, resp1);

        let mut verifier2 = OrVerifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier2.allocate_scalar(b"x");
        let var_B = verifier2.allocate_point(b"B", B.compress()).unwrap();
        let var_H = verifier2.allocate_point(b"H", H.compress()).unwrap();
        let var_A = verifier2.allocate_point(b"A", cmpr_A2).unwrap();
        let var_G = verifier2.allocate_point(b"G", cmpr_G2).unwrap();

        dleq_statement(&mut verifier2, var_x, var_A, var_G, var_B, var_H);

        verifier2.add_comms(sub_challenge, resp2);

        verifier2.overall_check(challenge);
    }
}
