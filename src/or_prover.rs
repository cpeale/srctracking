/* Modified prover from dalek-cryptography/zkp
* to work with ORs
*/

use rand::thread_rng;
use rand::rngs::OsRng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

use zkp::toolbox::{SchnorrCS, TranscriptProtocol};
use zkp::{BatchableProof, CompactProof, Transcript};

pub struct OrProof {
        /// The Overall Fiat-Shamir challenge.
        pub challenge: Scalar,
        /// The challenge for the first statement
        pub statement_challenge: Scalar,
        /// The prover's responses to the first statement, one per secret variable.
        pub responses1: Vec<Scalar>,
        /// The prover's responses to the first statement, one per secret variable.
        pub responses2: Vec<Scalar>,
}

/// Used to create proofs.
///
/// To use a [`OrProver`], first construct one using [`OrProver::new()`],
/// supplying a domain separation label, as well as the transcript to
/// operate on.
///
/// Then, allocate and assign secret ([`OrProver::allocate_scalar`]) and
/// public ([`OrProver::allocate_point`]) variables, and use those
/// variables to define the proof statements.
///
/// Finally, use [`OrProver::prove_compact`] or
/// [`OrProver::prove_batchable`] to consume the prover and produce a
/// proof
pub struct OrProver<'a> {
    //transcript: &'a mut Transcript,
    transcript: &'a mut Transcript,
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

/// A secret variable used during proving.
#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
/// A public variable used during proving.
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a> OrProver<'a> {
    /// Construct a new prover.  The `proof_label` disambiguates proof
    /// statements.
    pub fn new(proof_label: &'static [u8], transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(proof_label);
        OrProver {
            transcript,
            scalars: Vec::default(),
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    /// Allocate and assign a secret variable with the given `label`.
    pub fn allocate_scalar(&mut self, label: &'static [u8], assignment: Scalar) -> ScalarVar {
        self.transcript.append_scalar_var(label);
        self.scalars.push(assignment);
        ScalarVar(self.scalars.len() - 1)
    }

    /// Allocate and assign a public variable with the given `label`.
    ///
    /// The point is compressed to be appended to the transcript, and
    /// the compressed point is returned to allow reusing the result
    /// of that computation; it can be safely discarded.
    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: RistrettoPoint,
    ) -> (PointVar, CompressedRistretto) {
        let compressed = self.transcript.append_point_var(label, &assignment);
        self.points.push(assignment);
        self.point_labels.push(label);
        (PointVar(self.points.len() - 1), compressed)
    }

    /// The compact and batchable proofs differ only by which data they store.
    pub fn prove_impl(&mut self) -> (Vec<CompressedRistretto>, Vec<Scalar>, Vec<Scalar>) {
        // Construct a TranscriptRng
        let mut rng_builder = self.transcript.build_rng();
        for scalar in &self.scalars {
            rng_builder = rng_builder.rekey_with_witness_bytes(b"", scalar.as_bytes());
        }
        let mut transcript_rng = rng_builder.finalize(&mut thread_rng());

        // Generate a blinding factor for each secret variable
        let blindings = self
            .scalars
            .iter()
            .map(|_| Scalar::random(&mut transcript_rng))
            .collect::<Vec<Scalar>>();

        // Commit to each blinded LHS
        let mut commitments = Vec::with_capacity(self.constraints.len());
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc.iter().map(|(sc_var, _pt_var)| blindings[sc_var.0]),
                rhs_lc.iter().map(|(_sc_var, pt_var)| self.points[pt_var.0]),
            );
            let encoding = self
                .transcript
                .append_blinding_commitment(self.point_labels[lhs_var.0], &commitment);

            commitments.push(encoding);
        }

        // Obtain a scalar challenge and compute responses
        //let challenge = self.transcript.get_challenge(b"chal");
        (commitments, blindings, self.scalars.to_vec())
    }

    pub fn recompute_responses(&mut self, subchallenge: Scalar, blindings: Vec<Scalar>) -> (Vec<Scalar>, Scalar) {
        let challenge = self.transcript.get_challenge(b"chal");
        let second_chall = challenge - subchallenge;
        (Iterator::zip(self.scalars.iter(), blindings.iter())
            .map(|(s, b)| s * second_chall + b)
            .collect::<Vec<Scalar>>(), challenge)
    }

    pub fn finish_up(&mut self, subchallenge: Scalar, blindings: Vec<Scalar>, scalars: Vec<Scalar>) -> (Vec<Scalar>, Scalar) {
        let challenge = self.transcript.get_challenge(b"chal");
        let second_chall = challenge - subchallenge;
        (Iterator::zip(scalars.iter(), blindings.iter())
            .map(|(s, b)| s * second_chall + b)
            .collect::<Vec<Scalar>>(), challenge)
    }

    /// The compact and batchable proofs differ only by which data they store.
    pub fn sim_impl(&mut self, mut rng: &mut OsRng) -> (Scalar, Vec<Scalar>, Vec<CompressedRistretto>) {
        // Generate a random response for each secret variable
        let responses = self
            .scalars
            .iter()
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<Scalar>>();

        //get random challenge
        let challenge = Scalar::random(&mut rng);

        //re-compute commitments
        let minus_c = -challenge;
        let mut commitments = Vec::with_capacity(self.constraints.len());
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc
                    .iter()
                    .map(|(sc_var, _pt_var)| responses[sc_var.0])
                    .chain(std::iter::once(minus_c)),
                rhs_lc
                    .iter()
                    .map(|(_sc_var, pt_var)| self.points[pt_var.0])
                    .chain(std::iter::once(self.points[lhs_var.0])),
            );

            let encoding = self
                .transcript
                .append_blinding_commitment(self.point_labels[lhs_var.0], &commitment);

            commitments.push(encoding);
        }

        //(challenge, responses, commitments)
        (challenge, responses, commitments)
    }

}

impl<'a> SchnorrCS for OrProver<'a> {
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
    fn sim_chain() {
        let mut rng = OsRng{};
        let B = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(B.compress().as_bytes());

        let mut transcript = Transcript::new(b"DLEQTest");

        let (proof, cmpr_A, cmpr_G) = {
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

            let (commitments, blindings, scalars) = prover.prove_impl();
            let (new_resp, challenge) = prover.recompute_responses(proof.0, blindings.to_vec());

            (challenge, commitments, new_resp, cmpr_A, cmpr_G)
        };


    }
}
