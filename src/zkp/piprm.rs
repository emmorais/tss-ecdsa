// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that [`RingPedersen`] parameters were
//! correctly constructed.
//!
//! In more detail, a valid [`RingPedersen`] object is compromised of a tuple
//! `(N, s, t)` such that `s = t^λ mod N` for some secret `λ`. This module
//! implements a zero-knowledge proof of this fact. The proof is defined in
//! Figure 17 of CGGMP[^cite].
//!
//! This proof utilizes the soundness parameter as specified
//! [here](crate::parameters::SOUNDNESS_PARAMETER). In addition, it uses a
//! standard Fiat-Shamir transformation to make the proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).

use crate::{
    errors::*,
    ring_pedersen::RingPedersen,
    utils::*,
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;

// Soundness parameter.
const SOUNDNESS: usize = crate::parameters::SOUNDNESS_PARAMETER;

/// Proof that externally provided [`RingPedersen`] parameters are constructed
/// correctly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiPrmProof {
    /// The commitments computed by the prover (`A_i` in the paper).
    commitments: Vec<BigNumber>,
    /// The randomized challenge bytes (`e_i` in the paper).
    challenge_bytes: Vec<u8>,
    /// The prover responses (`z_i` in the paper).
    responses: Vec<BigNumber>,
}

/// The prover's secret knowledge.
///
/// This is comprised of two components:
/// 1. The secret exponent used when generating the [`RingPedersen`] parameters.
/// 2. Euler's totient of [`RingPedersen::modulus`].
pub(crate) struct PiPrmSecret<'a> {
    /// The secret exponent that correlates [`RingPedersen`] parameters
    /// [`s`](RingPedersen::s) and [`t`](RingPedersen::t).
    exponent: &'a BigNumber,
    /// Euler's totient of [`RingPedersen::modulus`].
    totient: &'a BigNumber,
}

impl<'a> Debug for PiPrmSecret<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("piprm::PiPrmSecret")
            .field("exponent", &"[redacted]")
            .field("totient", &"[redacted]")
            .finish()
    }
}

impl<'a> PiPrmSecret<'a> {
    /// Collect the secret knowledge for proving [`PiPrmProof`].
    pub(crate) fn new(exponent: &'a BigNumber, totient: &'a BigNumber) -> Self {
        Self { exponent, totient }
    }
}

/// Generates challenge bytes from the proof transcript using the Fiat-Shamir
/// transform. Used by the prover and the verifier.
fn generate_challenge_bytes(
    input: &RingPedersen,
    commitments: &[BigNumber],
    context: &impl ProofContext,
    transcript: &mut Transcript,
) -> Result<Vec<u8>> {
    transcript.append_message(b"PiPrm ProofContext", &context.as_bytes()?);
    transcript.append_message(b"PiPrm Common input", &serialize!(&input)?);
    transcript.append_message(b"PiPrm Commitments", &serialize!(&commitments)?);
    // Extract challenge bytes from the transcript.
    let mut challenges = [0u8; SOUNDNESS];
    transcript.challenge_bytes(b"Challenges", challenges.as_mut_slice());
    Ok(challenges.into())
}

impl Proof for PiPrmProof {
    type CommonInput<'a> = &'a RingPedersen;
    type ProverSecret<'a> = PiPrmSecret<'a>;
    #[cfg_attr(feature = "flame_it", flame("PiPrmProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample secret exponents `a_i ← Z[ɸ(N)]`.
        let secret_exponents: Vec<_> =
            std::iter::repeat_with(|| random_positive_bn(rng, secret.totient))
                .take(SOUNDNESS)
                .collect();
        // Compute commitments values `A_i = t^{a_i} mod N`.
        let commitments = secret_exponents
            .iter()
            .map(|a| modpow(input.t(), a, input.modulus()))
            .collect::<Vec<_>>();
        let challenge_bytes = generate_challenge_bytes(input, &commitments, context, transcript)?;
        // Compute challenge responses `z_i = a_i + e_i λ mod ɸ(N)`.
        let responses = challenge_bytes
            .iter()
            .zip(secret_exponents)
            .map(|(e, a)| {
                if e % 2 == 1 {
                    a.modadd(secret.exponent, secret.totient)
                } else {
                    a
                }
            })
            .collect();

        Ok(Self {
            commitments,
            challenge_bytes,
            responses,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiPrmProof"))]
    fn verify(
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Check that all the lengths equal the soundness parameter.
        if self.commitments.len() != SOUNDNESS
            || self.challenge_bytes.len() != SOUNDNESS
            || self.responses.len() != SOUNDNESS
        {
            error!("length of values provided does not match soundness parameter");
            return Err(InternalError::ProtocolError(None));
        }
        let challenges = generate_challenge_bytes(input, &self.commitments, context, transcript)?;
        // Check Fiat-Shamir consistency.
        if challenges != self.challenge_bytes.as_slice() {
            error!("Fiat-Shamir does not verify");
            return Err(InternalError::ProtocolError(None));
        }

        let is_sound = challenges
            .into_iter()
            .zip(&self.responses)
            .zip(&self.commitments)
            .all(|((e, z), a)| {
                // Verify that `t^{z_i} = {A_i} * s^{e_i} mod N`.
                let lhs = modpow(input.t(), z, input.modulus());
                let rhs = if e % 2 == 1 {
                    a.modmul(input.s(), input.modulus())
                } else {
                    a.clone()
                };
                lhs == rhs
            });

        if !is_sound {
            error!("response validation check failed");
            return Err(InternalError::ProtocolError(None));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paillier::DecryptionKey, utils::testing::init_testing, zkp::BadContext};
    use rand::Rng;

    /// Make a transcript for PiPrmProof.
    fn transcript() -> Transcript {
        Transcript::new(b"PiPrmProof")
    }

    fn random_ring_pedersen_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(RingPedersen, PiPrmProof, BigNumber, BigNumber)> {
        let (sk, _, _) = DecryptionKey::new(rng).unwrap();
        let (scheme, lambda, totient) = RingPedersen::extract(&sk, rng)?;
        let secrets = PiPrmSecret::new(&lambda, &totient);

        let proof = PiPrmProof::prove(&scheme, secrets, &(), &mut transcript(), rng)?;
        Ok((scheme, proof, lambda, totient))
    }

    #[test]
    fn piprm_proof_verifies() -> Result<()> {
        let mut rng = init_testing();
        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;
        proof.verify(&input, &(), &mut transcript())
    }

    #[test]
    fn piprm_proof_context_must_be_correct() -> Result<()> {
        let context = BadContext {};
        let mut rng = init_testing();
        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;

        let result = proof.verify(&input, &context, &mut transcript());
        assert!(result.is_err());
        Ok(())
    }
    #[test]
    fn piprm_proof_serializes() -> Result<()> {
        let mut rng = init_testing();
        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;
        let serialized = bincode::serialize(&proof).unwrap();
        let deserialized: PiPrmProof = bincode::deserialize(&serialized).unwrap();
        assert_eq!(serialized, bincode::serialize(&deserialized).unwrap());

        deserialized.verify(&input, &(), &mut transcript())
    }

    #[test]
    fn incorrect_lengths_fails() -> Result<()> {
        let mut rng = init_testing();
        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;
        // Validate that the proof is okay.
        assert!(proof.clone().verify(&input, &(), &mut transcript()).is_ok());
        // Test that too short vectors fail.
        {
            let mut bad_proof = proof.clone();
            bad_proof.commitments = bad_proof
                .commitments
                .into_iter()
                .take(SOUNDNESS - 1)
                .collect();
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        {
            let mut bad_proof = proof.clone();
            bad_proof.challenge_bytes = bad_proof
                .challenge_bytes
                .into_iter()
                .take(SOUNDNESS - 1)
                .collect();
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        {
            let mut bad_proof = proof.clone();
            bad_proof.responses = bad_proof
                .responses
                .into_iter()
                .take(SOUNDNESS - 1)
                .collect();
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        // Test that too long vectors fail.
        {
            let mut bad_proof = proof.clone();
            bad_proof
                .commitments
                .push(random_positive_bn(&mut rng, input.modulus()));
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        {
            let mut bad_proof = proof.clone();
            bad_proof.challenge_bytes.push(rng.gen::<u8>());
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        {
            let mut bad_proof = proof;
            bad_proof
                .responses
                .push(random_positive_bn(&mut rng, input.modulus()));
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        Ok(())
    }

    #[test]
    fn bad_secret_exponent_fails() -> Result<()> {
        let mut rng = init_testing();
        let (input, proof, _, totient) = random_ring_pedersen_proof(&mut rng)?;
        let bad_lambda = random_positive_bn(&mut rng, &totient);
        let secrets = PiPrmSecret::new(&bad_lambda, &totient);

        let bad_proof = PiPrmProof::prove(&input, secrets, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());

        // Validate that the original proof is okay.
        assert!(proof.verify(&input, &(), &mut transcript()).is_ok());

        Ok(())
    }

    #[test]
    fn incorrect_ring_pedersen_fails() -> Result<()> {
        let mut rng = init_testing();

        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;
        let (bad_input, _, _, _) = random_ring_pedersen_proof(&mut rng)?;

        assert!(proof
            .clone()
            .verify(&bad_input, &(), &mut transcript())
            .is_err());

        // Validate that the original proof is okay.
        assert!(proof.verify(&input, &(), &mut transcript()).is_ok());
        Ok(())
    }

    #[test]
    fn invalid_values_fails() -> Result<()> {
        let mut rng = init_testing();

        let (input, proof, _, _) = random_ring_pedersen_proof(&mut rng)?;

        for i in 0..SOUNDNESS {
            let mut bad_proof = proof.clone();
            bad_proof.commitments[i] = random_positive_bn(&mut rng, input.modulus());
            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        for i in 0..SOUNDNESS {
            let mut bad_proof = proof.clone();
            let valid = bad_proof.challenge_bytes[i];
            while bad_proof.challenge_bytes[i] == valid {
                bad_proof.challenge_bytes[i] = rng.gen::<u8>();
            }

            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        for i in 0..SOUNDNESS {
            let mut bad_proof = proof.clone();
            bad_proof.responses[i] = random_positive_bn(&mut rng, input.modulus());

            assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        }
        // Validate that the original proof is okay.
        assert!(proof.verify(&input, &(), &mut transcript()).is_ok());

        Ok(())
    }
}
