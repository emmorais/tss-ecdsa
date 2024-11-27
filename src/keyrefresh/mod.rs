//! Types and functions related to the key refresh sub-protocol.[^cite]
//!
//! This sub-protocol updates the private key shares and public key shares of
//! all parties. It can be used to regain security after compromise, provided
//! less than a threshold of parties have been corrupted. Note that this does
//! NOT change the ECDSA public key. Key refresh for thresholds other than n out
//! of n has not yet been implemented. *It is very important in practice that
//! after compromise AuxInfo is run before this protocol because this protocol
//! relies on AuxInfo to encrypt sensitive values*
//!
//! # High-level protocol description
//! The key refresh protocol runs in four rounds:
//! - In the first round, each participant generates an additive sharing of 0,
//!   i.e. x_1 + ... + x_n = 0. The party compute public key updates X_i based
//!   on the x_i values and commits to the public updates along with Schnorr
//!   pre-commitments for each update, represented here as A_i
//! - Once all commitment broadcasts have been received, the second round
//!   proceeds by each participant opening its commitment to all other
//!   participants.
//! - In the third round, each party verifies the correctness of commitments.
//!   They also ensure each party did create a correct additive sharing of 0 by
//!   checking if all the public updates sum to the identity point. Each party
//!   then computes schnorr proofs for their x_i updates using the
//!   pre-commitment values. Each party sends their share x_j to party P_j by
//!   encrypting it using the Paillier keys produced in AuxInfo. The Schnorr
//!   proofs are sent to all parties.
//! - Finally in the last round, all parties check that every schnorr update is
//!   correct and consistent with the precommitments commitments sent in round
//!   2. The private share updates are decrypted and also checked against the
//!   appropriate public key update. Each party computes their updated private
//!   key share by adding the updates they received to their current share x_i.
//!   All of the public key updates received are used to calculate the new
//!   public key shares of all other parties.
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf). Figure 6. Note that this does
//! not include the auxiliary information steps included in Figure 6.
// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

mod input;
mod keyrefresh_commit;
mod keyshare;
mod participant;

pub use participant::KeyrefreshParticipant;
// Same output as KeyGen.
pub use crate::keygen::Output;
