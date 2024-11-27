// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements the auxiliary information protocol.[^cite]
//!
//! This protocol produces auxiliary parameters and public/private key pairs
//! that are needed to run key refresh and presign.
//!
//! # High-level protocol description
//! The auxinfo protocol runs in four rounds:
//! - In the first round, we generate an RSA modulus `N = pq`, alongside
//!   ring-Pedersen parameters `(s, t, λ)` such that `s = t^λ mod N`. We then
//!   produce a zero-knowledge proof `𝚷[prm]` that the ring-Pedersen parameters
//!   are correct. Finally, we commit to the tuple `(N, s, t, 𝚷[prm])` and
//!   broadcast this commitment.
//! - Once we have received all broadcasted commitments, in the second round we
//!   send a decommitment to the commited value in round one to all other
//!   participants.
//! - In the third round, we (1) check the validity of all the commitments plus
//!   the validity of the committed `𝚷[prm]` proof, and (2) generate the
//!   following proofs about our RSA modulus `N`: `𝚷[mod]`, which asserts the
//!   validity of `N` as a product of two primes, and a version of `𝚷[fac]` _for
//!   each other participant_ which asserts that neither factor of `N` is "too
//!   small". (The security of the `𝚷[fac]` proof depends on the correctness of
//!   the commitment parameters used to create it, so each other party requires
//!   it to be created with the parameters they provided in round two.) We then
//!   send `𝚷[mod]` alongside the appropriate `𝚷[fac]` to each other
//!   participant.
//! - Finally, in the last round we check the validity of the proofs from round
//!   three. If everything passes, we output the `(N, s, t)` tuples from all
//!   participants (including ourselves), alongside our own secret primes `(p,
//!   q)`.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf). Figure 6. Note that this does
//! not include the key-refresh steps included in Figure 6.

mod auxinfo_commit;
mod info;
mod output;
mod participant;
mod proof;

pub use info::{AuxInfoPrivate, AuxInfoPublic};
pub use output::Output;
pub use participant::AuxInfoParticipant;
