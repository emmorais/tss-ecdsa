// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements the presign protocol, which is the offline
//! pre-processing phase when doing non-interactive signing. [^cite]
//!
//! # High-level protocol description
//! The goal of the presign protocol is to generate [`PresignRecord`]s for all
//! protocol participants. The protocol proceeds in four rounds, and utilizes
//! the [`KeySharePrivate`](crate::keygen::KeySharePrivate) (`xᵢ` in the paper)
//! constructed during the [`keygen`](crate::keygen::KeygenParticipant)
//! protocol.
//!
//! 1. In round one, each participant generates two values corresponding to a
//!    "key share" (`kᵢ` in the paper) and an "exponent share" (`ɣᵢ` in the
//!    paper). At the end of a successful run of the protocol, each participant
//!    constructs a value equal to `(∑ kᵢ) (∑ ɣᵢ)`, which is used to generate
//!    the [`PresignRecord`].
//!
//!    The participant then encrypts these values and constructs a
//!    zero-knowledge proof that the ciphertext (`Kᵢ` in the paper)
//!    corresponding to its key share `kᵢ` was encrypted correctly. This proof
//!    needs to be done once per-participant (that is, if there are `n` total
//!    participants then each participant generates `n-1` such proofs, one for
//!    each other participant).
//!
//! 2. Once each participant has received these values and proofs from all other
//!    participants, it verifies the proofs. If those all pass, it proceeds to
//!    round two. In this round, each participant `i`, for each other
//!    participant `j`, creates the following values:
//!
//!    - An exponentiation of its exponent share: `Γᵢ = g^{ɣᵢ}`.
//!    - A "mask" of its exponent share, roughly equal to `(ɣᵢ · Kⱼ)`.
//!    - A "mask" of its [`KeySharePrivate`](crate::keygen::KeySharePrivate),
//!      roughly equal to `(xᵢ · Kⱼ)`.
//!
//!    It also attaches relevant zero-knowledge proofs (per participant) that
//!    the above computations were done correctly.
//!
//! 3. Once each participant has received these values and proofs from all other
//!    participants, it verifies the proofs. If those all pass, it proceeds to
//!    round three. In this round, each participant creates the following
//!    values:
//!
//!    - A multiplication of all the exponentiated exponent shares: `Γ = ∏ᵢ Γᵢ =
//!      g^{∑ ɣᵢ}`.
//!    - An exponentiation of its key share by this new value: `Δᵢ = Γ^{kᵢ} =
//!      g^{kᵢ ∑ ɣᵢ}`.
//!    - An "unmasked" exponent share summation multiplied by its own key share:
//!      `δᵢ = (∑ ɣⱼ) kᵢ`.
//!    - An "unmasked" [`KeySharePrivate`](crate::keygen::KeySharePrivate)
//!      summation multiplied by its own key share: `χᵢ = (∑ xⱼ) kᵢ`.
//!
//!    It also attaches a zero-knowledge proof (per participant) that the value
//!    `Δᵢ` was computed correctly.
//!
//! 4. Once each participant has received these values and proofs from all other
//!    participants, it verifies the proofs. If those all pass, it proceeds to
//!    round four. In this round, each participant combines the `δᵢ` values and
//!    checks that `g^{∑ δᵢ} = ∏ᵢ Δᵢ`, which essentially checks that the value
//!    `g^{ɣ k}` was computed correctly, where `ɣ = ∑ ɣᵢ` and `k = ∑ kᵢ`.
//!    (Recall that `g^{ɣ k}` was the value we were aiming to compute in the
//!    first place.)
//!
//!    If this holds, each participant can output its [`PresignRecord`] as the
//!    tuple `(Γ^{(ɣ k)^{-1}}, kᵢ, χᵢ)`.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf). Figure 7.

mod input;
mod participant;
mod record;
mod round_one;
mod round_three;
mod round_two;

pub use input::Input;
pub use participant::PresignParticipant;
pub use record::PresignRecord;
