//! Types and functions related to non-interactive signing.[^cite]
//!
//! # High-level protocol description
//! The non-interactive signing protocol runs in two rounds:
//! - In the first round, parties calculate their share of a final signature
//! using a fresh presign record and the message that should be signed. This
//! value is then sent to all other parties.
//! - After receiving the shares from all other parties, the final signature
//! is reconstructed and all parties verify its correctness. If the verification
//! check passes, the signature is output.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf). Figure 8.
// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

pub(super) mod participant;
mod share;
