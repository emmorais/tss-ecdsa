//! Components for working with SLIP-0010.
//!
//! A description of SLIP-0010 can be found here: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>.
//! This is a method for achieving HD (hierarchical deterministic) wallets
//! whereby a single master key is  created - typically from a seed phrase - and
//! then used to generate a hierarchy of child keys. In  particular, this
//! library supports the generation of non-hardened child keys where the shifts
//! of a  key are publicly known. In the context of the ECDSA protocol,
//! supporting hardened children would  involve major modifications to the
//! existing code, including securely computing the output of a hash function on
//! an input that is privately shared among many parties.

//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

pub mod ckd;
