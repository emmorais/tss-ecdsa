//! Utilities for Child Key Derivation (CKD) according to SLIP-0010.

use crate::{errors::CallerError, utils::bn_to_scalar};
use k256::{ecdsa::VerifyingKey, Scalar};
use libpaillier::unknown_order::BigNumber;
use sha3::{Digest, Keccak256};

/// Represents the input to the CKD function.
#[derive(Debug, Clone)]
pub struct CKDInput {
    public_key: VerifyingKey,
    chain_code: [u8; 32],
    index: u32,
}

impl CKDInput {
    /// Create a new CKDInput.
    pub fn new(
        public_key: VerifyingKey,
        chain_code: [u8; 32],
        index: u32,
    ) -> Result<Self, CallerError> {
        if index == 0 || index >= 0x80000000 {
            Err(CallerError::WrongIndex)
        } else {
            Ok(Self {
                public_key,
                chain_code,
                index,
            })
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.public_key
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Derive a child key from this input.
    pub fn derive(&self) -> Scalar {
        /*let mut data = [0u8; 37];
        data[..33].copy_from_slice(&self.public_key.to_bytes());
        data[33..].copy_from_slice(&self.index.to_be_bytes());

        let hmac = Hmac::<Sha256>::new_varkey(&self.chain_code)?;
        let result = hmac.update(&data).finalize().into_bytes();

        let mut child_public_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&result[..33])?;
        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&result[33..]);

        Ok(Self::new(child_public_key, child_chain_code, self.index))*/

        let mut shift_input = Vec::new();
        shift_input.extend(self.public_key.to_sec1_bytes().iter());
        shift_input.extend(self.chain_code.to_vec());
        shift_input.extend(self.index.to_le_bytes().to_vec());

        let shift = Keccak256::new_with_prefix(shift_input);
        bn_to_scalar(&BigNumber::from_slice(&shift.clone().finalize()[..])).unwrap()
    }
}
