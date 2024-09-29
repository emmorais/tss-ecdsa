//! Utilities for Child Key Derivation (CKD) according to SLIP-0010.

use crate::{errors::CallerError, utils::bn_to_scalar};
use k256::{ecdsa::VerifyingKey, Scalar};
use libpaillier::unknown_order::BigNumber;
use hmac::Mac;
use generic_array::{
    typenum::{U32, U64},
    GenericArray,
};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

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
        let mut shift_result = Scalar::ZERO;
        let mut counter: u8 = 0;

        while shift_result.is_zero().into() {
            let mut shift_input = Vec::new();
            shift_input.extend(self.public_key.to_sec1_bytes().iter());
            shift_input.extend(self.chain_code.to_vec());
            shift_input.extend(self.index.to_le_bytes().to_vec());
            shift_input.extend(counter.to_le_bytes().to_vec());
            
            let hmac = HmacSha512::new_from_slice("Bitcoiun seed".as_bytes())
                .expect("this never fails: hmac can handle keys of any size");
            let i = hmac.clone().chain_update(shift_input).finalize().into_bytes(); 
            let (i_left, _i_right) = Self::split_into_two_halfes(&i);
            
            let shift = i_left;
            shift_result =
                bn_to_scalar(&BigNumber::from_slice(*shift)).unwrap();
            counter += 1;
        }

        shift_result
    }
    
    /// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R = I[32..]`
    fn split_into_two_halfes(
        i: &GenericArray<u8, U64>,
    ) -> (&GenericArray<u8, U32>, &GenericArray<u8, U32>) {
        generic_array::sequence::Split::split(i)
    }
}
