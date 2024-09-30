//! Utilities for Child Key Derivation (CKD) according to SLIP-0010.

use crate::{errors::CallerError, utils::bn_to_scalar};
use generic_array::{
    typenum::{U32, U64},
    GenericArray,
};
use hmac::Mac;
use k256::{ecdsa::VerifyingKey, Scalar};
use libpaillier::unknown_order::BigNumber;

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

    /// Derive master key from seed.
    pub fn derive_master_key(seed: &[u8]) -> (Scalar, [u8; 32]) {
        let hmac = HmacSha512::new_from_slice("Bitcoin seed".as_bytes())
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac.clone().chain_update(seed).finalize().into_bytes();
        let (i_left, i_right) = Self::split_into_two_halfes(&i);
        (
            bn_to_scalar(&BigNumber::from_slice(*i_left)).unwrap(),
            (*i_right).into(),
        )
    }

    /// Derive a child key from this input.
    pub fn derive(&self) -> (Scalar, [u8; 32]) {
        let mut chain_code = [0u8; 32];
        let mut shift_result = Scalar::ZERO;
        let mut counter: u8 = 0;

        while shift_result.is_zero().into() {
            let mut shift_input = Vec::new();
            shift_input.extend(self.public_key.to_sec1_bytes().iter());
            shift_input.extend(self.chain_code.to_vec());
            shift_input.extend(self.index.to_le_bytes().to_vec());
            shift_input.extend(counter.to_le_bytes().to_vec());

            let hmac = HmacSha512::new_from_slice("Bitcoin seed".as_bytes())
                .expect("this never fails: hmac can handle keys of any size");
            let i = hmac
                .clone()
                .chain_update(shift_input)
                .finalize()
                .into_bytes();
            let (i_left, new_chain_code) = Self::split_into_two_halfes(&i);
            chain_code = (*new_chain_code).into();

            let shift = i_left;
            shift_result = bn_to_scalar(&BigNumber::from_slice(*shift)).unwrap();
            counter += 1;
        }

        (shift_result, chain_code)
    }

    /// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R =
    /// I[32..]`
    fn split_into_two_halfes(
        i: &GenericArray<u8, U64>,
    ) -> (&GenericArray<u8, U32>, &GenericArray<u8, U32>) {
        generic_array::sequence::Split::split(i)
    }
}

// Unit tests
// test vector taken from: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

/* Seed (hex): 000102030405060708090a0b0c0d0e0f

Chain m
chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
private: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
public: 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2 */

#[test]
fn test_derive_master_key() {
    let seed = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let (master_key, chain_code) = CKDInput::derive_master_key(&seed);
    assert_eq!(
        master_key.to_bytes(),
        [
            0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93,
            0xc9, 0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17,
            0xc8, 0x43, 0x6b, 0x35
        ]
        .into()
    );
    assert_eq!(
        chain_code,
        [
            0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e,
            0xac, 0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff,
            0xed, 0x37, 0xd5, 0x08
        ]
    );
}
