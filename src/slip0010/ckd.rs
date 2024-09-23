

pub struct ExtendedPrivateKey {
    pub(crate) depth: u8,
    pub(crate) parent_fingerprint: [u8; 4],
    pub(crate) child_number: u32,
    pub(crate) chain_code: [u8; 32],
    pub(crate) private_key: [u8; 32],
}

pub struct ExtendedPublicKey {
    pub(crate) depth: u8,
    pub(crate) parent_fingerprint: [u8; 4],
    pub(crate) child_number: u32,
    pub(crate) chain_code: [u8; 32],
    pub(crate) public_key: [u8; 33],
}