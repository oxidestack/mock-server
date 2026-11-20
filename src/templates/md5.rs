//! MD5, which `ring` does not offer (`CryptoTemplateHelper.md5`).

pub fn digest(bytes: &[u8]) -> [u8; 16] {
    use ::md5::Digest;
    ::md5::Md5::digest(bytes).into()
}
