//! Signing keys shared by the mock identity providers (`org.mockserver.keys`): `AsymmetricKeyPairAlgorithm`, key
//! generation (`AsymmetricKeyGenerator`), private keys read from PEM (`PEMToFile.privateKeyFromPEM`), and signatures
//! in the raw forms JWS and XML-DSig use (PKCS#1 v1.5; ECDSA `r || s`). ECDSA signs a prehash, so a key signs with
//! any of the three digests, as the JDK's `SHAnnnwithECDSA` does whatever the curve.

use p256::ecdsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use crate::recorded::Failure;

/// A new RSA key of `bits` as PKCS#8 DER: from aws-lc for 2048, 3072 and 4096 bits (two to five times faster than the
/// `rsa` crate's prime search), from the `rsa` crate for any other size (none is asked for today).
pub fn rsa_pkcs8(bits: usize) -> Result<Vec<u8>, String> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::KeySize;
    let size = match bits {
        2048 => KeySize::Rsa2048,
        3072 => KeySize::Rsa3072,
        4096 => KeySize::Rsa4096,
        _ => {
            use rsa::pkcs8::EncodePrivateKey;
            let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits).map_err(|e| e.to_string())?;
            return Ok(key.to_pkcs8_der().map_err(|e| e.to_string())?.as_bytes().to_vec());
        }
    };
    // seconds of prime search on a loaded host: off the runtime's worker, whose timers it would hold up
    let key = crate::blocking::off_worker(|| aws_lc_rs::rsa::KeyPair::generate(size)).map_err(|e| e.to_string())?;
    Ok(key.as_der().map_err(|e| e.to_string())?.as_ref().to_vec())
}

/// `AsymmetricKeyPairAlgorithm`, in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Es256,
    Es384,
    Es512,
    Rs256,
    Rs384,
    Rs512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
}

/// What an algorithm is made of: its key (RSA bits or EC curve) and digest, its names, and the certificate
/// signature algorithm of a key generated for it.
struct Spec {
    algorithm: Algorithm,
    jwt: &'static str,
    key: KeySpec,
    hash: Hash,
    xml_signature_method: &'static str,
    xml_digest_method: &'static str,
    /// The DER `AlgorithmIdentifier` of a certificate signed with this algorithm.
    certificate: &'static [u8],
}

#[derive(Clone, Copy)]
enum KeySpec {
    Rsa(usize),
    Ec(Curve),
}

const SPECS: &[Spec] = &[
    Spec { algorithm: Algorithm::Es256, jwt: "ES256", key: KeySpec::Ec(Curve::P256), hash: Hash::Sha256, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", xml_digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", certificate: &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] },
    Spec { algorithm: Algorithm::Es384, jwt: "ES384", key: KeySpec::Ec(Curve::P384), hash: Hash::Sha384, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", xml_digest_method: "http://www.w3.org/2001/04/xmldsig-more#sha384", certificate: &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] },
    Spec { algorithm: Algorithm::Es512, jwt: "ES512", key: KeySpec::Ec(Curve::P521), hash: Hash::Sha512, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", xml_digest_method: "http://www.w3.org/2001/04/xmlenc#sha512", certificate: &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] },
    Spec { algorithm: Algorithm::Rs256, jwt: "RS256", key: KeySpec::Rsa(2048), hash: Hash::Sha256, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", xml_digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", certificate: &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00] },
    Spec { algorithm: Algorithm::Rs384, jwt: "RS384", key: KeySpec::Rsa(3072), hash: Hash::Sha384, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", xml_digest_method: "http://www.w3.org/2001/04/xmldsig-more#sha384", certificate: &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00] },
    Spec { algorithm: Algorithm::Rs512, jwt: "RS512", key: KeySpec::Rsa(4096), hash: Hash::Sha512, xml_signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", xml_digest_method: "http://www.w3.org/2001/04/xmlenc#sha512", certificate: &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00] },
];

impl Algorithm {
    fn spec(self) -> &'static Spec {
        SPECS.iter().find(|s| s.algorithm == self).expect("every algorithm has a spec")
    }

    /// `fromJwtAlgorithm`: the JWT name, trimmed and case-insensitively.
    pub fn from_jwt(name: &str) -> Option<Algorithm> {
        SPECS.iter().find(|s| s.jwt.eq_ignore_ascii_case(name.trim())).map(|s| s.algorithm)
    }

    pub fn jwt(self) -> &'static str {
        self.spec().jwt
    }

    pub fn is_rsa(self) -> bool {
        matches!(self.spec().key, KeySpec::Rsa(_))
    }

    /// `getAlgorithm`: `RSA` or `EC`.
    pub fn family(self) -> &'static str {
        if self.is_rsa() { "RSA" } else { "EC" }
    }

    pub fn curve(self) -> Option<Curve> {
        match self.spec().key {
            KeySpec::Ec(curve) => Some(curve),
            KeySpec::Rsa(_) => None,
        }
    }

    pub fn hash(self) -> Hash {
        self.spec().hash
    }

    pub fn xml_signature_method(self) -> &'static str {
        self.spec().xml_signature_method
    }

    pub fn xml_digest_method(self) -> &'static str {
        self.spec().xml_digest_method
    }
}

impl Hash {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let algorithm = match self {
            Hash::Sha256 => &ring::digest::SHA256,
            Hash::Sha384 => &ring::digest::SHA384,
            Hash::Sha512 => &ring::digest::SHA512,
        };
        ring::digest::digest(algorithm, data).as_ref().to_vec()
    }
}

/// An EC private key on one of the curves the JDK's providers load.
pub enum EcKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
}

impl EcKey {
    pub fn curve(&self) -> Curve {
        match self {
            EcKey::P256(_) => Curve::P256,
            EcKey::P384(_) => Curve::P384,
            EcKey::P521(_) => Curve::P521,
        }
    }

    fn field_len(&self) -> usize {
        match self {
            EcKey::P256(_) => 32,
            EcKey::P384(_) => 48,
            EcKey::P521(_) => 66,
        }
    }

    /// The private scalar `d` (big-endian, field length) on `curve`.
    pub fn from_scalar(curve: Curve, d: &[u8]) -> Option<EcKey> {
        Some(match curve {
            Curve::P256 => EcKey::P256(p256::ecdsa::SigningKey::from_slice(d).ok()?),
            Curve::P384 => EcKey::P384(p384::ecdsa::SigningKey::from_slice(d).ok()?),
            Curve::P521 => EcKey::P521(p521::ecdsa::SigningKey::from_slice(d).ok()?),
        })
    }

    fn generate(curve: Curve) -> EcKey {
        let rng = &mut rand_core::OsRng;
        match curve {
            Curve::P256 => EcKey::P256(p256::ecdsa::SigningKey::random(rng)),
            Curve::P384 => EcKey::P384(p384::ecdsa::SigningKey::random(rng)),
            Curve::P521 => EcKey::P521(p521::ecdsa::SigningKey::random(rng)),
        }
    }

    /// A PKCS#8 `PrivateKeyInfo` or a SEC1 `ECPrivateKey`, on whichever curve it names.
    /// The uncompressed public point (`04 || x || y`).
    pub fn public_point(&self) -> Vec<u8> {
        match self {
            EcKey::P256(k) => k.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
            EcKey::P384(k) => k.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
            EcKey::P521(k) => p521::ecdsa::VerifyingKey::from(k).to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// `prehash` as an integer of the curve's field length: a short digest (SHA-256 on P-521) is left-padded, which
    /// keeps its value, as `bits2int` does.
    fn padded(&self, prehash: &[u8]) -> Vec<u8> {
        let len = self.field_len();
        if prehash.len() >= len {
            return prehash.to_vec();
        }
        let mut out = vec![0u8; len - prehash.len()];
        out.extend_from_slice(prehash);
        out
    }

    /// ECDSA over `prehash`: `r || s` (`der` false) or the DER `ECDSA-Sig-Value` X.509 uses.
    fn sign_prehash(&self, prehash: &[u8], der: bool) -> Option<Vec<u8>> {
        let prehash = self.padded(prehash);
        let rng = &mut rand_core::OsRng;
        macro_rules! sign {
            ($k:expr, $signature:ty) => {{
                let signature: $signature = $k.sign_prehash_with_rng(rng, &prehash).ok()?;
                Some(if der { signature.to_der().as_bytes().to_vec() } else { signature.to_bytes().to_vec() })
            }};
        }
        match self {
            EcKey::P256(k) => sign!(k, p256::ecdsa::Signature),
            EcKey::P384(k) => sign!(k, p384::ecdsa::Signature),
            EcKey::P521(k) => sign!(k, p521::ecdsa::Signature),
        }
    }

    #[cfg(test)]
    fn verify_prehash(&self, prehash: &[u8], signature: &[u8]) -> bool {
        let prehash = self.padded(prehash);
        match self {
            EcKey::P256(k) => p256::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verifying_key().verify_prehash(&prehash, &s).is_ok()),
            EcKey::P384(k) => p384::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verifying_key().verify_prehash(&prehash, &s).is_ok()),
            EcKey::P521(k) => p521::ecdsa::Signature::from_slice(signature).is_ok_and(|s| p521::ecdsa::VerifyingKey::from(k).verify_prehash(&prehash, &s).is_ok()),
        }
    }
}

/// A private key that signs.
pub enum Signer {
    Rsa(ring::signature::RsaKeyPair),
    Ec(EcKey),
    /// a PEM RSA key, held and signed with as the JDK does: BouncyCastle's key factory takes any size, inconsistent
    /// CRT values and keys without them, all of which ring refuses
    Jdk(JdkRsaKey),
    /// a PEM EC key on a curve the JDK's SunEC cannot sign on: the `ECParameterSpec.toString()` of its parameters,
    /// which `ECDSASignature.engineSign` names in its `Curve not supported`, and the key BouncyCastle
    /// signs with where the JDK's provider selection reaches it, as XML-DSig's does; `None` for
    /// parameters that are not modelled
    UnsupportedCurve(String, Option<Box<ecdsa::EcDomainKey>>),
    /// a PEM key of another algorithm BouncyCastle's provider reads (DSA, EdDSA, XDH, DH, GOST, ML-DSA, ML-KEM,
    /// SLH-DSA; ElGamal, GOST R 34.10-94, DSTU 4145, LMS, Falcon, NTRU, FrodoKEM, Classic McEliece and
    /// composite ML-DSA/ML-KEM), which no JWT is signed with (except a GOST key SunEC translates)
    Other(OtherKey),
}

/// A key of another algorithm than RSA and EC, as BouncyCastle's provider reads it.
pub struct OtherKey {
    /// `Key.getAlgorithm()`: `None` for a generic composite key's null
    pub algorithm: Option<String>,
    /// the BouncyCastle key class, below `org.bouncycastle`
    class: &'static str,
    /// a GOST or DSTU key's curve and scalar, which BouncyCastle's ECDSA signs with (the JDK's XML-DSig falls over
    /// to it)
    gost: Option<Box<ecdsa::EcDomainKey>>,
    /// how SunEC's key factory translates a GOST key when a JWT is signed with it
    pub sun_ec: SunEc,
}

/// SunEC's translation of a GOST R 34.10 key (an `ECPrivateKey`) for an ES* JWT.
pub enum SunEc {
    /// GOST parameters: the encoding is no `ECPrivateKey` SunEC reads (`Not a SEQUENCE`)
    Encoding,
    /// X9.62 parameters of a NIST curve, named or explicit: SunEC signs with the key
    Nist(Box<EcKey>),
    /// X9.62 parameters of another curve: `Curve not supported: <ECParameterSpec text>`
    Unsupported(String),
    /// implicitlyCA X9.62 parameters
    Implicit,
}

impl OtherKey {
    /// The key's class, as `getClass().getName()` prints it.
    pub fn class_name(&self) -> String {
        other::class_name(self.class)
    }
}

impl Signer {
    /// `AsymmetricKeyGenerator.createKeyPair`: RSA of the algorithm's size, or EC on its curve.
    ///
    /// RSA keys come from aws-lc (already linked through rustls): the `rsa` crate's prime search took 2.2 s of CPU
    /// on average for 4096 bits (up to 5.8 s) even optimised, aws-lc 0.4 s (up to 0.9 s).
    ///
    /// Callers are control-plane requests (`PUT /mockserver/oidc`, `/saml`): the generation leaves the async worker
    /// first, so the worker's other connections are answered meanwhile.
    pub fn generate(algorithm: Algorithm) -> Result<Signer, String> {
        crate::blocking::off_worker(|| match algorithm.spec().key {
            KeySpec::Rsa(bits) => Ok(Signer::Rsa(ring::signature::RsaKeyPair::from_pkcs8(&rsa_pkcs8(bits)?).map_err(|e| e.to_string())?)),
            KeySpec::Ec(curve) => Ok(Signer::Ec(EcKey::generate(curve))),
        })
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, Signer::Rsa(_) | Signer::Jdk(_))
    }

    /// `OidcKeyProvider.keyFamily` of the key's algorithm: `RSA` or `EC` by its prefix, else the name in upper case.
    pub fn family(&self) -> String {
        match self {
            Signer::Other(key) => {
                // a null algorithm is the empty family
                let upper = key.algorithm.as_deref().unwrap_or_default().to_uppercase();
                if upper.starts_with("RSA") {
                    "RSA".into()
                } else if upper.starts_with("EC") {
                    "EC".into()
                } else {
                    upper
                }
            }
            _ if self.is_rsa() => "RSA".into(),
            _ => "EC".into(),
        }
    }

    /// `(n, e)` of an RSA key, big-endian; `None` for a PEM key without CRT values, which BouncyCastle makes a plain
    /// `RSAPrivateKey` (`OidcKeyProvider` derives the public key of an `RSAPrivateCrtKey` only).
    pub fn rsa_public(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;
        if let Signer::Jdk(k) = self {
            return k.crt_key.then(|| (k.n.to_bytes_be(), k.e.to_bytes_be()));
        }
        let Signer::Rsa(k) = self else { return None };
        let key = rsa::RsaPublicKey::from_pkcs1_der(ring::signature::KeyPair::public_key(k).as_ref()).ok()?;
        Some((key.n().to_bytes_be(), key.e().to_bytes_be()))
    }

    /// The public half of the key pair.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Signer::Rsa(_) => {
                let (n, e) = self.rsa_public().unwrap_or_default();
                PublicKey::Rsa { n, e }
            }
            Signer::Jdk(k) => PublicKey::Rsa { n: k.n.to_bytes_be(), e: k.e.to_bytes_be() },
            Signer::Ec(k) => {
                let point = k.public_point();
                let half = (point.len() - 1) / 2;
                PublicKey::Ec { x: point[1..1 + half].to_vec(), y: point[1 + half..].to_vec() }
            }
            Signer::UnsupportedCurve(..) | Signer::Other(_) => PublicKey::Ec { x: Vec::new(), y: Vec::new() },
        }
    }

    /// `algorithm`'s signature over `input` in JWS/XML-DSig form; `None` when the key is of the other family (the
    /// JDK's `Signature.initSign` rejects it) or a PEM RSA key's signing fails ([`JdkRsaKey::rsassa`] says why). A
    /// key on a curve SunEC does not support signs as BouncyCastle does (the JWT path refuses it before signing).
    pub fn sign(&self, algorithm: Algorithm, input: &[u8]) -> Option<Vec<u8>> {
        self.sign_as(algorithm, input, false)
    }

    /// nimbus' `RSASSASigner` / `ECDSASigner.sign`: as [`Signer::sign`], an ECDSA signature transcoded by
    /// `ECDSA.transcodeSignatureToConcat`, so `r` and `s` each take the longer of their minimal lengths and half the
    /// algorithm's signature length. A key on another curve than the algorithm's signs anyway: a P-384 key under ES256
    /// gives 96 bytes, a P-256 key under ES384 is padded to 96.
    pub fn sign_jws(&self, algorithm: Algorithm, input: &[u8]) -> Option<Vec<u8>> {
        let signature = self.sign(algorithm, input)?;
        let Some(curve) = algorithm.curve() else { return Some(signature) };
        let half = match curve {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        };
        let (r, s) = signature.split_at(signature.len() / 2);
        let minimal = |v: &[u8]| v.iter().position(|b| *b != 0).map_or(0, |i| v.len() - i);
        let len = minimal(r).max(minimal(s)).max(half);
        let pad = |v: &[u8]| [vec![0; len - minimal(v)], v[v.len() - minimal(v)..].to_vec()].concat();
        Some([pad(r), pad(s)].concat())
    }

    fn sign_as(&self, algorithm: Algorithm, input: &[u8], der: bool) -> Option<Vec<u8>> {
        match self {
            Signer::Rsa(key) if algorithm.is_rsa() => {
                let padding: &'static dyn ring::signature::RsaEncoding = match algorithm.hash() {
                    Hash::Sha256 => &ring::signature::RSA_PKCS1_SHA256,
                    Hash::Sha384 => &ring::signature::RSA_PKCS1_SHA384,
                    Hash::Sha512 => &ring::signature::RSA_PKCS1_SHA512,
                };
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(padding, &ring::rand::SystemRandom::new(), input, &mut signature).ok()?;
                Some(signature)
            }
            Signer::Jdk(key) if algorithm.is_rsa() => key.rsassa(algorithm, input).ok(),
            Signer::Ec(key) if !algorithm.is_rsa() => key.sign_prehash(&algorithm.hash().digest(input), der),
            Signer::UnsupportedCurve(_, Some(key)) if !algorithm.is_rsa() && !der => key.sign_prehash(&algorithm.hash().digest(input)),
            Signer::Other(OtherKey { gost: Some(key), .. }) if !algorithm.is_rsa() && !der => key.sign_prehash(&algorithm.hash().digest(input)),
            _ => None,
        }
    }

    /// The key pair's own verification (tokens are verified against [`PublicKey`], which may be another key).
    #[cfg(test)]
    pub fn verify(&self, algorithm: Algorithm, input: &[u8], signature: &[u8]) -> bool {
        match self {
            Signer::Rsa(key) if algorithm.is_rsa() => {
                let parameters: &ring::signature::RsaParameters = match algorithm.hash() {
                    Hash::Sha256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    Hash::Sha384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
                    Hash::Sha512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
                };
                let public = ring::signature::KeyPair::public_key(key);
                ring::signature::UnparsedPublicKey::new(parameters, public.as_ref()).verify(input, signature).is_ok()
            }
            Signer::Ec(key) if !algorithm.is_rsa() => key.verify_prehash(&algorithm.hash().digest(input), signature),
            _ => false,
        }
    }

    /// The DER `SubjectPublicKeyInfo`.
    fn subject_public_key_info(&self) -> Vec<u8> {
        const RSA_ENCRYPTION: &[u8] = &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
        const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let (algorithm, key) = match self {
            Signer::Rsa(k) => (RSA_ENCRYPTION.to_vec(), ring::signature::KeyPair::public_key(k).as_ref().to_vec()),
            Signer::Jdk(k) => {
                let int = |v: Vec<u8>| der(0x02, &if v[0] & 0x80 != 0 { [vec![0], v].concat() } else { v });
                (RSA_ENCRYPTION.to_vec(), der(0x30, &[int(k.n.to_bytes_be()), int(k.e.to_bytes_be())].concat()))
            }
            // no certificate is ever made for a key only a PEM supplies
            Signer::UnsupportedCurve(..) | Signer::Other(_) => (Vec::new(), Vec::new()),
            Signer::Ec(k) => {
                let curve: &[u8] = match k.curve() {
                    Curve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                    Curve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
                    Curve::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
                };
                (der(0x30, &[EC_PUBLIC_KEY, curve].concat()), k.public_point())
            }
        };
        der(0x30, &[algorithm, bit_string(&key)].concat())
    }

    /// BouncyCastle's `JcaX509v3CertificateBuilder` output for a self-signed v3 certificate: `subject` as the issuer
    /// too (UTF8String values), a positive `serial`, the validity as UTCTime (GeneralizedTime from 2050), and
    /// `extensions` (DER `Extension`s), signed with `algorithm`.
    pub fn self_signed_certificate(
        &self,
        algorithm: Algorithm,
        subject: &[(&[u8], &str)],
        serial: u64,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        extensions: &[Vec<u8>],
    ) -> Result<Vec<u8>, String> {
        let name = der(0x30, &subject.iter().map(|(oid, value)| der(0x31, &der(0x30, &[der(0x06, oid), der(0x0c, value.as_bytes())].concat()))).collect::<Vec<_>>().concat());
        let time = |t: chrono::DateTime<chrono::Utc>| {
            use chrono::Datelike;
            if (1950..2050).contains(&t.year()) { der(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes()) } else { der(0x18, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes()) }
        };
        let mut serial_bytes: Vec<u8> = serial.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        if serial_bytes.first().is_none_or(|b| b & 0x80 != 0) {
            serial_bytes.insert(0, 0);
        }
        let signature_algorithm = algorithm.spec().certificate;
        let mut tbs = vec![der(0xa0, &der(0x02, &[2])), der(0x02, &serial_bytes), signature_algorithm.to_vec(), name.clone(), der(0x30, &[time(not_before), time(not_after)].concat()), name, self.subject_public_key_info()];
        if !extensions.is_empty() {
            tbs.push(der(0xa3, &der(0x30, &extensions.concat())));
        }
        let tbs = der(0x30, &tbs.concat());
        let signature = self.sign_as(algorithm, &tbs, true).ok_or_else(|| format!("{} cannot sign with a {} key", algorithm.jwt(), self.family()))?;
        Ok(der(0x30, &[tbs, signature_algorithm.to_vec(), bit_string(&signature)].concat()))
    }
}

/// A public key as an identity provider publishes it and verifies tokens with, which need not belong to the key it
/// signs with (a JWK's own x/y or n/e, a certificate's key): RSA `(n, e)` without leading zero bytes, or EC affine
/// coordinates as given, taken to be on the signing algorithm's curve.
#[derive(Debug, Clone)]
pub enum PublicKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { x: Vec<u8>, y: Vec<u8> },
    /// a certificate's key of another algorithm: its key bits
    Other { bits: Vec<u8> },
}

/// Big-endian bytes without leading zeros (`BigIntegerUtils.toBytesUnsigned`).
fn unsigned(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().skip_while(|b| *b == 0).collect()
}

/// `bytes` as an integer of `len` bytes, `None` when it does not fit.
pub fn fixed_len(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    let bytes = unsigned(bytes);
    (bytes.len() <= len).then(|| [vec![0; len - bytes.len()], bytes].concat())
}

impl PublicKey {
    pub fn rsa(n: &[u8], e: &[u8]) -> PublicKey {
        PublicKey::Rsa { n: unsigned(n), e: unsigned(e) }
    }

    /// `X509Certificate.getPublicKey()` of a certificate's DER, read by [`crate::tls::x509`] as `X509Factory` reads it
    ///: an RSA key, an EC key's uncompressed point, or the key bits of another algorithm's key.
    pub fn from_certificate(der: &[u8]) -> Option<PublicKey> {
        use crate::tls::x509::PublicKey as Parsed;
        let certificate = crate::tls::x509::generate_certificate(der).ok()?;
        match certificate.public_key {
            Parsed::Rsa { modulus, exponent } => Some(PublicKey::rsa(&modulus.to_bytes_be(), &exponent.to_bytes_be())),
            // the point as given (fixed-width coordinates), `X509Key.parse` having checked its form and size
            Parsed::Ec { .. } => {
                let point = &certificate.key_bits;
                let half = (point.len() - 1) / 2;
                Some(PublicKey::Ec { x: point[1..1 + half].to_vec(), y: point[1 + half..].to_vec() })
            }
            Parsed::Other => Some(PublicKey::Other { bits: certificate.key_bits }),
        }
    }

    /// `AsymmetricKeyConverter.getRSAPublicKey` (`rsa`) or `getECPublicKey` over this key's X.509 encoding: the JDK
    /// key factory of the other family refuses it, an EC point read as RSA key bits fails in the JDK's DER parser
    ///.
    pub fn convert(&self, rsa: bool) -> Result<(), Failure> {
        const INVALID_KEY: &str = "java.security.InvalidKeyException";
        let invalid = match self {
            PublicKey::Rsa { .. } if !rsa => throwable(INVALID_KEY, Some("EC domain parameters must be encoded in the algorithm identifier".into()), None),
            PublicKey::Ec { x, y } if rsa => {
                let bits = [&[4][..], x, y].concat();
                throwable(INVALID_KEY, Some("Invalid RSA public key".into()), jdk::rsa_public_key_bits(&bits))
            }
            PublicKey::Other { bits } if rsa => throwable(INVALID_KEY, Some("Invalid RSA public key".into()), jdk::rsa_public_key_bits(bits)),
            PublicKey::Other { .. } => throwable(INVALID_KEY, Some("EC domain parameters must be encoded in the algorithm identifier".into()), None),
            _ => return Ok(()),
        };
        let spec = throwable("java.security.spec.InvalidKeySpecException", Some(java_string(&invalid)), Some(invalid));
        let message = format!("Exception converting public key for algorithm \"{}\" {}", if rsa { "RSA" } else { "EC" }, spec.message);
        Err(caused(RUNTIME_EXCEPTION, message, spec))
    }

    /// nimbus' `RSASSAVerifier` / `ECDSAVerifier` (`r || s`) of `algorithm` over `input`.
    pub fn verify(&self, algorithm: Algorithm, input: &[u8], signature: &[u8]) -> bool {
        match (self, algorithm.curve()) {
            (PublicKey::Rsa { n, e }, None) => {
                let parameters: &ring::signature::RsaParameters = match algorithm.hash() {
                    Hash::Sha256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    Hash::Sha384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
                    Hash::Sha512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
                };
                ring::signature::RsaPublicKeyComponents { n, e }.verify(parameters, input, signature).is_ok()
            }
            (PublicKey::Ec { x, y }, Some(curve)) => {
                let len = match curve {
                    Curve::P256 => 32,
                    Curve::P384 => 48,
                    Curve::P521 => 66,
                };
                let (Some(x), Some(y)) = (fixed_len(x, len), fixed_len(y, len)) else { return false };
                let point = [&[4u8][..], &x, &y].concat();
                let digest = algorithm.hash().digest(input);
                let prehash = fixed_len(&digest, len.max(digest.len())).unwrap_or(digest);
                match curve {
                    Curve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok_and(|k| p256::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&prehash, &s).is_ok())),
                    Curve::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok_and(|k| p384::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&prehash, &s).is_ok())),
                    Curve::P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok_and(|k| p521::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&prehash, &s).is_ok())),
                }
            }
            _ => false,
        }
    }
}

/// An RSA private key as the JDK holds one built from a JWK (`RSAKey.toPrivateKey`): unvalidated components, signed
/// with as `SHAnnnwithRSA` signs (`RSACore`). A key whose CRT components are all non-zero is an `RSAPrivateCrtKey`,
/// signed by CRT and checked against `e` (`RSA private key operation failed` when the components are inconsistent);
/// any other is `c^d mod n`, unchecked.
pub struct JdkRsaKey {
    n: rsa::BigUint,
    e: rsa::BigUint,
    d: rsa::BigUint,
    /// `[p, q, dp, dq, qi]`
    crt: Option<[rsa::BigUint; 5]>,
    /// BouncyCastle's key factory makes an `RSAPrivateCrtKey` (its coefficient is not 0), whose public key
    /// `OidcKeyProvider` derives
    crt_key: bool,
}

impl JdkRsaKey {
    pub fn new(n: &[u8], e: &[u8], d: &[u8], crt: Option<&[Vec<u8>]>) -> JdkRsaKey {
        let big = |b: &[u8]| rsa::BigUint::from_bytes_be(b);
        let crt = crt.map(|parts| [0, 1, 2, 3, 4].map(|i| big(&parts[i]))).filter(|parts| parts.iter().all(|v| *v != rsa::BigUint::from(0u8)));
        JdkRsaKey { n: big(n), e: big(e), d: big(d), crt, crt_key: true }
    }

    /// The key BouncyCastle's RSA key factory makes of an `RSAPrivateKey`'s nine INTEGERs (version, n, e, d, p, q,
    /// dp, dq, qi), validated by the caller (`jca`): an `RSAPrivateCrtKey` unless the coefficient is 0.
    fn from_integers(ints: &[Vec<u8>]) -> JdkRsaKey {
        let coefficient_zero = rsa::BigUint::from_bytes_be(&ints[8]) == rsa::BigUint::from(0u8);
        let mut key = JdkRsaKey::new(&ints[1], &ints[2], &ints[3], Some(&ints[4..9]));
        key.crt_key = !coefficient_zero;
        key
    }

    /// The modulus' length in bits.
    pub fn modulus_bits(&self) -> usize {
        self.n.bits()
    }

    /// nimbus' `RSASSASigner` (a modulus of at least 2048 bits) over [`JdkRsaKey::rsassa`].
    pub fn sign(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, JdkRsaFailure> {
        if !algorithm.is_rsa() {
            return Err(JdkRsaFailure::NotRsa);
        }
        if self.n.bits() < 2048 {
            return Err(JdkRsaFailure::KeySize);
        }
        self.rsassa(algorithm, input)
    }

    /// The JDK's PKCS#1 v1.5 signature (`SHAnnnwithRSA`); where it throws, which check failed.
    pub fn rsassa(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, JdkRsaFailure> {
        use rsa::BigUint;
        if !algorithm.is_rsa() {
            return Err(JdkRsaFailure::NotRsa);
        }
        let prefix: &[u8] = match algorithm.hash() {
            Hash::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            Hash::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            Hash::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        };
        let k = self.n.bits().div_ceil(8);
        let t = [prefix, &algorithm.hash().digest(input)].concat();
        if k < t.len() + 11 {
            return Err(JdkRsaFailure::TooShort);
        }
        let padded = [&[0u8, 1][..], &vec![0xff; k - t.len() - 3], &[0], &t].concat();
        let c = BigUint::from_bytes_be(&padded);
        let m = match &self.crt {
            Some([p, q, dp, dq, qi]) => {
                // `RSACore.crtCrypt` with its verification
                let m1 = c.modpow(dp, p);
                let m2 = c.modpow(dq, q);
                let h = ((&m1 + p - (&m2 % p)) % p * qi) % p;
                let m = (h * q + m2) % &self.n;
                if m.modpow(&self.e, &self.n) != c {
                    return Err(JdkRsaFailure::CrtCheck);
                }
                m
            }
            None => c.modpow(&self.d, &self.n),
        };
        Ok(fixed_len(&m.to_bytes_be(), k).expect("m < n"))
    }
}

/// Why [`JdkRsaKey::sign`] throws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JdkRsaFailure {
    /// an EC algorithm: no RSA signer is built for it
    NotRsa,
    /// nimbus' `RSASSASigner` constructor: `The RSA key size must be at least 2048 bits`
    KeySize,
    /// `RSACore.crtCrypt`'s verification: `RSA private key operation failed`
    CrtCheck,
    /// `RSAPadding`: a modulus too short for the digest's PKCS#1 v1.5 encoding
    TooShort,
}

/// The curves the JDK names (`CurveDB`, `NamedCurve.toString()` without its OID) but SunEC does not sign on, and the
/// ones only BouncyCastle names (`None`: its `ECNamedCurveSpec` has no `toString`), by OID content; as the oracle
/// reports them for a key from `openssl ecparam -list_curves`. The WTLS curves are absent: the PUT
/// refuses them.
const UNSUPPORTED_CURVES: &[(&[u8], Option<&str>)] = &[
    (&[0x2b, 0x81, 0x04, 0x00, 0x06], Some("secp112r1")), // secp112r1 1.3.132.0.6
    (&[0x2b, 0x81, 0x04, 0x00, 0x07], Some("secp112r2")), // secp112r2 1.3.132.0.7
    (&[0x2b, 0x81, 0x04, 0x00, 0x1c], Some("secp128r1")), // secp128r1 1.3.132.0.28
    (&[0x2b, 0x81, 0x04, 0x00, 0x1d], Some("secp128r2")), // secp128r2 1.3.132.0.29
    (&[0x2b, 0x81, 0x04, 0x00, 0x09], Some("secp160k1")), // secp160k1 1.3.132.0.9
    (&[0x2b, 0x81, 0x04, 0x00, 0x08], Some("secp160r1")), // secp160r1 1.3.132.0.8
    (&[0x2b, 0x81, 0x04, 0x00, 0x1e], Some("secp160r2")), // secp160r2 1.3.132.0.30
    (&[0x2b, 0x81, 0x04, 0x00, 0x1f], Some("secp192k1")), // secp192k1 1.3.132.0.31
    (&[0x2b, 0x81, 0x04, 0x00, 0x20], Some("secp224k1")), // secp224k1 1.3.132.0.32
    (&[0x2b, 0x81, 0x04, 0x00, 0x21], Some("secp224r1 [NIST P-224]")), // secp224r1 1.3.132.0.33
    (&[0x2b, 0x81, 0x04, 0x00, 0x0a], Some("secp256k1")), // secp256k1 1.3.132.0.10
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01], Some("secp192r1 [NIST P-192,X9.62 prime192v1]")), // prime192v1 1.2.840.10045.3.1.1
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x02], Some("X9.62 prime192v2")), // prime192v2 1.2.840.10045.3.1.2
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x03], Some("X9.62 prime192v3")), // prime192v3 1.2.840.10045.3.1.3
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x04], Some("X9.62 prime239v1")), // prime239v1 1.2.840.10045.3.1.4
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x05], Some("X9.62 prime239v2")), // prime239v2 1.2.840.10045.3.1.5
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x06], Some("X9.62 prime239v3")), // prime239v3 1.2.840.10045.3.1.6
    (&[0x2b, 0x81, 0x04, 0x00, 0x04], Some("sect113r1")), // sect113r1 1.3.132.0.4
    (&[0x2b, 0x81, 0x04, 0x00, 0x05], Some("sect113r2")), // sect113r2 1.3.132.0.5
    (&[0x2b, 0x81, 0x04, 0x00, 0x16], Some("sect131r1")), // sect131r1 1.3.132.0.22
    (&[0x2b, 0x81, 0x04, 0x00, 0x17], Some("sect131r2")), // sect131r2 1.3.132.0.23
    (&[0x2b, 0x81, 0x04, 0x00, 0x01], Some("sect163k1 [NIST K-163]")), // sect163k1 1.3.132.0.1
    (&[0x2b, 0x81, 0x04, 0x00, 0x02], Some("sect163r1")), // sect163r1 1.3.132.0.2
    (&[0x2b, 0x81, 0x04, 0x00, 0x0f], Some("sect163r2 [NIST B-163]")), // sect163r2 1.3.132.0.15
    (&[0x2b, 0x81, 0x04, 0x00, 0x18], Some("sect193r1")), // sect193r1 1.3.132.0.24
    (&[0x2b, 0x81, 0x04, 0x00, 0x19], Some("sect193r2")), // sect193r2 1.3.132.0.25
    (&[0x2b, 0x81, 0x04, 0x00, 0x1a], Some("sect233k1 [NIST K-233]")), // sect233k1 1.3.132.0.26
    (&[0x2b, 0x81, 0x04, 0x00, 0x1b], Some("sect233r1 [NIST B-233]")), // sect233r1 1.3.132.0.27
    (&[0x2b, 0x81, 0x04, 0x00, 0x03], Some("sect239k1")), // sect239k1 1.3.132.0.3
    (&[0x2b, 0x81, 0x04, 0x00, 0x10], Some("sect283k1 [NIST K-283]")), // sect283k1 1.3.132.0.16
    (&[0x2b, 0x81, 0x04, 0x00, 0x11], Some("sect283r1 [NIST B-283]")), // sect283r1 1.3.132.0.17
    (&[0x2b, 0x81, 0x04, 0x00, 0x24], Some("sect409k1 [NIST K-409]")), // sect409k1 1.3.132.0.36
    (&[0x2b, 0x81, 0x04, 0x00, 0x25], Some("sect409r1 [NIST B-409]")), // sect409r1 1.3.132.0.37
    (&[0x2b, 0x81, 0x04, 0x00, 0x26], Some("sect571k1 [NIST K-571]")), // sect571k1 1.3.132.0.38
    (&[0x2b, 0x81, 0x04, 0x00, 0x27], Some("sect571r1 [NIST B-571]")), // sect571r1 1.3.132.0.39
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x01], None), // c2pnb163v1 1.2.840.10045.3.0.1
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x02], None), // c2pnb163v2 1.2.840.10045.3.0.2
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x03], None), // c2pnb163v3 1.2.840.10045.3.0.3
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x04], None), // c2pnb176v1 1.2.840.10045.3.0.4
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x05], Some("X9.62 c2tnb191v1")), // c2tnb191v1 1.2.840.10045.3.0.5
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x06], Some("X9.62 c2tnb191v2")), // c2tnb191v2 1.2.840.10045.3.0.6
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x07], Some("X9.62 c2tnb191v3")), // c2tnb191v3 1.2.840.10045.3.0.7
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0a], None), // c2pnb208w1 1.2.840.10045.3.0.10
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0b], Some("X9.62 c2tnb239v1")), // c2tnb239v1 1.2.840.10045.3.0.11
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0c], Some("X9.62 c2tnb239v2")), // c2tnb239v2 1.2.840.10045.3.0.12
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0d], Some("X9.62 c2tnb239v3")), // c2tnb239v3 1.2.840.10045.3.0.13
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x10], None), // c2pnb272w1 1.2.840.10045.3.0.16
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x11], None), // c2pnb304w1 1.2.840.10045.3.0.17
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x12], Some("X9.62 c2tnb359v1")), // c2tnb359v1 1.2.840.10045.3.0.18
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x13], None), // c2pnb368w1 1.2.840.10045.3.0.19
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x14], Some("X9.62 c2tnb431r1")), // c2tnb431r1 1.2.840.10045.3.0.20
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01], Some("brainpoolP160r1")), // brainpoolP160r1 1.3.36.3.3.2.8.1.1.1
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02], None), // brainpoolP160t1 1.3.36.3.3.2.8.1.1.2
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03], Some("brainpoolP192r1")), // brainpoolP192r1 1.3.36.3.3.2.8.1.1.3
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04], None), // brainpoolP192t1 1.3.36.3.3.2.8.1.1.4
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05], Some("brainpoolP224r1")), // brainpoolP224r1 1.3.36.3.3.2.8.1.1.5
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06], None), // brainpoolP224t1 1.3.36.3.3.2.8.1.1.6
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], Some("brainpoolP256r1")), // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08], None), // brainpoolP256t1 1.3.36.3.3.2.8.1.1.8
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09], Some("brainpoolP320r1")), // brainpoolP320r1 1.3.36.3.3.2.8.1.1.9
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0a], None), // brainpoolP320t1 1.3.36.3.3.2.8.1.1.10
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b], Some("brainpoolP384r1")), // brainpoolP384r1 1.3.36.3.3.2.8.1.1.11
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0c], None), // brainpoolP384t1 1.3.36.3.3.2.8.1.1.12
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d], Some("brainpoolP512r1")), // brainpoolP512r1 1.3.36.3.3.2.8.1.1.13
    (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e], None), // brainpoolP512t1 1.3.36.3.3.2.8.1.1.14
    (&[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d], None), // SM2 1.2.156.10197.1.301
];

/// The text of a Java object without `toString`: its class and an identity hash.
fn identity(class: &str) -> String {
    format!("{class}@{:x}", rand_core::RngCore::next_u32(&mut rand_core::OsRng) >> 1)
}

/// An OID's content in dotted form.
fn dotted(oid: &[u8]) -> String {
    let mut parts = vec![u64::from(oid[0] / 40), u64::from(oid[0] % 40)];
    let mut value = 0u64;
    for b in &oid[1..] {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// A DER TLV.
pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    der(0x03, &[&[0u8][..], bytes].concat())
}

// ---------------------------------------------------------------------------------------------------------------
// `PEMToFile.privateKeyFromPEM` and `x509FromPEM` failures: the RuntimeExceptions they throw, with BouncyCastle's
// `PEMParser` (its `PemReader`, `Base64` decoder, ASN.1 decoder and key structures, `bc`) or the JDK's `X509Factory`
// exception (`jdk`, over `crate::tls::x509`) beneath. A key both accept that we cannot read, or one they reject past
// what is modelled (`JcaPEMKeyConverter`'s key factories), is the RuntimeException without a cause.
// ---------------------------------------------------------------------------------------------------------------

mod bc;
mod curves;
mod ecdsa;
mod jca;
mod jdk;
mod mlkem;
mod other;

pub(crate) use other::gost_set;

const RUNTIME_EXCEPTION: &str = "java.lang.RuntimeException";
const IO_EXCEPTION: &str = "java.io.IOException";
const PEM_EXCEPTION: &str = "shaded_package.org.bouncycastle.openssl.PEMException";
const UNREADABLE_PRIVATE_KEY: &str = "Exception reading private key from PEM file";

fn caused(class: &'static str, message: impl Into<String>, cause: Failure) -> Failure {
    Failure::of(class, message, vec![("cause", cause.bean)], &cause.classes)
}

/// A Java exception of `class`, its message (`None` for a null one) and its cause.
fn throwable(class: &'static str, message: Option<String>, cause: Option<Failure>) -> Failure {
    let (fields, classes) = match cause {
        Some(cause) => (vec![("cause", cause.bean)], cause.classes),
        None => (Vec::new(), Vec::new()),
    };
    match message {
        Some(message) => Failure::of(class, message, fields, &classes),
        None => {
            let mut bean: serde_json::Map<String, serde_json::Value> = fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
            bean.insert("stackTrace".into(), serde_json::Value::Array(Vec::new()));
            Failure { message: String::new(), bean: serde_json::Value::Object(bean), classes: [&[class][..], &classes].concat() }
        }
    }
}

/// `Throwable.toString`: the class name, and `: message` unless the message is null.
fn java_string(e: &Failure) -> String {
    match e.bean.get("message").and_then(|m| m.as_str()) {
        Some(message) => format!("{}: {message}", e.classes[0]),
        None => e.classes[0].to_string(),
    }
}

fn iae(message: impl Into<String>) -> Failure {
    Failure::illegal(message)
}

/// `new PEMException(message, underlying)`: the underlying exception is its cause and its `underlyingException`.
fn pem_exception(message: impl Into<String>, underlying: Failure) -> Failure {
    Failure::of(PEM_EXCEPTION, message, vec![("cause", underlying.bean.clone()), ("underlyingException", underlying.bean)], &underlying.classes)
}

/// `String.charAt` or an array index past the end, as JDK 17+ words it.
fn out_of_bounds(class: &'static str, index: usize, length: usize) -> Failure {
    Failure::of(class, format!("Index {index} out of bounds for length {length}"), Vec::new(), &[])
}

/// `BufferedReader.readLine`: lines end at `\n`, `\r` or `\r\n`.
fn java_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find(['\r', '\n']) {
            None => {
                lines.push(rest);
                break;
            }
            Some(i) => {
                lines.push(&rest[..i]);
                let skip = if rest[i..].starts_with("\r\n") { 2 } else { 1 };
                rest = &rest[i + skip..];
            }
        }
    }
    lines
}

/// `String.trim`: every character up to U+0020 at either end.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// BouncyCastle's `Base64Encoder.decode(String)`, index arithmetic included: a too short input fails in
/// `String.charAt`, a character past ASCII in the decoding table.
fn bc_base64(data: &str) -> Result<Vec<u8>, Failure> {
    let d: Vec<u16> = data.encode_utf16().collect();
    let ignore = |c: u16| matches!(c, 0x0a | 0x0d | 0x09 | 0x20);
    let char_at = |i: usize| d.get(i).copied().ok_or_else(|| out_of_bounds("java.lang.StringIndexOutOfBoundsException", i, d.len()));
    let table = |c: u16| -> Result<i32, Failure> {
        Ok(match c {
            0x80.. => return Err(out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", usize::from(c), 128)),
            0x41..=0x5a => i32::from(c) - 0x41,
            0x61..=0x7a => i32::from(c) - 0x61 + 26,
            0x30..=0x39 => i32::from(c) - 0x30 + 52,
            0x2b => 62,
            0x2f => 63,
            _ => -1,
        })
    };
    let next = |mut i: usize, finish: usize| {
        while i < finish && ignore(d[i]) {
            i += 1;
        }
        i
    };
    let invalid = |message: &str| Failure::of(IO_EXCEPTION, message, Vec::new(), &[]);
    let mut out = Vec::new();
    let mut end = d.len();
    while end > 0 && ignore(d[end - 1]) {
        end -= 1;
    }
    if end == 0 {
        return Ok(out);
    }
    let (mut i, mut finish) = (0, end);
    while finish > 0 && i != 4 {
        if !ignore(d[finish - 1]) {
            i += 1;
        }
        finish -= 1;
    }
    i = next(0, finish);
    while i < finish {
        let mut b = [0i32; 4];
        for (k, slot) in b.iter_mut().enumerate() {
            *slot = table(char_at(i)?)?;
            i += 1;
            if k < 3 {
                i = next(i, finish);
            }
        }
        if b.iter().any(|v| *v < 0) {
            return Err(invalid("invalid characters encountered in base64 data"));
        }
        out.extend([(b[0] << 2) | (b[1] >> 4), (b[1] << 4) | (b[2] >> 2), (b[2] << 6) | b[3]].map(|v| v as u8));
        i = next(i, finish);
    }
    let e0 = next(i, end);
    let e1 = next(e0 + 1, end);
    let e2 = next(e1 + 1, end);
    let e3 = next(e2 + 1, end);
    let c = [char_at(e0)?, char_at(e1)?, char_at(e2)?, char_at(e3)?];
    // `decodeLastBlock`
    const PAD: u16 = b'=' as u16;
    let at_end = || invalid("invalid characters encountered at end of base64 data");
    let used = if c[2] == PAD {
        if c[3] != PAD {
            return Err(at_end());
        }
        2
    } else if c[3] == PAD {
        3
    } else {
        4
    };
    let mut b = [0i32; 4];
    for k in 0..used {
        b[k] = table(c[k])?;
    }
    if b.iter().any(|v| *v < 0) {
        return Err(at_end());
    }
    let bytes = [(b[0] << 2) | (b[1] >> 4), (b[1] << 4) | (b[2] >> 2), (b[2] << 6) | b[3]];
    out.extend(bytes[..used - 1].iter().map(|v| *v as u8));
    Ok(out)
}

/// What `PemReader.readPemObject` reads from a text.
enum PemRead {
    /// no `-----BEGIN <type>-----` line
    Nothing,
    Object { kind: String, headers: Vec<(String, String)>, content: Vec<u8> },
}

/// `PemReader.readPemObject`: the first line starting `-----BEGIN `, then header lines (any line with a colon: the
/// name before it, the trimmed value after it) and the body (each line trimmed) up to the line starting with the end
/// marker, base64-decoded.
fn read_pem(text: &str) -> Result<PemRead, Failure> {
    let mut lines = java_lines(text).into_iter();
    let Some(begin) = lines.by_ref().find(|l| l.starts_with("-----BEGIN ")) else { return Ok(PemRead::Nothing) };
    let header = java_trim(&begin["-----BEGIN ".len()..]);
    let kind = match header.find('-') {
        Some(i) if i > 0 && header.ends_with("-----") && header.len() - i == 5 => header[..i].to_string(),
        _ => return Ok(PemRead::Nothing),
    };
    let end = format!("-----END {kind}-----");
    let mut headers = Vec::new();
    let mut body = String::new();
    loop {
        match lines.next() {
            None => return Err(Failure::of(IO_EXCEPTION, format!("{end} not found"), Vec::new(), &[])),
            Some(l) if l.contains(':') => {
                let i = l.find(':').unwrap_or_default();
                headers.push((l[..i].to_string(), java_trim(&l[i + 1..]).to_string()));
            }
            Some(l) if l.starts_with(&end) => break,
            Some(l) => body.push_str(java_trim(l)),
        }
    }
    let content = bc_base64(&body).map_err(|cause| {
        let decoder = caused("shaded_package.org.bouncycastle.util.encoders.DecoderException", format!("unable to decode base64 string: {}", cause.message), cause);
        caused(IO_EXCEPTION, format!("malformed PEM data: {}", decoder.message), decoder)
    })?;
    Ok(PemRead::Object { kind, headers, content })
}

/// BouncyCastle's `Hex.decode(String)`: a DecoderException over `HexEncoder.decode`'s failure.
fn bc_hex(data: &str) -> Result<(), Failure> {
    let d: Vec<u16> = data.encode_utf16().collect();
    let ignore = |c: u16| matches!(c, 0x0a | 0x0d | 0x09 | 0x20);
    let decoding = || -> Result<(), Failure> {
        let mut end = d.len();
        while end > 0 && ignore(d[end - 1]) {
            end -= 1;
        }
        let digit = |i: usize| -> Result<bool, Failure> {
            let c = *d.get(i).ok_or_else(|| out_of_bounds("java.lang.StringIndexOutOfBoundsException", i, d.len()))?;
            if c >= 128 {
                return Err(out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", usize::from(c), 128));
            }
            Ok(char::from(c as u8).is_ascii_hexdigit())
        };
        let mut i = 0;
        while i < end {
            while i < end && ignore(d[i]) {
                i += 1;
            }
            let b1 = digit(i)?;
            i += 1;
            while i < end && ignore(d[i]) {
                i += 1;
            }
            let b2 = digit(i)?;
            i += 1;
            if !(b1 && b2) {
                return Err(Failure::of(IO_EXCEPTION, "invalid characters encountered in Hex string", Vec::new(), &[]));
            }
        }
        Ok(())
    };
    decoding().map_err(|e| caused("shaded_package.org.bouncycastle.util.encoders.DecoderException", format!("exception decoding Hex string: {}", e.message), e))
}

/// `PrivateKeyParser` / `KeyPairParser` over a PEM object's headers: whether it is an encrypted key pair (`Proc-Type`
/// `4,ENCRYPTED`), which needs a DEK-Info of two comma-separated parts whose second is hex.
fn encrypted_key(headers: &[(String, String)]) -> Result<bool, Failure> {
    let encrypted = headers.iter().any(|(name, value)| name == "Proc-Type" && value == "4,ENCRYPTED");
    if !encrypted {
        return Ok(false);
    }
    let dek_info = headers.iter().rev().find(|(name, _)| name == "DEK-Info").map(|(_, value)| value.as_str());
    let tokens: Vec<&str> = dek_info.map(|d| d.split(',').filter(|t| !t.is_empty()).collect()).unwrap_or_default();
    if tokens.len() != 2 {
        return Err(Failure::of(PEM_EXCEPTION, "malformed PEM data: missing or invalid DEK-Info header", Vec::new(), &[]));
    }
    bc_hex(tokens[1]).map_err(|e| pem_exception("exception decoding - please check password and data.", e))?;
    Ok(true)
}

/// `PEMToFile.privateKeyFromPEM` up to the key: the exception it catches, the key, or `None` for a key BouncyCastle
/// reads that is not read here.
fn read_private_key(pem: &str) -> Result<Option<Signer>, Failure> {
    const TYPES: &[&str] = &[
        "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE", "X509 CRL", "PKCS7", "CMS",
        "ATTRIBUTE CERTIFICATE", "EC PARAMETERS", "PUBLIC KEY", "RSA PUBLIC KEY", "RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY", "PRIVATE KEY",
    ];
    // `PrivateKeyInfo.getInstance` of what is not one
    let unknown = |class: &str| iae(format!("unknown object in getInstance: {class}"));
    let (kind, headers, content) = match read_pem(pem)? {
        PemRead::Nothing => return Err(null_private_key_info()),
        PemRead::Object { kind, .. } if !TYPES.contains(&kind.as_str()) => {
            return Err(Failure::of(IO_EXCEPTION, format!("unrecognised object: {kind}"), Vec::new(), &[]));
        }
        PemRead::Object { kind, headers, content } => (kind, headers, content),
    };
    match kind.as_str() {
        "PRIVATE KEY" => {
            if encrypted_key(&headers)? {
                return Err(unknown("shaded_package.org.bouncycastle.openssl.PEMEncryptedKeyPair"));
            }
            let info = bc::private_key_info(&content).map_err(|e| pem_exception(format!("problem parsing PRIVATE KEY: {}", java_string(&e)), e))?;
            jca::private_key(&info)
        }
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" => {
            if encrypted_key(&headers)? {
                return Err(unknown("shaded_package.org.bouncycastle.openssl.PEMEncryptedKeyPair"));
            }
            // the key pair parser's PEMException, wrapped once more by `KeyPairParser`
            let wrapped = |e: Failure| pem_exception(e.message.clone(), e);
            match kind.as_str() {
                "RSA PRIVATE KEY" => jca::rsa_key_pair(&bc::rsa_key_pair(&content).map_err(wrapped)?).map(Some),
                "EC PRIVATE KEY" => jca::ec_key_pair(&bc::ec_key_pair(&content).map_err(wrapped)?),
                _ => other::dsa_key_pair(&bc::dsa_key_pair(&content).map_err(wrapped)?).map(Some),
            }
        }
        _ => bc::other_object(&kind, &content).map_or(Ok(None), Err),
    }
}

/// `PrivateKeyInfo.getInstance(null)` is null, which `JcaPEMKeyConverter.getPrivateKey` dereferences.
fn null_private_key_info() -> Failure {
    const NPE: &str = "Cannot invoke \"shaded_package.org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getPrivateKeyAlgorithm()\" because \"<parameter1>\" is null";
    let npe = Failure::of("java.lang.NullPointerException", NPE, Vec::new(), &[]);
    pem_exception(format!("unable to convert key pair: {NPE}"), npe)
}

/// `PEMToFile.privateKeyFromPEM`; its failure is the `RuntimeException` it throws.
pub fn private_key_from_pem(pem: &str) -> Result<Signer, Failure> {
    read_private_key(pem)
        .map_err(|cause| caused(RUNTIME_EXCEPTION, UNREADABLE_PRIVATE_KEY, cause))?
        .ok_or_else(|| Failure::of(RUNTIME_EXCEPTION, UNREADABLE_PRIVATE_KEY, Vec::new(), &[]))
}

/// `failure` and each of its causes as `Throwable.toString` would print them, outermost first.
pub fn exception_chain(failure: &Failure) -> Vec<String> {
    let mut lines = Vec::new();
    let mut bean = Some(&failure.bean);
    for class in &failure.classes {
        let Some(at) = bean else { break };
        lines.push(match at.get("message").and_then(|m| m.as_str()) {
            Some(message) => format!("{class}: {message}"),
            None => class.to_string(),
        });
        bean = at.get("cause");
    }
    lines
}

/// `PEMToFile.x509FromPEM`: the certificate's DER; its failure is the `RuntimeException` it throws, wrapping the one
/// of `x509FromPEM(InputStream)` and `X509Factory`'s `CertificateException`.
pub fn certificate_from_pem(pem: &str) -> Result<Vec<u8>, Failure> {
    jdk::generate_certificate(pem.as_bytes()).map_err(|cause| {
        let creating = caused(RUNTIME_EXCEPTION, "Exception creating X509 from PEM", cause);
        caused(RUNTIME_EXCEPTION, format!("Exception reading X509 from PEM \n{pem}"), creating)
    })
}

/// A configuration string that is set and not blank.
pub fn not_blank(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading idp_pem_signing_failure's 8192-bit RSA key ran the modulus' Miller-Rabin test twice
    /// (1.5 s each under full-suite load), so `PUT /mockserver/oidc` outlasted the replay's 10 s request limit. The
    /// key's own factors prove the modulus composite: reading it now costs a small part of one primality test, measured
    /// side by side so the machine's load cancels out.
    #[test]
    fn a_large_rsa_key_is_read_without_testing_its_modulus_for_primality() {
        let scenario: serde_json::Value = serde_json::from_str(include_str!("../tests/scenarios/idp_pem_signing_failure.json")).unwrap();
        let step = scenario["steps"].as_array().unwrap().iter().find(|s| s["note"] == "an 8192-bit RSA key under RS512").expect("the 8192-bit step");
        let pem = step["body"]["privateKeyPem"].as_str().unwrap();
        let PemRead::Object { content, .. } = read_pem(pem).unwrap() else { panic!("a PEM object") };
        let n = num_bigint::BigUint::from_bytes_be(&bc::rsa_key_pair(&content).unwrap()[1]);
        let started = std::time::Instant::now();
        assert!(!jca::probably_prime(&n));
        let primality = started.elapsed();
        let started = std::time::Instant::now();
        let signer = private_key_from_pem(pem).unwrap();
        let reading = started.elapsed();
        assert_eq!(signer.rsa_public().map(|(n, _)| n.len()), Some(1024));
        assert!(reading * 4 < primality, "reading the key took {reading:?}, one primality test {primality:?}");
    }

    /// A key whose `p` and `q` do not multiply to its modulus is still tested: a prime modulus is refused.
    #[test]
    fn a_prime_modulus_with_unrelated_factors_is_refused() {
        // n = 2^127 - 1 (prime), p = 3, q = 5
        let int = |v: u128| {
            let bytes = v.to_be_bytes();
            bytes[bytes.iter().position(|b| *b != 0).unwrap_or(15)..].to_vec()
        };
        let ints = [0, (1u128 << 127) - 1, 65537, 7, 3, 5, 1, 1, 1].map(int);
        let failure = jca::rsa_key_pair(&ints).err().expect("refused");
        assert!(format!("{:?}", failure.bean).contains("RSA modulus is not composite"), "{:?}", failure.bean);
    }

    #[test]
    fn ecdsa_signs_with_any_digest_on_any_curve() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let key = Signer::Ec(EcKey::generate(curve));
            for algorithm in [Algorithm::Es256, Algorithm::Es384, Algorithm::Es512] {
                let signature = key.sign(algorithm, b"input").expect("signs");
                let Signer::Ec(ec) = &key else { unreachable!() };
                assert_eq!(signature.len(), 2 * ec.field_len());
                assert!(key.verify(algorithm, b"input", &signature), "{curve:?} {algorithm:?}");
                assert!(!key.verify(algorithm, b"other", &signature));
            }
            assert!(key.sign(Algorithm::Rs256, b"input").is_none());
        }
    }

    /// Keys whose reading BouncyCastle ends in an ArrayIndexOutOfBoundsException. The oracle's message
    /// is the JDK's `Index i out of bounds for length n` until its JIT compiles the throwing method, then null
    /// (OmitStackTraceInFastThrow), so no golden pins them: ours always gives the cold message, checked here
    /// against BouncyCastle 1.86's own (`tests/files/keys-index-out-of-bounds.tsv`: case, PEMException message,
    /// PKCS#8 DER in base64; from).
    #[test]
    fn index_out_of_bounds_keys_fail_with_the_cold_jdk_message() {
        use base64::Engine;
        let cases = include_str!("../tests/files/keys-index-out-of-bounds.tsv");
        for line in cases.lines().filter(|l| !l.is_empty()) {
            let [name, message, der] = line.splitn(3, '\t').collect::<Vec<_>>()[..] else { panic!("a case: {line}") };
            base64::engine::general_purpose::STANDARD.decode(der).expect("base64");
            let body: Vec<&str> = der.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
            let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", body.join("\n"));
            let Err(failure) = private_key_from_pem(&pem) else { panic!("{name}: read") };
            let text = failure.bean.to_string().replace("shaded_package.", "");
            let expected = serde_json::Value::String(message.into()).to_string();
            assert!(text.contains(&expected), "{name}: {expected} not in {text}");
        }
    }

    #[test]
    fn sec1_and_pkcs8_ec_keys_are_read() {
        use p256::pkcs8::EncodePrivateKey;
        let secret = p384::SecretKey::random(&mut rand_core::OsRng);
        // RustCrypto's SEC1 encoding has no [0] parameters, which BouncyCastle's key factory needs (the oracle
        // refuses such a key too)
        let sec1 = secret.to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
        assert!(private_key_from_pem(&sec1).is_err());
        let pkcs8 = secret.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        assert!(matches!(private_key_from_pem(&pkcs8), Ok(Signer::Ec(EcKey::P384(_)))));
        let pkcs8 = p521::SecretKey::random(&mut rand_core::OsRng).to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        assert!(matches!(private_key_from_pem(&pkcs8), Ok(Signer::Ec(EcKey::P521(_)))));
        assert!(private_key_from_pem("junk").is_err());
    }

    #[test]
    fn jdk_rsa_keys_sign_by_crt_and_check_it() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        let key = rsa::RsaPrivateKey::from_pkcs8_der(&rsa_pkcs8(2048).unwrap()).unwrap();
        let bytes = |v: &rsa::BigUint| v.to_bytes_be();
        let (p, q) = (&key.primes()[0], &key.primes()[1]);
        let one = rsa::BigUint::from(1u8);
        let dp = key.d() % (p - &one);
        let dq = key.d() % (q - &one);
        let qi = q.modpow(&(p - rsa::BigUint::from(2u8)), p);
        let crt = vec![bytes(p), bytes(q), bytes(&dp), bytes(&dq), bytes(&qi)];
        let public = PublicKey::rsa(&bytes(key.n()), &bytes(key.e()));
        for parts in [Some(crt.as_slice()), None] {
            let signer = JdkRsaKey::new(&bytes(key.n()), &bytes(key.e()), &bytes(key.d()), parts);
            let signature = signer.sign(Algorithm::Rs384, b"input").expect("signs");
            assert!(public.verify(Algorithm::Rs384, b"input", &signature));
            assert_eq!(signer.sign(Algorithm::Es256, b"input"), Err(JdkRsaFailure::NotRsa));
        }
        // a dp that is not d mod (p - 1): the CRT result fails the JDK's check
        let mut wrong = crt.clone();
        wrong[2] = bytes(&(dp + rsa::BigUint::from(2u8)));
        assert_eq!(JdkRsaKey::new(&bytes(key.n()), &bytes(key.e()), &bytes(key.d()), Some(&wrong)).sign(Algorithm::Rs256, b"input"), Err(JdkRsaFailure::CrtCheck));
        // a zero component makes it a non-CRT key, signed with d
        wrong[2] = vec![0];
        assert!(JdkRsaKey::new(&bytes(key.n()), &bytes(key.e()), &bytes(key.d()), Some(&wrong)).sign(Algorithm::Rs256, b"input").is_ok());
    }

    #[test]
    fn ec_public_keys_verify_on_the_algorithm_curve() {
        let signer = Signer::Ec(EcKey::generate(Curve::P521));
        let signature = signer.sign(Algorithm::Es512, b"input").unwrap();
        assert!(signer.public_key().verify(Algorithm::Es512, b"input", &signature));
        assert!(!signer.public_key().verify(Algorithm::Es256, b"input", &signature));
        let other = Signer::Ec(EcKey::generate(Curve::P521)).public_key();
        assert!(!other.verify(Algorithm::Es512, b"input", &signature));
    }

    #[test]
    fn algorithms_resolve_by_jwt_name() {
        assert_eq!(Algorithm::from_jwt(" es512 "), Some(Algorithm::Es512));
        assert_eq!(Algorithm::from_jwt("HS256"), None);
        assert_eq!(Algorithm::Rs384.xml_digest_method(), "http://www.w3.org/2001/04/xmldsig-more#sha384");
    }
}
