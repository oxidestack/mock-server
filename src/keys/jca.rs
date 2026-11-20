//! BouncyCastle 1.86's `JcaPEMKeyConverter` over the BC provider's RSA and EC key factories, as far as their
//! failures go: the PEMException `unable to convert key pair: ...` over the factory's `InvalidKeySpecException`
//! (an RSA private key's `unable to process key spec: <cause>` with its cause; any other key's
//! `encoded key spec not recognized: <message>` without one) or the provider's `NoSuchAlgorithmException`.
//!
//! A key pair (`RSA PRIVATE KEY`, `EC PRIVATE KEY`) has its public key converted before its private key. RSA keys are
//! validated as `RSAKeyParameters` validates a modulus; EC public points are decoded and checked on P-256, P-384 and
//! P-521 only, and private scalars checked against those curves' orders only. Keys of the provider's other algorithms
//! (DSA, EdDSA, ...) are read in [`super::other`]; the EC factory's ECDH/ECMQV OIDs are refused as it refuses them.

use num_bigint::{BigInt, BigUint, Sign};

use super::bc::{self, Asn1};
use super::{identity, java_string, pem_exception, throwable, Curve, EcKey, Failure, JdkRsaKey, Signer, UNSUPPORTED_CURVES};

const NPE: &str = "java.lang.NullPointerException";
const INVALID_KEY_SPEC: &str = "java.security.spec.InvalidKeySpecException";

/// `Throwable.getMessage()` as string concatenation prints it: `null` for none.
fn java_message(e: &Failure) -> String {
    e.bean.get("message").and_then(|m| m.as_str()).unwrap_or("null").to_string()
}

pub(super) fn npe(message: &str) -> Failure {
    throwable(NPE, Some(message.into()), None)
}

fn index_out_of_bounds(index: usize, length: usize) -> Failure {
    throwable("java.lang.ArrayIndexOutOfBoundsException", Some(format!("Index {index} out of bounds for length {length}")), None)
}

fn illegal_state(message: &str) -> Failure {
    throwable("java.lang.IllegalStateException", Some(message.into()), None)
}

/// `new PEMException("unable to convert key pair: " + e.getMessage(), e)`.
pub(super) fn unable(e: Failure) -> Failure {
    pem_exception(format!("unable to convert key pair: {}", java_message(&e)), e)
}

/// The key factories' `InvalidKeySpecException("encoded key spec not recognized: " + e.getMessage())`.
pub(super) fn not_recognized(e: Failure) -> Failure {
    unable(throwable(INVALID_KEY_SPEC, Some(format!("encoded key spec not recognized: {}", java_message(&e))), None))
}

/// The RSA key factory's `InvalidKeySpecException("unable to process key spec: " + e, e)` for a private key.
fn unable_to_process(e: Failure) -> Failure {
    unable(throwable(INVALID_KEY_SPEC, Some(format!("unable to process key spec: {}", java_string(&e))), Some(e)))
}

/// `getKeyFactory(algorithm)`'s `NoSuchAlgorithmException` for an OID the BC provider has no key factory for.
fn no_such_algorithm(oid: &[u8]) -> Failure {
    unable(throwable("java.security.NoSuchAlgorithmException", Some(format!("no such algorithm: {} for provider BC", super::dotted(oid))), None))
}

// ---------------------------------------------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------------------------------------------

const RSA_OIDS: &[&str] = &["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.7", "2.5.8.1.1"];
const EC_OID: &str = "1.2.840.10045.2.1";

/// The ECDH and ECMQV scheme OIDs (SEC 1 and X9.63) the provider maps to its EC key factory, which reads keys of
/// `id-ecPublicKey` only.
const EC_ALIAS_OIDS: &[&str] = &[
    "1.3.132.1.11.0", "1.3.132.1.11.1", "1.3.132.1.11.2", "1.3.132.1.11.3", "1.3.132.1.14.0", "1.3.132.1.14.1", "1.3.132.1.14.2",
    "1.3.132.1.14.3", "1.3.132.1.15.0", "1.3.132.1.15.1", "1.3.132.1.15.2", "1.3.132.1.15.3", "1.3.133.16.840.63.0.16",
    "1.3.133.16.840.63.0.2", "1.3.133.16.840.63.0.3",
];

/// The OIDs the shaded BC provider of the oracle has a key factory for (listed from bcprov 1.86 and checked against
/// the oracle), other than RSA's and EC's.
const OTHER_KEY_FACTORY_OIDS: &[&str] = &[
    "1.0.18033.2.2.6.1", "1.0.18033.2.2.6.10", "1.0.18033.2.2.6.11", "1.0.18033.2.2.6.12", "1.0.18033.2.2.6.13",
    "1.0.18033.2.2.6.14", "1.0.18033.2.2.6.15", "1.0.18033.2.2.6.16", "1.0.18033.2.2.6.2", "1.0.18033.2.2.6.3",
    "1.0.18033.2.2.6.4", "1.0.18033.2.2.6.5", "1.0.18033.2.2.6.6", "1.0.18033.2.2.6.7", "1.0.18033.2.2.6.8",
    "1.0.18033.2.2.6.9", "1.0.18033.2.2.7.1", "1.0.18033.2.2.7.2", "1.0.18033.2.2.7.3", "1.0.18033.2.2.7.4",
    "1.0.18033.2.2.7.5", "1.0.18033.2.2.7.6", "1.0.18033.2.2.7.7", "1.0.18033.2.2.7.8", "1.2.643.2.2.19",
    "1.2.643.2.2.20", "1.2.643.2.2.98", "1.2.643.7.1.1.1.1", "1.2.643.7.1.1.1.2", "1.2.643.7.1.1.6.1",
    "1.2.643.7.1.1.6.2", "1.2.804.2.1.1.1.1.3.1.1", "1.2.804.2.1.1.1.1.3.1.1.1.1", "1.2.840.10040.4.1",
    "1.2.840.10040.4.3", "1.2.840.10046.2.1", "1.2.840.113549.1.3.1", "1.2.840.113549.1.9.16.3.17", "1.3.101.110",
    "1.3.101.111", "1.3.101.112", "1.3.101.113", "1.3.132.1.11.0", "1.3.132.1.11.1", "1.3.132.1.11.2",
    "1.3.132.1.11.3", "1.3.132.1.14.0", "1.3.132.1.14.1", "1.3.132.1.14.2", "1.3.132.1.14.3", "1.3.132.1.15.0",
    "1.3.132.1.15.1", "1.3.132.1.15.2", "1.3.132.1.15.3", "1.3.133.16.840.63.0.16", "1.3.133.16.840.63.0.2",
    "1.3.133.16.840.63.0.3", "1.3.14.3.2.27", "1.3.14.7.2.1.1", "1.3.6.1.4.1.18227.2.1", "1.3.6.1.4.1.22554.4.2",
    "1.3.6.1.4.1.22554.5.5", "1.3.6.1.4.1.22554.5.5.1", "1.3.6.1.4.1.22554.5.5.2", "1.3.6.1.4.1.22554.5.5.3",
    "1.3.6.1.4.1.22554.5.5.4", "1.3.6.1.4.1.22554.5.5.5", "1.3.6.1.4.1.22554.5.5.6", "1.3.6.1.5.5.7.6.37",
    "1.3.6.1.5.5.7.6.38", "1.3.6.1.5.5.7.6.39", "1.3.6.1.5.5.7.6.40", "1.3.6.1.5.5.7.6.41", "1.3.6.1.5.5.7.6.42",
    "1.3.6.1.5.5.7.6.43", "1.3.6.1.5.5.7.6.44", "1.3.6.1.5.5.7.6.45", "1.3.6.1.5.5.7.6.46", "1.3.6.1.5.5.7.6.47",
    "1.3.6.1.5.5.7.6.48", "1.3.6.1.5.5.7.6.49", "1.3.6.1.5.5.7.6.50", "1.3.6.1.5.5.7.6.51", "1.3.6.1.5.5.7.6.52",
    "1.3.6.1.5.5.7.6.53", "1.3.6.1.5.5.7.6.54", "1.3.6.1.5.5.7.6.55", "1.3.6.1.5.5.7.6.56", "1.3.6.1.5.5.7.6.57",
    "1.3.6.1.5.5.7.6.58", "1.3.6.1.5.5.7.6.59", "1.3.6.1.5.5.7.6.60", "1.3.6.1.5.5.7.6.61", "1.3.6.1.5.5.7.6.62",
    "1.3.6.1.5.5.7.6.63", "1.3.6.1.5.5.7.6.64", "1.3.6.1.5.5.7.6.65", "1.3.6.1.5.5.7.6.66", "1.3.9999.3.11",
    "1.3.9999.3.14", "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19",
    "2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.21", "2.16.840.1.101.3.4.3.22", "2.16.840.1.101.3.4.3.23",
    "2.16.840.1.101.3.4.3.24", "2.16.840.1.101.3.4.3.25", "2.16.840.1.101.3.4.3.26", "2.16.840.1.101.3.4.3.27",
    "2.16.840.1.101.3.4.3.28", "2.16.840.1.101.3.4.3.29", "2.16.840.1.101.3.4.3.30", "2.16.840.1.101.3.4.3.31",
    "2.16.840.1.101.3.4.3.32", "2.16.840.1.101.3.4.3.33", "2.16.840.1.101.3.4.3.34", "2.16.840.1.101.3.4.3.35",
    "2.16.840.1.101.3.4.3.36", "2.16.840.1.101.3.4.3.37", "2.16.840.1.101.3.4.3.38", "2.16.840.1.101.3.4.3.39",
    "2.16.840.1.101.3.4.3.40", "2.16.840.1.101.3.4.3.41", "2.16.840.1.101.3.4.3.42", "2.16.840.1.101.3.4.3.43",
    "2.16.840.1.101.3.4.3.44", "2.16.840.1.101.3.4.3.45", "2.16.840.1.101.3.4.3.46", "2.16.840.1.101.3.4.4.1",
    "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.3", "2.16.840.1.114027.80.4.1",
];

/// The product of the odd primes up to 743 (`BigIntegers.SMALL_PRIMES_PRODUCT`).
const SMALL_PRIMES_PRODUCT: &str = "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f";

/// `BigInteger.bitLength`.
fn bit_length(x: &BigInt) -> u64 {
    if x.sign() == Sign::Minus { (-x - BigInt::from(1)).bits() } else { x.bits() }
}

fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let (mut a, mut b) = (a.magnitude().clone(), b.magnitude().clone());
    while b != BigUint::ZERO {
        (a, b) = (b.clone(), a % b);
    }
    BigInt::from(a)
}

/// A Miller-Rabin probable-prime test (`Primes.enhancedMRProbablePrimeTest` finds no witness), on `rsa`'s big
/// integers, which the dev profile optimises (an 8192-bit modulus).
pub(super) fn probably_prime(n: &BigUint) -> bool {
    use rsa::BigUint as Big;
    if !n.bit(0) {
        return *n == BigUint::from(2u8);
    }
    let n = Big::from_bytes_be(&n.to_bytes_be());
    let (one, two) = (Big::from(1u8), Big::from(2u8));
    if n < Big::from(4u8) {
        return n >= two;
    }
    let m = &n - &one;
    let s = m.trailing_zeros().unwrap_or(0);
    let d = &m >> s;
    'bases: for base in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71] {
        let a = Big::from(base);
        if a >= m {
            continue;
        }
        let mut x = a.modpow(&d, &n);
        if x == one || x == m {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, &n);
            if x == m {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

/// `RSAKeyParameters.validate`: the exception for a modulus BouncyCastle refuses.
/// `factors` are the key's own `p` and `q` where it has them: when they are both above 1 and multiply to `n`, `n` is
/// composite, and the Miller-Rabin test, which could only say so too, is skipped. On an 8192-bit modulus that test is
/// one full-size `modpow` per call, 0.3 s in a test build and 1.5 s under full-suite load, and a PEM key is validated
/// twice (public, then private key): `PUT /mockserver/oidc` with idp_pem_signing_failure's 8192-bit key outlasted the
/// replay's 10 s request limit, so its provider was registered after the scenario's `/token` step.
fn validate_modulus(n: &BigInt, factors: Option<(&[u8], &[u8])>) -> Result<(), Failure> {
    let illegal = |m: &str| Failure::illegal(m);
    if !n.bit(0) {
        return Err(illegal("RSA modulus is even"));
    }
    if bit_length(n) > 16384 {
        return Err(illegal("RSA modulus out of range"));
    }
    // `BigIntegers.hasAnySmallFactors` / `modOddIsCoprimeVar`, the larger number as the modulus
    let product = BigInt::parse_bytes(SMALL_PRIMES_PRODUCT.as_bytes(), 16).expect("hex");
    let coprime = if bit_length(n) < bit_length(&product) {
        let x = ((n % &product) + &product) % &product;
        x == BigInt::from(1) || gcd(&x, &product) == BigInt::from(1)
    } else {
        if n.sign() != Sign::Plus {
            return Err(throwable("java.lang.ArithmeticException", Some("BigInteger: modulus not positive".into()), None));
        }
        gcd(n, &product) == BigInt::from(1)
    };
    if !coprime {
        return Err(illegal("RSA modulus has a small prime factor"));
    }
    if *n < BigInt::from(2u8) {
        return Err(illegal("'candidate' must be non-null and >= 2"));
    }
    let one = BigInt::from(1);
    let factored = factors.map(|(p, q)| (BigInt::from_signed_bytes_be(p), BigInt::from_signed_bytes_be(q))).is_some_and(|(p, q)| p > one && q > one && &p * &q == *n);
    if !factored && probably_prime(n.magnitude()) {
        return Err(illegal("RSA modulus is not composite"));
    }
    Ok(())
}

/// The key BouncyCastle's RSA key factory makes of an `RSAPrivateKey`'s nine INTEGERs, or its exception.
fn rsa_private(ints: &[Vec<u8>]) -> Result<Signer, Failure> {
    validate_modulus(&BigInt::from_signed_bytes_be(&ints[1]), Some((&ints[4], &ints[5])))?;
    Ok(Signer::Jdk(JdkRsaKey::from_integers(ints)))
}

/// `getKeyPair` of an `RSA PRIVATE KEY` (its nine INTEGERs): the public key (`RSAPublicKey` reads the modulus and
/// exponent as unsigned), then the private key.
pub(super) fn rsa_key_pair(ints: &[Vec<u8>]) -> Result<Signer, Failure> {
    let (n, e) = (BigInt::from_bytes_be(Sign::Plus, &ints[1]), BigInt::from_bytes_be(Sign::Plus, &ints[2]));
    if !e.bit(0) {
        return Err(not_recognized(Failure::illegal("RSA publicExponent is even")));
    }
    validate_modulus(&n, Some((&ints[4], &ints[5]))).map_err(not_recognized)?;
    rsa_private(ints).map_err(unable_to_process)
}

/// The RSA key factory over a `PrivateKeyInfo`'s private key octets.
fn rsa_private_key_info(octets: &[u8]) -> Result<Signer, Failure> {
    let ints = match bc::from_byte_array(octets).map_err(unable_to_process)? {
        None => return Err(unable_to_process(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.pkcs.RSAPrivateKey.getCoefficient()\" because \"<local3>\" is null"))),
        Some(object) => bc::rsa_private_key(bc::sequence_of(&object).map_err(unable_to_process)?).map_err(unable_to_process)?,
    };
    rsa_private(&ints).map_err(unable_to_process)
}

// ---------------------------------------------------------------------------------------------------------------
// EC
// ---------------------------------------------------------------------------------------------------------------

/// The named curves BouncyCastle 1.86 knows (`ECUtil.getNamedCurveByOid`, checked against the oracle).
const NAMED_CURVES: &[&str] = &[
    "1.2.156.10197.1.301", "1.2.156.10197.1.301.101", "1.2.156.11235.1.1.1", "1.2.250.1.223.101.256.1", "1.2.643.2.2.35.1",
    "1.2.643.2.2.35.2", "1.2.643.2.2.35.3", "1.2.643.2.2.36.0", "1.2.643.2.2.36.1", "1.2.643.7.1.2.1.1.1", "1.2.643.7.1.2.1.1.2",
    "1.2.643.7.1.2.1.1.3", "1.2.643.7.1.2.1.1.4", "1.2.643.7.1.2.1.2.1", "1.2.643.7.1.2.1.2.2", "1.2.643.7.1.2.1.2.3",
    "1.2.840.10045.3.0.1", "1.2.840.10045.3.0.10", "1.2.840.10045.3.0.11", "1.2.840.10045.3.0.12", "1.2.840.10045.3.0.13",
    "1.2.840.10045.3.0.16", "1.2.840.10045.3.0.17", "1.2.840.10045.3.0.18", "1.2.840.10045.3.0.19", "1.2.840.10045.3.0.2",
    "1.2.840.10045.3.0.20", "1.2.840.10045.3.0.3", "1.2.840.10045.3.0.4", "1.2.840.10045.3.0.5", "1.2.840.10045.3.0.6",
    "1.2.840.10045.3.0.7", "1.2.840.10045.3.1.1", "1.2.840.10045.3.1.2", "1.2.840.10045.3.1.3", "1.2.840.10045.3.1.4",
    "1.2.840.10045.3.1.5", "1.2.840.10045.3.1.6", "1.2.840.10045.3.1.7", "1.3.132.0.1", "1.3.132.0.10", "1.3.132.0.15",
    "1.3.132.0.16", "1.3.132.0.17", "1.3.132.0.2", "1.3.132.0.22", "1.3.132.0.23", "1.3.132.0.24", "1.3.132.0.25", "1.3.132.0.26",
    "1.3.132.0.27", "1.3.132.0.28", "1.3.132.0.29", "1.3.132.0.3", "1.3.132.0.30", "1.3.132.0.31", "1.3.132.0.32", "1.3.132.0.33",
    "1.3.132.0.34", "1.3.132.0.35", "1.3.132.0.36", "1.3.132.0.37", "1.3.132.0.38", "1.3.132.0.39", "1.3.132.0.4", "1.3.132.0.5",
    "1.3.132.0.6", "1.3.132.0.7", "1.3.132.0.8", "1.3.132.0.9", "1.3.36.3.3.2.8.1.1.1", "1.3.36.3.3.2.8.1.1.10",
    "1.3.36.3.3.2.8.1.1.11", "1.3.36.3.3.2.8.1.1.12", "1.3.36.3.3.2.8.1.1.13", "1.3.36.3.3.2.8.1.1.14", "1.3.36.3.3.2.8.1.1.2",
    "1.3.36.3.3.2.8.1.1.3", "1.3.36.3.3.2.8.1.1.4", "1.3.36.3.3.2.8.1.1.5", "1.3.36.3.3.2.8.1.1.6", "1.3.36.3.3.2.8.1.1.7",
    "1.3.36.3.3.2.8.1.1.8", "1.3.36.3.3.2.8.1.1.9",
];

/// A NIST curve's field prime, `b` (`a` is `-3`), order and field length in octets, and BouncyCastle's field element
/// class.
struct Nist {
    p: &'static str,
    b: &'static str,
    n: &'static str,
    len: usize,
    element: &'static str,
}

fn nist(curve: Curve) -> Nist {
    match curve {
        Curve::P256 => Nist {
            p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            len: 32,
            element: "SecP256R1FieldElement",
        },
        Curve::P384 => Nist {
            p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            len: 48,
            element: "SecP384R1FieldElement",
        },
        Curve::P521 => Nist {
            p: "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            b: "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            n: "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            len: 66,
            element: "SecP521R1FieldElement",
        },
    }
}

fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("hex")
}

/// The curve of an EC key, as BouncyCastle's key factory finds it.
enum EcCurve {
    Nist(Curve),
    /// a curve the JDK cannot sign on: [`Signer::UnsupportedCurve`]'s text and where its domain
    /// parameters come from
    Unsupported(String, Domain),
    /// a curve BouncyCastle knows that is not modelled
    Unmodelled,
}

/// The domain parameters of an [`EcCurve::Unsupported`] curve: a named curve's OID content, or explicit
/// `SpecifiedECDomain` elements.
enum Domain {
    Named(Vec<u8>),
    Explicit(Vec<Asn1>),
}

impl Domain {
    /// The key BouncyCastle signs with: the private scalar `d` on these parameters, `None` where they are not
    /// modelled or `d` is negative.
    fn key(&self, d: &BigInt) -> Option<Box<super::ecdsa::EcDomainKey>> {
        let d = d.to_biguint()?.to_bytes_be();
        match self {
            Domain::Named(oid) => super::ecdsa::EcDomainKey::named(oid, &d),
            Domain::Explicit(domain) => super::ecdsa::EcDomainKey::explicit(domain, &d),
        }
        .map(Box::new)
    }
}

/// `X962Parameters.getInstance` and `EC5Util.getCurve` over an EC key's algorithm parameters.
fn ec_curve(parameters: Option<&Asn1>) -> Result<EcCurve, Failure> {
    match parameters {
        None => Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x9.X962Parameters.isNamedCurve()\" because \"<parameter2>\" is null")),
        Some(Asn1::Other("DERNull")) => Err(npe(
            "Cannot invoke \"shaded_package.org.bouncycastle.jce.spec.ECParameterSpec.getCurve()\" because the return value of \"shaded_package.org.bouncycastle.jcajce.provider.config.ProviderConfiguration.getEcImplicitlyCa()\" is null",
        )),
        Some(Asn1::Oid(oid)) => {
            const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
            const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
            Ok(match oid.as_slice() {
                P256 => EcCurve::Nist(Curve::P256),
                P384 => EcCurve::Nist(Curve::P384),
                P521 => EcCurve::Nist(Curve::P521),
                _ => match UNSUPPORTED_CURVES.iter().find(|(o, _)| *o == oid.as_slice()) {
                    Some((_, Some(name))) => EcCurve::Unsupported(format!("{name} ({})", super::dotted(oid)), Domain::Named(oid.clone())),
                    Some((_, None)) => EcCurve::Unsupported(identity("shaded_package.org.bouncycastle.jce.spec.ECNamedCurveSpec"), Domain::Named(oid.clone())),
                    None if NAMED_CURVES.contains(&super::dotted(oid).as_str()) => EcCurve::Unmodelled,
                    None => return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x9.X9ECParameters.getCurve()\" because \"<local5>\" is null")),
                },
            })
        }
        Some(Asn1::Sequence(domain, _)) if domain.is_empty() => Err(index_out_of_bounds(0, 0)),
        Some(Asn1::Sequence(domain, _)) => explicit_curve(domain),
        Some(other) => Err(Failure::illegal(format!("unknown object in getInstance: {}", other.class()))),
    }
}

/// Explicit `SpecifiedECDomain` parameters (version, fieldID, curve, base, order, cofactor), read and their base
/// point decoded as BouncyCastle does ([`super::ecdsa::EcDomainKey::read`]; its refusal's message, whose
/// class the caller's `encoded key spec not recognized` drops): a prime field's NIST curve as the JDK finds it, any
/// other prime- or binary-field curve [`EcCurve::Unsupported`]; anything else is not modelled.
fn explicit_curve(domain: &[Asn1]) -> Result<EcCurve, Failure> {
    const PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
    let read = super::ecdsa::EcDomainKey::read(domain).map_err(Failure::illegal)?;
    let (Some(Asn1::Sequence(field, _)), Some(Asn1::Integer(order))) = (domain.get(1), domain.get(4)) else { return Ok(EcCurve::Unmodelled) };
    let nist_curve = match &field[..] {
        [Asn1::Oid(field_type), Asn1::Integer(p)] if field_type == PRIME_FIELD => {
            let (p, order) = (BigUint::from_bytes_be(p), BigUint::from_bytes_be(order));
            [Curve::P256, Curve::P384, Curve::P521].into_iter().find(|c| hex(nist(*c).p) == p && hex(nist(*c).n) == order)
        }
        // a binary field's parameters that `read` does not model
        _ if read.is_none() => return Ok(EcCurve::Unmodelled),
        _ => None,
    };
    Ok(match nist_curve {
        Some(curve) => EcCurve::Nist(curve),
        None => EcCurve::Unsupported(identity("java.security.spec.ECParameterSpec"), Domain::Explicit(domain.to_vec())),
    })
}

/// `ECCurve.decodePoint` and `ECPublicKeyParameters`' check of a public point's octets on a NIST curve, after the
/// key factory's reading of a legacy OCTET STRING encoding: the exception's message.
fn decode_point(curve: Curve, data: &[u8]) -> Result<(), Failure> {
    let spec = nist(curve);
    let (p, b) = (hex(spec.p), hex(spec.b));
    let mut encoded = data;
    // `BCECPublicKey.populateFromPubKeyInfo`
    let at = |i: usize| data.get(i).copied().ok_or_else(|| index_out_of_bounds(i, data.len()));
    if at(0)? == 0x04 && i64::from(at(1)? as i8) == data.len() as i64 - 2 && matches!(at(2)?, 2 | 3) && spec.len >= data.len() - 3 {
        encoded = &data[2..];
    }
    let element = |x: &[u8]| -> Result<BigUint, Failure> {
        let x = BigUint::from_bytes_be(x);
        if x >= p {
            return Err(Failure::illegal(format!("x value invalid for {}", spec.element)));
        }
        Ok(x)
    };
    let rhs = |x: &BigUint| (x * x * x + &b + &p * 3u8 - (x * 3u8) % &p) % &p;
    let illegal = |m: &str| Err(Failure::illegal(m));
    let ty = *encoded.first().ok_or_else(|| index_out_of_bounds(0, 0))?;
    match ty {
        0x00 => {
            if encoded.len() != 1 {
                return illegal("Incorrect length for infinity encoding");
            }
            illegal("Point at infinity")
        }
        0x02 | 0x03 => {
            if encoded.len() != spec.len + 1 {
                return illegal("Incorrect length for compressed encoding");
            }
            let x = element(&encoded[1..])?;
            let alpha = rhs(&x);
            let y = alpha.modpow(&((&p + 1u8) >> 2), &p);
            if (&y * &y) % &p != alpha {
                return illegal("Invalid point compression");
            }
            Ok(())
        }
        0x04 | 0x06 | 0x07 => {
            if encoded.len() != 2 * spec.len + 1 {
                return illegal(if ty == 0x04 { "Incorrect length for uncompressed encoding" } else { "Incorrect length for hybrid encoding" });
            }
            let (x, y) = (BigUint::from_bytes_be(&encoded[1..=spec.len]), BigUint::from_bytes_be(&encoded[spec.len + 1..]));
            if ty != 0x04 && y.bit(0) != (ty == 0x07) {
                return illegal("Inconsistent Y coordinate in hybrid encoding");
            }
            let (x, y) = (element(&x.to_bytes_be())?, element(&y.to_bytes_be())?);
            if (&y * &y) % &p != rhs(&x) {
                return illegal("Invalid point coordinates");
            }
            Ok(())
        }
        _ => illegal(&format!("Invalid point encoding 0x{ty:x}")),
    }
}

/// `ECPrivateKey.getObjectInTag(tagNo, baseTag)`: the object of the first context tag `no` among `items`, which must
/// be explicit (and a BIT STRING when `bit_string`).
fn object_in_tag(items: &[Asn1], no: u32, bit_string: bool) -> Result<Option<Asn1>, Failure> {
    let Some(tagged) = items.iter().find(|o| matches!(o, Asn1::Tagged { class: 0x80, no: n, .. } if *n == no)) else { return Ok(None) };
    let object = tagged.explicit().ok_or_else(|| illegal_state("object implicit - explicit expected."))?;
    if bit_string && !matches!(object, Asn1::BitString(..)) {
        return Err(illegal_state("unexpected explicit encoding"));
    }
    Ok(Some(object.clone()))
}

/// The private scalar of an EC-style key class's private key (`BCECPrivateKey` and its GOST and DSTU twins): a bare
/// INTEGER's signed value, else `ECPrivateKey.getInstance(key)`'s `getKey()` and `getPublicKey()`; `local` names the
/// variable a missing key's NullPointerException reports.
pub(super) fn ec_scalar(key: Option<Asn1>, local: &str) -> Result<BigInt, Failure> {
    match key {
        None => Err(npe(&format!("Cannot invoke \"shaded_package.org.bouncycastle.asn1.sec.ECPrivateKey.getKey()\" because \"{local}\" is null"))),
        Some(Asn1::Integer(bytes)) => Ok(BigInt::from_signed_bytes_be(&bytes)),
        Some(object) => {
            let items = bc::sequence_of(&object)?;
            let octets = match items.get(1) {
                None => return Err(index_out_of_bounds(1, items.len())),
                Some(Asn1::OctetString(_, octets)) => octets,
                Some(other) => return Err(bc::cast(other, "ASN1OctetString")),
            };
            let d = BigInt::from_bytes_be(Sign::Plus, octets);
            object_in_tag(items, 1, true)?;
            Ok(d)
        }
    }
}

/// The NIST curve the named curve `oid` (its content octets) is.
pub(super) fn nist_named(oid: &[u8]) -> Option<Curve> {
    match ec_curve(Some(&Asn1::Oid(oid.to_vec()))) {
        Ok(EcCurve::Nist(c)) => Some(c),
        _ => None,
    }
}

/// The NIST curve explicit `SpecifiedECDomain` parameters are, as SunEC matches them (prime and order).
pub(super) fn nist_explicit(domain: &[Asn1]) -> Option<Curve> {
    match explicit_curve(domain) {
        Ok(EcCurve::Nist(c)) => Some(c),
        _ => None,
    }
}

/// The key `d` on the NIST curve `curve`; `None` for a scalar outside `[1, n - 1]`.
pub(super) fn nist_key(curve: Curve, d: &BigInt) -> Option<EcKey> {
    let n = BigInt::from_biguint(Sign::Plus, hex(nist(curve).n));
    if d < &BigInt::from(1) || d >= &n {
        return None;
    }
    EcKey::from_scalar(curve, &super::fixed_len(&d.magnitude().to_bytes_be(), nist(curve).len)?)
}

/// Whether `ECUtil.getNamedCurveByOid` knows the curve `oid` (its content octets).
pub(super) fn bc_named_curve(oid: &[u8]) -> bool {
    UNSUPPORTED_CURVES.iter().any(|(o, _)| *o == oid) || NAMED_CURVES.contains(&super::dotted(oid).as_str())
}

/// The EC key factory's private key from an `ECPrivateKey` (or a bare INTEGER) on `curve`: the exception, before
/// it is wrapped.
fn ec_private(curve: &EcCurve, key: Option<Asn1>) -> Result<Option<Signer>, Failure> {
    let d = ec_scalar(key, "<local5>")?;
    Ok(match curve {
        EcCurve::Nist(c) => {
            let n = BigInt::from_biguint(Sign::Plus, hex(nist(*c).n));
            if d < BigInt::from(1) || d >= n {
                return Err(Failure::illegal("Scalar is not in the interval [1, n - 1]"));
            }
            let d = super::fixed_len(&d.magnitude().to_bytes_be(), nist(*c).len).expect("d < n");
            Some(Signer::Ec(EcKey::from_scalar(*c, &d).expect("d in [1, n - 1]")))
        }
        EcCurve::Unsupported(text, domain) => Some(Signer::UnsupportedCurve(text.clone(), domain.key(&d))),
        EcCurve::Unmodelled => None,
    })
}

/// `getKeyPair` of an `EC PRIVATE KEY` (its elements): PEMParser's parameters and public key (each failure a
/// `problem creating EC private key` PEMException, wrapped once more by `KeyPairParser`), then the public key and
/// the private key. `Ok(None)` for a key pair without a public key (`JcaPEMKeyConverter`'s NullPointerException is
/// the caller's) is not returned: that case is `Err`.
pub(super) fn ec_key_pair(items: &[Asn1]) -> Result<Option<Signer>, Failure> {
    let problem = |e: Failure| {
        let parser = pem_exception(format!("problem creating EC private key: {}", java_string(&e)), e);
        pem_exception(parser.message.clone(), parser)
    };
    let parameters = object_in_tag(items, 0, false).map_err(problem)?;
    let public = match object_in_tag(items, 1, true).map_err(problem)? {
        None => {
            const NULL_PUBLIC: &str = "Cannot invoke \"shaded_package.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getEncoded()\" because the return value of \"shaded_package.org.bouncycastle.openssl.PEMKeyPair.getPublicKeyInfo()\" is null";
            return Err(unable(npe(NULL_PUBLIC)));
        }
        // `ASN1BitString.getBytes`: the pad bits of the last byte cleared (a non-octet-aligned public key is read)
        Some(Asn1::BitString(_, pad, mut bytes)) => {
            if let Some(last) = bytes.last_mut() {
                *last &= 0xffu8.checked_shl(u32::from(pad)).unwrap_or(0);
            }
            bytes
        }
        Some(_) => return Err(problem(illegal_state("attempt to get non-octet aligned data from BIT STRING"))),
    };
    let curve = ec_curve(parameters.as_ref()).map_err(not_recognized)?;
    match &curve {
        EcCurve::Nist(c) => decode_point(*c, &public).map_err(not_recognized)?,
        EcCurve::Unsupported(_, domain) => {
            let (elements, named) = match domain {
                Domain::Named(oid) => (super::ecdsa::EcDomainKey::named_domain(oid), Some(oid.as_slice())),
                Domain::Explicit(elements) => (Some(elements.clone()), None),
            };
            if let Some(elements) = elements {
                super::ecdsa::EcDomainKey::check_public_point(&elements, &public, named).map_err(|m| not_recognized(Failure::illegal(m)))?;
            }
        }
        EcCurve::Unmodelled => {}
    }
    ec_private(&curve, Some(Asn1::Sequence(items.to_vec(), false))).map_err(not_recognized)
}

/// `getPrivateKey` of a `PRIVATE KEY`: its algorithm's key factory over the PrivateKeyInfo, the other algorithms'
/// in [`super::other`]. `Ok(None)` for a key of another algorithm the provider converts, which is not modelled.
pub(super) fn private_key(info: &bc::PrivateKeyInfo) -> Result<Option<Signer>, Failure> {
    let oid = super::dotted(&info.algorithm);
    if RSA_OIDS.contains(&oid.as_str()) {
        return rsa_private_key_info(&info.key).map(Some);
    }
    if oid == EC_OID {
        let curve = ec_curve(info.parameters.as_ref()).map_err(not_recognized)?;
        let key = bc::from_byte_array(&info.key).map_err(not_recognized)?;
        return ec_private(&curve, key).map_err(not_recognized);
    }
    if EC_ALIAS_OIDS.contains(&oid.as_str()) {
        // the EC key factory reads `id-ecPublicKey` keys only
        let message = format!("algorithm identifier {oid} in key not recognised");
        return Err(not_recognized(throwable("java.io.IOException", Some(message), None)));
    }
    if let Some(key) = super::other::private_key(&oid, info) {
        return key;
    }
    if OTHER_KEY_FACTORY_OIDS.contains(&oid.as_str()) {
        return Ok(None);
    }
    Err(no_such_algorithm(&info.algorithm))
}
