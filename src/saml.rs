//! A mock SAML 2.0 identity provider (`org.mockserver.saml`): `PUT /mockserver/saml` registers a provider (its
//! signing credential supplied as PEM, or a self-signed one generated) and adds expectations for the IdP metadata and
//! the SSO and Single-Logout endpoints, answered by built-in callback classes. Each SSO/SLO request mints a fresh
//! `Response`/`LogoutResponse`, enveloped-signed with XML-DSig (exclusive C14N, RSA or ECDSA), returned as an
//! auto-POST form. Providers live until `reset`.
//!
//! The documents are built here, so their canonical form is too: `Element` serialises once as the JDK's
//! `Transformer` writes it (the document) and once as exclusive C14N (the digest and signature input).

use std::sync::Arc;

use base64::Engine;
use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::class_callback::{CallbackClass, CallbackError, ResponseCallback};
use crate::keys::{Algorithm, JdkRsaFailure, Signer, der, not_blank};
use crate::recorded::Failure;
use crate::request::HttpRequest;
use crate::state::State;

const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SSO_CLASS: &str = "org.mockserver.saml.SamlSsoCallback";
const SLO_CLASS: &str = "org.mockserver.saml.SamlSloCallback";
const CONFIG_CLASS: &str = "org.mockserver.saml.SamlProviderConfiguration";
const MAX_DECODED_SAML_REQUEST_BYTES: usize = 64 * 1024;
const MAX_INFLATED_SAML_REQUEST_BYTES: usize = 1024 * 1024;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// ---------------------------------------------------------------------------------------------------------------
// Configuration (`SamlProviderConfiguration`)
// ---------------------------------------------------------------------------------------------------------------

/// Strings are `None` where Jackson would set the field to null.
#[derive(Debug, Clone)]
struct Config {
    idp_entity_id: Option<String>,
    sso_service_url: Option<String>,
    metadata_url: Option<String>,
    sp_entity_id: Option<String>,
    assertion_consumer_service_url: Option<String>,
    slo_service_url: Option<String>,
    sp_single_logout_service_url: Option<String>,
    subject_name_id: Option<String>,
    name_id_format: Option<String>,
    attributes: Option<Vec<(String, Option<String>)>>,
    session_duration_seconds: i64,
    signing_algorithm: Option<String>,
    expired_assertion: bool,
    wrong_audience: bool,
    tampered_signature: bool,
    signing_certificate_pem: Option<String>,
    signing_private_key_pem: Option<String>,
}

fn bind(body: &str) -> Result<Config, Failure> {
    use crate::chaos::bind::{Bean, BindError};
    let tree = if body.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        crate::chaos::read_tree(body, false).map_err(|e| crate::chaos::bind::parse_failure(body, &e))?
    };
    if tree.is_null() {
        // Jackson reads a `null` body as a null configuration, which the generator rejects
        return Err("SAML provider configuration is required".into());
    }
    let source = |e: BindError| e.failure(body);
    let b = Bean::of(&tree, CONFIG_CLASS).map_err(source)?;
    // an explicit null sets the field to null; an absent property keeps the default
    let present = |name: &str| b.map().keys().any(|k| k.eq_ignore_ascii_case(name));
    let text = |name: &str, default: &str| -> Result<Option<String>, Failure> {
        match b.string(name).map_err(source)? {
            Some(v) => Ok(Some(v)),
            None if present(name) => Ok(None),
            None => Ok(Some(default.to_string())),
        }
    };
    // primitive `long` and `boolean` fields: an explicit null reads as 0/false, an absent property keeps the default
    let primitive_long = |name: &str, default: i64| -> Result<i64, Failure> { Ok(b.primitive_long(name).map_err(source)?.unwrap_or(default)) };
    let primitive_boolean = |name: &str| -> Result<bool, Failure> { Ok(b.primitive_boolean(name).map_err(source)?.unwrap_or(false)) };
    let attributes = match b.string_map("attributes").map_err(source)? {
        Some(map) => Some(map),
        None if present("attributes") => None,
        None => Some(Vec::new()),
    };
    Ok(Config {
        idp_entity_id: text("idpEntityId", "http://localhost:1080/saml/idp")?,
        sso_service_url: text("ssoServiceUrl", "/saml/sso")?,
        metadata_url: text("metadataUrl", "/saml/metadata")?,
        sp_entity_id: text("spEntityId", "http://localhost:8080/saml/sp")?,
        assertion_consumer_service_url: text("assertionConsumerServiceUrl", "http://localhost:8080/saml/acs")?,
        slo_service_url: text("sloServiceUrl", "/saml/logout")?,
        sp_single_logout_service_url: text("spSingleLogoutServiceUrl", "http://localhost:8080/saml/slo")?,
        subject_name_id: text("subjectNameId", "mock-user@example.com")?,
        name_id_format: text("nameIdFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")?,
        attributes,
        session_duration_seconds: primitive_long("sessionDurationSeconds", 3600)?,
        signing_algorithm: b.string("signingAlgorithm").map_err(source)?,
        expired_assertion: primitive_boolean("expiredAssertion")?,
        wrong_audience: primitive_boolean("wrongAudience")?,
        tampered_signature: primitive_boolean("tamperedSignature")?,
        signing_certificate_pem: b.string("signingCertificatePem").map_err(source)?,
        signing_private_key_pem: b.string("signingPrivateKeyPem").map_err(source)?,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Signing credential (`SamlSigningCredential`)
// ---------------------------------------------------------------------------------------------------------------

struct Credential {
    signer: Signer,
    certificate_der: Vec<u8>,
    algorithm: Algorithm,
}

impl Credential {
    /// The XML-DSig `SignatureValue` bytes. For a key of the other family the JDK's `Signature.initSign` throws an
    /// `InvalidKeyException` (BouncyCastle's EC key class named by the RSA signer, the key's algorithm by the EC
    /// one), which `DOMXMLSignature.sign` wraps in an `XMLSignatureException`. A PEM RSA key's own failures are
    /// [`rsa_failure`]'s. A key of another algorithm is refused the same way, by its own class or
    /// algorithm name, except a GOST key, which BouncyCastle signs with under an ES algorithm. Any other signing
    /// failure has no probed chain: `None`, a causeless wrapper.
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Option<CallbackError>> {
        if let Signer::Jdk(key) = &self.signer && self.algorithm.is_rsa() {
            return key.rsassa(self.algorithm, input).map_err(|failure| rsa_failure(key, failure));
        }
        let refused = |message: String| {
            Some(
                CallbackError::of("javax.xml.crypto.dsig.XMLSignatureException", format!("java.security.InvalidKeyException: {message}"))
                    .caused_by(CallbackError::of("java.security.InvalidKeyException", message)),
            )
        };
        let not_rsa = |class: &str| format!("Supplied key ({class}) is not a RSAPrivateKey instance");
        if let Signer::Other(key) = &self.signer {
            // a GOST or DSTU key is an ECPrivateKey: BouncyCastle's ECDSA signs with it on its own curve
            return match self.signer.sign(self.algorithm, input) {
                Some(signature) => Ok(signature),
                None if self.algorithm.is_rsa() => Err(refused(not_rsa(&key.class_name()))),
                // a generic composite key's null algorithm fails the provider selection's name comparison
                None if key.algorithm.is_none() => {
                    Err(Some(CallbackError::of("java.lang.NullPointerException", "Cannot invoke \"String.equals(Object)\" because \"<local2>\" is null")))
                }
                // a key of another algorithm, or a GOST or DSTU key without curve parameters
                None => Err(refused(format!("Not an EC key: {}", key.algorithm.as_deref().unwrap_or_default()))),
            };
        }
        self.signer.sign(self.algorithm, input).ok_or_else(|| {
            if self.signer.is_rsa() == self.algorithm.is_rsa() {
                return None;
            }
            refused(if self.algorithm.is_rsa() {
                not_rsa("shaded_package.org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey")
            } else {
                format!("Not an EC key: {}", self.signer.family())
            })
        })
    }

    fn certificate_base64(&self) -> String {
        B64.encode(&self.certificate_der)
    }
}

/// The chain of a PEM RSA key's signing failure. The JDK's provider selection gives the key to SunRsaSign
/// unless `initSign` refuses it: below 512 bits (its length rounded up to a whole byte) or too short for the
/// algorithm's DigestInfo. BouncyCastle then signs: its `PKCS1Encoding` throws `input data too large` for a short
/// key, its `RSABlindedEngine` a failed CRT self-check, each of which `DigestSignatureSpi` rethrows as a
/// `SignatureException` of the exception's text without a cause. SunRsaSign's own CRT self-check throws
/// `BadPaddingException`, which `RSASignature.engineSign` wraps.
fn rsa_failure(key: &crate::keys::JdkRsaKey, failure: JdkRsaFailure) -> Option<CallbackError> {
    let bouncy_castle = |cause: &str| {
        let message = format!("java.security.SignatureException: {cause}");
        CallbackError::of("javax.xml.crypto.dsig.XMLSignatureException", message).caused_by(CallbackError::of("java.security.SignatureException", cause))
    };
    match failure {
        JdkRsaFailure::TooShort => Some(bouncy_castle("java.lang.IllegalArgumentException: input data too large")),
        JdkRsaFailure::CrtCheck if key.modulus_bits().div_ceil(8) * 8 < 512 => {
            Some(bouncy_castle("java.lang.IllegalStateException: RSA engine faulty decryption/signing detected"))
        }
        JdkRsaFailure::CrtCheck => Some(
            CallbackError::of("javax.xml.crypto.dsig.XMLSignatureException", "java.security.SignatureException: Could not sign data").caused_by(
                CallbackError::of("java.security.SignatureException", "Could not sign data")
                    .caused_by(CallbackError::of("javax.crypto.BadPaddingException", "RSA private key operation failed")),
            ),
        ),
        JdkRsaFailure::NotRsa | JdkRsaFailure::KeySize => None,
    }
}

/// `SamlSigningCredential.from`: the supplied PEM pair (the key parsed first), else a self-signed credential. The
/// algorithm is `resolveAlgorithm`'s: the JWT name, RS256 when unset or unknown. A PEM that cannot be read fails
/// with `PEMToFile`'s RuntimeException, which the endpoint's generic handler reports.
fn credential(config: &Config) -> Result<Credential, Failure> {
    let algorithm = config.signing_algorithm.as_deref().and_then(Algorithm::from_jwt).unwrap_or(Algorithm::Rs256);
    if let (Some(cert_pem), Some(key_pem)) = (not_blank(&config.signing_certificate_pem), not_blank(&config.signing_private_key_pem)) {
        let signer = crate::keys::private_key_from_pem(key_pem)?;
        let certificate_der = crate::keys::certificate_from_pem(cert_pem)?;
        return Ok(Credential { signer, certificate_der, algorithm });
    }
    Ok(self_signed(config.idp_entity_id.as_deref(), algorithm)?)
}

/// `generateSelfSigned`: `CN=MockServer SAML IdP, O=MockServer, OU=<entity id>`, a positive 64-bit serial, valid from
/// a day ago for ten years, basic constraints (critical) not a CA, signed with the key's own algorithm.
fn self_signed(idp_entity_id: Option<&str>, algorithm: Algorithm) -> Result<Credential, String> {
    let failed = |e: String| format!("Exception generating self-signed SAML signing credential: {e}");
    let signer = Signer::generate(algorithm).map_err(failed)?;
    let ou = sanitise(idp_entity_id);
    let subject: [(&[u8], &str); 3] = [(&[0x55, 0x04, 0x03], "MockServer SAML IdP"), (&[0x55, 0x04, 0x0a], "MockServer"), (&[0x55, 0x04, 0x0b], &ou)];
    let basic_constraints = der(0x30, &[der(0x06, &[0x55, 0x1d, 0x13]), der(0x01, &[0xff]), der(0x04, &der(0x30, &[]))].concat());
    let serial = loop {
        let serial = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        if serial != 0 {
            break serial;
        }
    };
    let now = chrono::Utc::now();
    let certificate_der = signer
        .self_signed_certificate(algorithm, &subject, serial, now - chrono::Duration::days(1), now + chrono::Duration::days(3650), &[basic_constraints])
        .map_err(failed)?;
    Ok(Credential { signer, certificate_der, algorithm })
}

fn sanitise(value: Option<&str>) -> String {
    match value {
        None => "mockserver".into(),
        Some(v) => v.chars().map(|c| if ",=+<>;\"\\".contains(c) { '_' } else { c }).collect(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Store (`SamlAssertionStore`)
// ---------------------------------------------------------------------------------------------------------------

struct Provider {
    config: Config,
    credential: Credential,
}

#[derive(Default)]
pub struct Saml {
    providers: Mutex<Vec<Arc<Provider>>>,
}

impl Saml {
    pub fn reset(&self) {
        self.providers.lock().clear();
    }

    /// `registerProvider`: a provider serving the same SSO path is replaced; the newest first.
    fn register(&self, provider: Provider) {
        let mut providers = self.providers.lock();
        providers.retain(|p| p.config.sso_service_url != provider.config.sso_service_url);
        providers.insert(0, Arc::new(provider));
    }

    fn for_sso_path(&self, path: &str) -> Option<Arc<Provider>> {
        self.providers.lock().iter().find(|p| p.config.sso_service_url.as_deref() == Some(path)).cloned()
    }

    fn for_slo_path(&self, path: &str) -> Option<Arc<Provider>> {
        self.providers.lock().iter().find(|p| p.config.slo_service_url.as_deref() == Some(path)).cloned()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// XML: one element tree, written as the JDK's identity `Transformer` does and as exclusive C14N
// ---------------------------------------------------------------------------------------------------------------

enum Node {
    Element(Element),
    Text(String),
}

struct Element {
    prefix: &'static str,
    local: &'static str,
    /// The namespace declaration the serialiser places on this element (where its prefix first comes into scope).
    declares: Option<&'static str>,
    attributes: Vec<(&'static str, String)>,
    children: Vec<Node>,
}

impl Element {
    fn new(prefix: &'static str, local: &'static str) -> Element {
        Element { prefix, local, declares: None, attributes: Vec::new(), children: Vec::new() }
    }

    fn declaring(mut self, uri: &'static str) -> Element {
        self.declares = Some(uri);
        self
    }

    /// `setAttribute`; the attribute map keeps names sorted, as Xerces' `NamedNodeMapImpl` does.
    fn attr(mut self, name: &'static str, value: impl Into<String>) -> Element {
        self.attributes.retain(|(n, _)| *n != name);
        self.attributes.push((name, value.into()));
        self.attributes.sort_by(|a, b| a.0.cmp(b.0));
        self
    }

    fn child(mut self, child: Element) -> Element {
        self.children.push(Node::Element(child));
        self
    }

    /// `setTextContent`: null leaves the element empty.
    fn text(mut self, text: Option<&str>) -> Element {
        if let Some(t) = text.filter(|t| !t.is_empty()) {
            self.children.push(Node::Text(t.to_string()));
        }
        self
    }

    fn qname(&self) -> String {
        format!("{}:{}", self.prefix, self.local)
    }

    /// The exception the JDK's round trip of the unsigned document (`serialize`, then `reparse`) throws, if any.
    /// Xalan's serialiser rejects a C0 control XML 1.0 does not allow, the first in document order (attributes, in
    /// name order, before content). What it writes, Xerces then rejects at U+FFFE or U+FFFF, reporting where in the
    /// unsigned text the character sits.
    fn round_trip_failure(&self) -> Option<CallbackError> {
        if let Some(c) = self.first_char(&|c| c < '\u{20}' && !matches!(c, '\t' | '\n' | '\r')) {
            let message = format!("An invalid XML character (Unicode: 0x{:x}) was found in the node's character data content.", c as u32);
            let cause = CallbackError::of("org.xml.sax.SAXException", message.clone());
            return Some(CallbackError::of("javax.xml.transform.TransformerException", format!("org.xml.sax.SAXException: {message}")).caused_by(cause));
        }
        let (text, fault) = self.parse_fault()?;
        let (line, column) = fault.position(&text);
        let place = match fault.attribute {
            Some((name, element)) => format!("the value of attribute \"{name}\" and element is \"{element}\""),
            None => "the element content of the document".to_string(),
        };
        let message = format!("An invalid XML character (Unicode: 0x{:x}) was found in {place}.", fault.char as u32);
        Some(CallbackError::of("org.xml.sax.SAXParseException", message).with_property("columnNumber", column).with_property("lineNumber", line))
    }

    /// The unsigned document text and the parser's fault in it, if any.
    fn parse_fault(&self) -> Option<(String, Fault)> {
        let (mut text, mut fault) = (String::new(), None);
        self.write_with(&mut text, true, &mut fault);
        fault.map(|f| (text, f))
    }

    /// The first character of an attribute value or text in document order that is `bad`.
    fn first_char(&self, bad: &dyn Fn(char) -> bool) -> Option<char> {
        let find = |s: &str| s.chars().find(|c| bad(*c));
        self.attributes.iter().find_map(|(_, v)| find(v)).or_else(|| {
            self.children.iter().find_map(|c| match c {
                Node::Element(e) => e.first_char(bad),
                Node::Text(t) => find(t),
            })
        })
    }

    /// The document text, as Xalan's serialiser writes it: empty elements self-closed.
    fn write(&self, out: &mut String) {
        self.write_with(out, false, &mut None);
    }

    /// The document text. An element's namespace declaration comes before its attributes in a parsed document
    /// (the signed one), after them in the one built in memory (`unsigned`). `fault` gets the first U+FFFE or
    /// U+FFFF written, which the serialiser passes through and the parser rejects.
    fn write_with(&self, out: &mut String, unsigned: bool, fault: &mut Option<Fault>) {
        let declaration = self.declares.map(|uri| format!(" xmlns:{}=\"{}\"", self.prefix, escape_attr_doc(uri)));
        out.push('<');
        out.push_str(&self.qname());
        if !unsigned && let Some(d) = &declaration {
            out.push_str(d);
        }
        for (name, value) in &self.attributes {
            out.push_str(&format!(" {name}=\""));
            Fault::note(fault, out, value, Some((name, self.qname())));
            out.push_str(&escape_attr_doc(value));
            out.push('"');
        }
        if unsigned && let Some(d) = &declaration {
            out.push_str(d);
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for child in &self.children {
            match child {
                Node::Element(e) => e.write_with(out, unsigned, fault),
                Node::Text(t) => {
                    Fault::note(fault, out, t, None);
                    out.push_str(&escape_text_doc(t));
                }
            }
        }
        out.push_str(&format!("</{}>", self.qname()));
    }

    /// Exclusive XML canonicalisation (no inclusive prefixes) of this subtree. `scope` is the namespace context the
    /// document gives the element (its ancestors' declarations); `rendered` what the output ancestors already
    /// declared. Only visibly utilised prefixes are rendered (our attributes are unprefixed, so just the element's).
    fn canonical(&self, scope: &[(&'static str, &'static str)], rendered: &[(&'static str, &'static str)], out: &mut String) {
        let mut scope = scope.to_vec();
        if let Some(uri) = self.declares {
            scope.push((self.prefix, uri));
        }
        let uri = scope.iter().rev().find(|(p, _)| *p == self.prefix).map(|(_, u)| *u).unwrap_or_default();
        let mut rendered = rendered.to_vec();
        out.push('<');
        out.push_str(&self.qname());
        if rendered.iter().rev().find(|(p, _)| *p == self.prefix).map(|(_, u)| *u) != Some(uri) {
            out.push_str(&format!(" xmlns:{}=\"{}\"", self.prefix, escape_attr_c14n(uri)));
            rendered.push((self.prefix, uri));
        }
        for (name, value) in &self.attributes {
            out.push_str(&format!(" {name}=\"{}\"", escape_attr_c14n(value)));
        }
        out.push('>');
        for child in &self.children {
            match child {
                Node::Element(e) => e.canonical(&scope, &rendered, out),
                Node::Text(t) => out.push_str(&escape_text_c14n(t)),
            }
        }
        out.push_str(&format!("</{}>", self.qname()));
    }
}

/// Where the parser of the unsigned text first meets a character XML 1.0 does not allow: the byte offset in the
/// text, the character, and the attribute (name, element) whose value holds it.
struct Fault {
    at: usize,
    char: char,
    attribute: Option<(&'static str, String)>,
}

impl Fault {
    /// Records the first U+FFFE or U+FFFF of `value`, about to be written (escaped) at the end of `out`.
    fn note(fault: &mut Option<Fault>, out: &str, value: &str, attribute: Option<(&'static str, String)>) {
        if fault.is_some() {
            return;
        }
        let Some((i, c)) = value.char_indices().find(|(_, c)| matches!(c, '\u{FFFE}' | '\u{FFFF}')) else { return };
        let escaped = if attribute.is_some() { escape_attr_doc(&value[..i]) } else { escape_text_doc(&value[..i]) };
        *fault = Some(Fault { at: out.len() + escaped.len(), char: c, attribute });
    }

    /// The `SAXParseException`'s `lineNumber` and `columnNumber` of the character in `text`, the unsigned document:
    /// 1-based, the column counted in characters from the last line feed.
    fn position(&self, text: &str) -> (usize, usize) {
        let before = &text[..self.at];
        (before.matches('\n').count() + 1, before.rsplit('\n').next().unwrap_or_default().chars().count() + 1)
    }
}

/// Text as Xalan's `ToStream` writes it in XML 1.0: markup characters, CR, the C1 controls and characters outside
/// the BMP as references.
fn escape_text_doc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            '\u{7F}'..='\u{9F}' | '\u{10000}'.. => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// An attribute value as Xalan writes it: markup characters, the whitespace a parser would normalise, and characters
/// outside the BMP as references (the C1 controls stay raw).
fn escape_attr_doc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            '\u{10000}'.. => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn escape_text_c14n(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\r', "&#xD;")
}

fn escape_attr_c14n(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;").replace('\t', "&#x9;").replace('\n', "&#xA;").replace('\r', "&#xD;")
}

/// Base64 as the JDK's XML-DSig writes it into `SignatureValue` and `X509Certificate`: 76-column lines, CRLF.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = B64.encode(bytes);
    encoded.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).expect("base64 is ASCII")).collect::<Vec<_>>().join("\r\n")
}

/// Enveloped-signs `signed` (whose namespace context in the document is `scope`), inserting `<ds:Signature>` as its
/// second child, after `<saml:Issuer>`. The reference digest is taken before the insertion, which is what the
/// enveloped-signature transform undoes.
fn sign_enveloped(signed: &mut Element, scope: &[(&'static str, &'static str)], credential: &Credential, tamper: bool) -> Result<(), Option<CallbackError>> {
    let id = signed.attributes.iter().find(|(n, _)| *n == "ID").map(|(_, v)| v.clone()).unwrap_or_default();
    let algorithm = credential.algorithm;
    let mut canonical = String::new();
    signed.canonical(scope, &[], &mut canonical);
    let digest = B64.encode(algorithm.hash().digest(canonical.as_bytes()));
    let ds = |local| Element::new("ds", local);
    let signed_info = ds("SignedInfo")
        .child(ds("CanonicalizationMethod").attr("Algorithm", EXC_C14N))
        .child(ds("SignatureMethod").attr("Algorithm", algorithm.xml_signature_method()))
        .child(
            ds("Reference")
                .attr("URI", format!("#{id}"))
                .child(ds("Transforms").child(ds("Transform").attr("Algorithm", ENVELOPED)).child(ds("Transform").attr("Algorithm", EXC_C14N)))
                .child(ds("DigestMethod").attr("Algorithm", algorithm.xml_digest_method()))
                .child(ds("DigestValue").text(Some(&digest))),
        );
    let mut signature_scope = scope.to_vec();
    if let Some(uri) = signed.declares {
        signature_scope.push((signed.prefix, uri));
    }
    signature_scope.push(("ds", NS_DS));
    let mut signed_info_c14n = String::new();
    signed_info.canonical(&signature_scope, &[], &mut signed_info_c14n);
    let mut signature_value = base64_lines(&credential.sign(signed_info_c14n.as_bytes())?);
    if tamper {
        // `corruptSignatureValue`: flip the first base64 character
        let replacement = if signature_value.starts_with('A') { 'B' } else { 'A' };
        signature_value.replace_range(0..1, &replacement.to_string());
    }
    let signature = ds("Signature")
        .declaring(NS_DS)
        .child(signed_info)
        .child(ds("SignatureValue").text(Some(&signature_value)))
        .child(ds("KeyInfo").child(ds("X509Data").child(ds("X509Certificate").text(Some(&base64_lines(&credential.certificate_der))))));
    let at = signed.children.len().min(1);
    signed.children.insert(at, Node::Element(signature));
    Ok(())
}

/// `ISO_INSTANT` at whole seconds.
fn instant(t: chrono::DateTime<chrono::Utc>) -> String {
    iso_instant(t.timestamp())
}

const SECONDS_PER_10000_YEARS: i64 = 146_097 * 25 * 86_400;
const SECONDS_0000_TO_1970: i64 = (146_097 * 5 - (30 * 365 + 7)) * 86_400;

/// `Instant.ofEpochSecond(seconds).plusSeconds(delta)`'s epoch second, with its exceptions: `Math.addExact`'s and
/// the range check against `Instant.MIN`/`MAX` (years -1e9 to 1e9, wider than chrono's).
fn plus_seconds(seconds: i64, delta: i64) -> Result<i64, CallbackError> {
    let sum = seconds.checked_add(delta).ok_or_else(|| CallbackError::of("java.lang.ArithmeticException", "long overflow"))?;
    if !(-31_557_014_167_219_200..=31_556_889_864_403_199).contains(&sum) {
        return Err(CallbackError::of("java.time.DateTimeException", "Instant exceeds minimum or maximum instant"));
    }
    Ok(sum)
}

/// `DateTimeFormatter.ISO_INSTANT` of an epoch second within the `Instant` range (`InstantPrinterParser.format`):
/// the date-time of the second within its 10,000-year cycle as `LocalDateTime` prints it, the cycles added to the
/// year (`+10265-…`, `-12345-…`).
fn iso_instant(seconds: i64) -> String {
    let local = |s: i64| chrono::DateTime::from_timestamp(s - SECONDS_0000_TO_1970, 0).expect("within 10,000 years").naive_utc();
    let time = |t: chrono::NaiveDateTime| t.format("-%m-%dT%H:%M:%SZ").to_string();
    if seconds >= -SECONDS_0000_TO_1970 {
        let zero = seconds - SECONDS_PER_10000_YEARS + SECONDS_0000_TO_1970;
        let hi = zero.div_euclid(SECONDS_PER_10000_YEARS) + 1;
        let t = local(zero.rem_euclid(SECONDS_PER_10000_YEARS));
        let cycles = if hi > 0 { format!("+{hi}") } else { String::new() };
        return format!("{cycles}{:04}{}", chrono::Datelike::year(&t), time(t));
    }
    let zero = seconds + SECONDS_0000_TO_1970;
    let (hi, lo) = (zero / SECONDS_PER_10000_YEARS, zero % SECONDS_PER_10000_YEARS);
    let t = local(lo);
    let year = chrono::Datelike::year(&t);
    // `LocalDate.toString`: four digits at least, a sign when negative
    let mut out = if year < 0 { format!("-{:04}", -year) } else { format!("{year:04}") };
    if hi < 0 {
        if year == -10_000 {
            out.replace_range(0..2, &(hi - 1).to_string());
        } else if lo == 0 {
            out.insert_str(0, &hi.to_string());
        } else {
            out.insert_str(1, &hi.abs().to_string());
        }
    }
    out + &time(t)
}

fn new_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
}

fn saml_issuer(idp_entity_id: Option<&str>) -> Element {
    Element::new("saml", "Issuer").text(idp_entity_id)
}

fn success_status() -> Element {
    Element::new("samlp", "Status").child(Element::new("samlp", "StatusCode").attr("Value", STATUS_SUCCESS))
}

/// `SamlResponseBuilder.buildSignedResponse`: a `Response` whose `Assertion` is enveloped-signed.
fn signed_response(provider: &Provider, in_response_to: Option<&str>) -> Result<String, CallbackError> {
    let c = &provider.config;
    let failed = |cause: CallbackError| CallbackError::new("Exception building signed SAML response").caused_by(cause);
    let now_seconds = chrono::Utc::now().timestamp();
    let now = iso_instant(now_seconds);
    let validity = if c.expired_assertion { -3600 } else { c.session_duration_seconds };
    let not_on_or_after = iso_instant(plus_seconds(now_seconds, validity).map_err(failed)?);
    let acs = c.assertion_consumer_service_url.clone().unwrap_or_default();

    let mut response = Element::new("samlp", "Response")
        .declaring(NS_PROTOCOL)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", now.clone())
        .attr("Destination", acs.clone());
    if let Some(id) = in_response_to {
        response = response.attr("InResponseTo", id);
    }
    response = response.child(saml_issuer(c.idp_entity_id.as_deref()).declaring(NS_ASSERTION)).child(success_status());

    let mut name_id = Element::new("saml", "NameID");
    if let Some(format) = c.name_id_format.as_deref().filter(|f| !f.is_empty()) {
        name_id = name_id.attr("Format", format);
    }
    name_id = name_id.text(c.subject_name_id.as_deref());
    let mut confirmation_data = Element::new("saml", "SubjectConfirmationData").attr("NotOnOrAfter", not_on_or_after.clone()).attr("Recipient", acs);
    if let Some(id) = in_response_to {
        confirmation_data = confirmation_data.attr("InResponseTo", id);
    }
    let subject = Element::new("saml", "Subject")
        .child(name_id)
        .child(Element::new("saml", "SubjectConfirmation").attr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer").child(confirmation_data));
    let audience = match (c.wrong_audience, c.sp_entity_id.as_deref()) {
        (true, sp) => Some(format!("{}/wrong-audience", sp.unwrap_or("null"))),
        (false, sp) => sp.map(str::to_string),
    };
    let conditions = Element::new("saml", "Conditions")
        .attr("NotBefore", now.clone())
        .attr("NotOnOrAfter", not_on_or_after.clone())
        .child(Element::new("saml", "AudienceRestriction").child(Element::new("saml", "Audience").text(audience.as_deref())));
    let authn_statement = Element::new("saml", "AuthnStatement")
        .attr("AuthnInstant", now.clone())
        .attr("SessionNotOnOrAfter", not_on_or_after)
        .attr("SessionIndex", new_id())
        .child(Element::new("saml", "AuthnContext").child(Element::new("saml", "AuthnContextClassRef").text(Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"))));
    let mut assertion = Element::new("saml", "Assertion")
        .declaring(NS_ASSERTION)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", now)
        .child(saml_issuer(c.idp_entity_id.as_deref()))
        .child(subject)
        .child(conditions)
        .child(authn_statement);
    if let Some(attributes) = c.attributes.as_ref().filter(|a| !a.is_empty()) {
        let mut statement = Element::new("saml", "AttributeStatement");
        for (name, value) in attributes {
            statement = statement.child(
                Element::new("saml", "Attribute")
                    .attr("Name", name.clone())
                    .attr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
                    .child(Element::new("saml", "AttributeValue").text(value.as_deref())),
            );
        }
        assertion = assertion.child(statement);
    }
    // the unsigned document is serialised and re-parsed before signing, which fails on characters XML 1.0 does not allow
    response.children.push(Node::Element(assertion));
    if let Some(cause) = response.round_trip_failure() {
        return Err(failed(cause));
    }
    let Some(Node::Element(mut assertion)) = response.children.pop() else { unreachable!("the assertion was just added") };
    sign_enveloped(&mut assertion, &[("samlp", NS_PROTOCOL)], &provider.credential, c.tampered_signature)
        .map_err(|cause| cause.map_or_else(|| CallbackError::new("Exception building signed SAML response"), failed))?;
    response.children.push(Node::Element(assertion));
    let mut out = String::new();
    response.write(&mut out);
    Ok(out)
}

/// `SamlLogoutResponseBuilder.buildSignedLogoutResponse`: an enveloped-signed `LogoutResponse`.
fn signed_logout_response(provider: &Provider, in_response_to: Option<&str>) -> Result<String, CallbackError> {
    let c = &provider.config;
    let failed = |cause: CallbackError| CallbackError::new("Exception building signed SAML logout response").caused_by(cause);
    let mut response = Element::new("samlp", "LogoutResponse")
        .declaring(NS_PROTOCOL)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(chrono::Utc::now()))
        .attr("Destination", c.sp_single_logout_service_url.clone().unwrap_or_default());
    if let Some(id) = in_response_to {
        response = response.attr("InResponseTo", id);
    }
    response = response.child(saml_issuer(c.idp_entity_id.as_deref()).declaring(NS_ASSERTION)).child(success_status());
    if let Some(cause) = response.round_trip_failure() {
        return Err(failed(cause));
    }
    sign_enveloped(&mut response, &[], &provider.credential, false)
        .map_err(|cause| cause.map_or_else(|| CallbackError::new("Exception building signed SAML logout response"), failed))?;
    let mut out = String::new();
    response.write(&mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------------------
// Callbacks (`SamlSsoCallback`, `SamlSloCallback`)
// ---------------------------------------------------------------------------------------------------------------

/// The built-in SAML callback classes, answering from `saml`'s providers.
pub fn callback_class(saml: &Arc<Saml>, class: &str) -> Option<CallbackClass> {
    let logout = match class {
        SSO_CLASS => false,
        SLO_CLASS => true,
        _ => return None,
    };
    Some(CallbackClass::new().with_response(Callback { saml: saml.clone(), logout }))
}

struct Callback {
    saml: Arc<Saml>,
    logout: bool,
}

impl ResponseCallback for Callback {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        let request = crate::forward::request_from_json(request);
        let provider = if self.logout { self.saml.for_slo_path(&request.path) } else { self.saml.for_sso_path(&request.path) };
        let Some(provider) = provider else {
            let endpoint = if self.logout { "SLO" } else { "SSO" };
            return Ok(response(404, "text/plain; charset=utf-8", format!("no SAML provider registered for this {endpoint} endpoint")));
        };
        let relay_state = param(&request, "RelayState");
        let request_id = extract_root_element_id(param(&request, "SAMLRequest").as_deref());
        let (action, xml) = if self.logout {
            (provider.config.sp_single_logout_service_url.clone(), signed_logout_response(&provider, request_id.as_deref())?)
        } else {
            (provider.config.assertion_consumer_service_url.clone(), signed_response(&provider, request_id.as_deref())?)
        };
        let html = auto_post_form(action.as_deref(), "SAMLResponse", &B64.encode(xml.as_bytes()), relay_state.as_deref());
        Ok(response(200, "text/html; charset=utf-8", html))
    }
}

fn response(status: u32, content_type: &str, body: String) -> Value {
    json!({"statusCode": status, "headers": {"content-type": [content_type]}, "body": body})
}

/// `buildAutoPostForm`.
fn auto_post_form(action: Option<&str>, field: &str, message: &str, relay_state: Option<&str>) -> String {
    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head><title>SAML 2.0</title></head>\n<body onload=\"document.forms[0].submit()\">\n");
    html.push_str("<noscript><p>Your browser does not support JavaScript. Please click the button below to continue.</p></noscript>\n");
    html.push_str(&format!("<form method=\"post\" action=\"{}\">\n", escape(action)));
    html.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\"/>\n", escape(Some(field)), escape(Some(message))));
    if let Some(relay_state) = relay_state.filter(|r| !r.is_empty()) {
        html.push_str(&format!("<input type=\"hidden\" name=\"RelayState\" value=\"{}\"/>\n", escape(Some(relay_state))));
    }
    html.push_str("<noscript><input type=\"submit\" value=\"Continue\"/></noscript>\n</form>\n</body>\n</html>");
    html
}

/// `param`: the first query parameter, else the first matching `application/x-www-form-urlencoded` body pair.
fn param(request: &HttpRequest, name: &str) -> Option<String> {
    let query = request.query.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.first()).filter(|v| !v.is_empty());
    if let Some(value) = query {
        return Some(value.clone());
    }
    let body = request.body_str();
    body.split('&').find_map(|pair| match pair.find('=') {
        Some(eq) if eq > 0 && &pair[..eq] == name => Some(crate::chaos::url_decode(&pair[eq + 1..])),
        _ => None,
    })
}

/// `extractRootElementId`: the root element's `ID` of a base64 (optionally raw-DEFLATE) SAML message, parsed without
/// DTDs and echoed only in `xs:ID` form.
fn extract_root_element_id(message: Option<&str>) -> Option<String> {
    let message = message.filter(|m| !m.is_empty())?;
    let lenient = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent));
    let decoded = lenient.decode(message).ok()?;
    if decoded.len() > MAX_DECODED_SAML_REQUEST_BYTES {
        return None;
    }
    let xml = inflate_if_needed(&decoded);
    let document = roxmltree::Document::parse(&xml).ok()?;
    let id = document.root_element().attribute("ID")?;
    let valid = id.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    valid.then(|| id.to_string())
}

/// `inflateIfNeeded`: raw DEFLATE (the HTTP-Redirect binding) when it yields anything, else the bytes as UTF-8.
fn inflate_if_needed(decoded: &[u8]) -> String {
    let mut inflater = flate2::Decompress::new(false);
    let mut out: Vec<u8> = Vec::new();
    let mut buffer = vec![0u8; 8192];
    loop {
        let (before_in, before_out) = (inflater.total_in(), inflater.total_out());
        let status = inflater.decompress(&decoded[before_in as usize..], &mut buffer, flate2::FlushDecompress::None);
        let produced = (inflater.total_out() - before_out) as usize;
        match status {
            Err(_) => return String::from_utf8_lossy(decoded).into_owned(),
            Ok(status) => {
                if produced == 0 {
                    break;
                }
                out.extend_from_slice(&buffer[..produced]);
                if out.len() > MAX_INFLATED_SAML_REQUEST_BYTES {
                    out.clear();
                    break;
                }
                if status == flate2::Status::StreamEnd {
                    break;
                }
            }
        }
    }
    if out.is_empty() { String::from_utf8_lossy(decoded).into_owned() } else { String::from_utf8_lossy(&out).into_owned() }
}

// ---------------------------------------------------------------------------------------------------------------
// `PUT /mockserver/saml` (`SamlProviderGenerator`)
// ---------------------------------------------------------------------------------------------------------------

/// The escaping of `SamlProviderGenerator.escape` and `SamlSsoCallback.escapeAttr` (the same four characters).
fn escape(value: Option<&str>) -> String {
    value.unwrap_or_default().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// `buildAbsoluteLocation`: a relative path resolved against the entity id's origin when that is an absolute URL.
fn absolute_location(path: Option<&str>, entity_id: Option<&str>) -> String {
    let Some(path) = path else { return String::new() };
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    if let Some(entity_id) = entity_id.filter(|e| e.starts_with("http://") || e.starts_with("https://")) {
        let (scheme, rest) = entity_id.split_once("://").unwrap_or_default();
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        // `URI.create` rejects what is not a legal URI; the raw path is used then
        if !authority.is_empty() && !entity_id.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}')) {
            let slash = if path.starts_with('/') { "" } else { "/" };
            return format!("{scheme}://{authority}{slash}{path}");
        }
    }
    path.to_string()
}

/// Built as text, as upstream does: an indented document whose root declares two prefixes, escaping only `escape`'s
/// four characters (control characters pass through unchecked).
fn metadata_xml(config: &Config, certificate_base64: &str) -> String {
    let entity = config.idp_entity_id.as_deref();
    let slo = match config.slo_service_url.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(slo) => format!("    <md:SingleLogoutService Binding=\"{BINDING_POST}\" Location=\"{}\"/>\n", escape(Some(&absolute_location(Some(slo), entity)))),
        None => String::new(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <md:EntityDescriptor xmlns:md=\"{NS_METADATA}\" xmlns:ds=\"{NS_DS}\" entityID=\"{}\">\n  \
         <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"{NS_PROTOCOL}\">\n    \
         <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo>\n        <ds:X509Data>\n          \
         <ds:X509Certificate>{certificate_base64}</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    \
         </md:KeyDescriptor>\n{slo}    <md:NameIDFormat>{}</md:NameIDFormat>\n    \
         <md:SingleSignOnService Binding=\"{BINDING_POST}\" Location=\"{}\"/>\n  </md:IDPSSODescriptor>\n</md:EntityDescriptor>\n",
        escape(entity),
        escape(config.name_id_format.as_deref()),
        escape(Some(&absolute_location(config.sso_service_url.as_deref(), entity))),
    )
}

/// The expectations (input form) a provider configuration generates; the provider is registered.
pub fn generate(state: &State, body: &str) -> Result<Vec<Value>, Failure> {
    let config = bind(body)?;
    let credential = credential(&config)?;
    let request = |method: Option<&str>, path: Option<&str>| {
        let mut request = Map::new();
        if let Some(method) = method {
            request.insert("method".into(), json!(method));
        }
        if let Some(path) = path {
            request.insert("path".into(), json!(path));
        }
        Value::Object(request)
    };
    let mut expectations = vec![
        json!({
            "id": "saml.metadata",
            "httpRequest": request(Some("GET"), config.metadata_url.as_deref()),
            "httpResponse": {"statusCode": 200, "headers": {"content-type": ["application/samlmetadata+xml; charset=utf-8"]}, "body": metadata_xml(&config, &credential.certificate_base64())},
        }),
        json!({"id": "saml.sso", "httpRequest": request(None, config.sso_service_url.as_deref()), "httpResponseClassCallback": {"callbackClass": SSO_CLASS}}),
    ];
    if config.slo_service_url.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        expectations.push(json!({"id": "saml.slo", "httpRequest": request(None, config.slo_service_url.as_deref()), "httpResponseClassCallback": {"callbackClass": SLO_CLASS}}));
    }
    state.saml.register(Provider { config, credential });
    Ok(expectations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_declares_visibly_used_prefixes_and_expands_empty_elements() {
        let assertion = Element::new("saml", "Assertion")
            .declaring(NS_ASSERTION)
            .attr("Version", "2.0")
            .attr("ID", "_a")
            .child(Element::new("saml", "Issuer").text(Some("a&b>")))
            .child(Element::new("saml", "SubjectConfirmationData").attr("Recipient", "x\"<>\t"));
        let mut canonical = String::new();
        assertion.canonical(&[("samlp", NS_PROTOCOL)], &[], &mut canonical);
        assert_eq!(
            canonical,
            format!("<saml:Assertion xmlns:saml=\"{NS_ASSERTION}\" ID=\"_a\" Version=\"2.0\"><saml:Issuer>a&amp;b&gt;</saml:Issuer><saml:SubjectConfirmationData Recipient=\"x&quot;&lt;>&#x9;\"></saml:SubjectConfirmationData></saml:Assertion>")
        );
        let mut document = String::new();
        assertion.write(&mut document);
        assert!(document.ends_with("<saml:SubjectConfirmationData Recipient=\"x&quot;&lt;&gt;&#9;\"/></saml:Assertion>"), "{document}");
    }

    #[test]
    fn signed_info_is_canonicalised_with_the_ds_namespace_it_inherits() {
        let element = Element::new("ds", "SignedInfo").child(Element::new("ds", "CanonicalizationMethod").attr("Algorithm", EXC_C14N));
        let mut canonical = String::new();
        element.canonical(&[("samlp", NS_PROTOCOL), ("saml", NS_ASSERTION), ("ds", NS_DS)], &[], &mut canonical);
        assert_eq!(canonical, format!("<ds:SignedInfo xmlns:ds=\"{NS_DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod></ds:SignedInfo>"));
    }

    #[test]
    fn iso_instant_prints_the_whole_instant_range_as_the_jdk_does() {
        assert_eq!(iso_instant(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_instant(253_402_300_799), "9999-12-31T23:59:59Z");
        assert_eq!(iso_instant(253_402_300_800), "+10000-01-01T00:00:00Z");
        assert_eq!(iso_instant(31_556_889_864_403_199), "+1000000000-12-31T23:59:59Z");
        assert_eq!(iso_instant(-62_167_219_200), "0000-01-01T00:00:00Z");
        assert_eq!(iso_instant(-62_167_219_201), "-0001-12-31T23:59:59Z");
        assert_eq!(iso_instant(-377_736_739_200), "-10000-01-01T00:00:00Z");
        assert_eq!(iso_instant(-377_736_739_201), "-10001-12-31T23:59:59Z");
        assert_eq!(iso_instant(-31_557_014_167_219_200), "-1000000000-01-01T00:00:00Z");
    }

    #[test]
    fn plus_seconds_fails_as_instant_does() {
        let failure = |r: Result<i64, CallbackError>| r.map_err(|e| format!("{}: {}", e.class, e.message()));
        assert_eq!(failure(plus_seconds(1, i64::MAX)), Err("java.lang.ArithmeticException: long overflow".to_string()));
        assert_eq!(failure(plus_seconds(1, i64::MIN)), Err("java.time.DateTimeException: Instant exceeds minimum or maximum instant".to_string()));
        assert_eq!(failure(plus_seconds(0, 31_556_889_864_403_200)), Err("java.time.DateTimeException: Instant exceeds minimum or maximum instant".to_string()));
        assert_eq!(failure(plus_seconds(0, 31_556_889_864_403_199)), Ok(31_556_889_864_403_199));
    }

    /// A `Response` as built in memory, with the oracle's field lengths (a UUID id, a whole-second instant).
    fn unsigned_response(destination: &str, issuer: &str) -> Element {
        Element::new("samlp", "Response")
            .declaring(NS_PROTOCOL)
            .attr("ID", format!("_{}", "0".repeat(36)))
            .attr("Version", "2.0")
            .attr("IssueInstant", "2026-10-06T15:35:59Z")
            .attr("Destination", destination)
            .child(saml_issuer(Some(issuer)).declaring(NS_ASSERTION))
            .child(success_status())
    }

    #[test]
    fn round_trip_failures_are_the_serialiser_s_then_the_parser_s() {
        let thrown = |e: &Element| e.round_trip_failure().map(|e| (e.class.clone(), e.message().to_string(), e.cause.map(|c| (c.class, c.message))));
        assert_eq!(
            thrown(&unsigned_response("x\u{FFFE}", "a\u{1}")),
            Some((
                "javax.xml.transform.TransformerException".to_string(),
                "org.xml.sax.SAXException: An invalid XML character (Unicode: 0x1) was found in the node's character data content.".to_string(),
                Some(("org.xml.sax.SAXException".to_string(), Some("An invalid XML character (Unicode: 0x1) was found in the node's character data content.".to_string())))
            ))
        );
        assert_eq!(
            thrown(&unsigned_response("x\u{FFFE}", "a")),
            Some(("org.xml.sax.SAXParseException".to_string(), "An invalid XML character (Unicode: 0xfffe) was found in the value of attribute \"Destination\" and element is \"samlp:Response\".".to_string(), None))
        );
        assert_eq!(
            thrown(&unsigned_response("x", "\u{FFFF}")),
            Some(("org.xml.sax.SAXParseException".to_string(), "An invalid XML character (Unicode: 0xffff) was found in the element content of the document.".to_string(), None))
        );
        assert!(unsigned_response("\u{7F}\u{85}\u{2028}", "\u{1F600}").round_trip_failure().is_none());
    }

    #[test]
    fn the_parser_s_position_is_in_the_unsigned_text() {
        // columns as the oracle reports them (2026-10-06)
        let position = |e: Element| e.parse_fault().map(|(text, fault)| fault.position(&text));
        assert_eq!(position(unsigned_response("http://localhost:8080/saml/acs", "\u{FFFE}")), Some((1, 270)));
        assert_eq!(position(unsigned_response("\u{FFFE}", "i")), Some((1, 30)));
        assert_eq!(position(unsigned_response("http://localhost:8080/saml/acs", "\u{1F600}\u{FFFE}")), Some((1, 279)));
        assert_eq!(position(unsigned_response("http://localhost:8080/saml/acs", "a\nbc\u{FFFE}")), Some((2, 3)));
        let logout = Element::new("samlp", "LogoutResponse").declaring(NS_PROTOCOL).attr("Destination", "\u{FFFE}").attr("ID", "_");
        assert_eq!(position(logout), Some((1, 36)));
    }

    #[test]
    fn document_text_escapes_as_xalan_writes_it() {
        assert_eq!(escape_text_doc("\t\n\r<>&\"\u{7F}\u{9F}\u{A0}\u{2028}\u{1F600}"), "\t\n&#13;&lt;&gt;&amp;\"&#127;&#159;\u{A0}\u{2028}&#128512;");
        assert_eq!(escape_attr_doc("\t\n\r<>&\"\u{7F}\u{85}\u{2028}\u{1F600}"), "&#9;&#10;&#13;&lt;&gt;&amp;&quot;\u{7F}\u{85}\u{2028}&#128512;");
    }

    #[test]
    fn root_element_id_comes_from_plain_or_deflated_requests() {
        let xml = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_abc\" Version=\"2.0\"/>";
        assert_eq!(extract_root_element_id(Some(&B64.encode(xml))).as_deref(), Some("_abc"));
        let mut deflater = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut deflater, xml.as_bytes()).unwrap();
        assert_eq!(extract_root_element_id(Some(&B64.encode(deflater.finish().unwrap()))).as_deref(), Some("_abc"));
        assert_eq!(extract_root_element_id(Some(&B64.encode("<a ID=\"1bad\"/>"))), None);
        assert_eq!(extract_root_element_id(Some(&B64.encode("<!DOCTYPE a><a ID=\"_x\"/>"))), None);
    }

    #[test]
    fn locations_resolve_against_the_entity_id_origin() {
        assert_eq!(absolute_location(Some("/saml/sso"), Some("http://localhost:1080/saml/idp")), "http://localhost:1080/saml/sso");
        assert_eq!(absolute_location(Some("sso"), Some("https://idp.example")), "https://idp.example/sso");
        assert_eq!(absolute_location(Some("/saml/sso"), Some("urn:idp")), "/saml/sso");
        assert_eq!(absolute_location(Some("https://x/sso"), Some("http://y")), "https://x/sso");
    }
}
