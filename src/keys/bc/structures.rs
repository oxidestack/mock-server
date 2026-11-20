//! The structures `PEMParser` builds from a PEM object of another type than a key, and their `getInstance` checks
//! (BouncyCastle 1.86): `X509 CRL` (`X509CRLHolder` over `CertificateList`/`TBSCertList`), `CERTIFICATE REQUEST`
//! (`PKCS10CertificationRequest` over `CertificationRequest`/`CertificationRequestInfo`), `ATTRIBUTE CERTIFICATE`
//! (`X509AttributeCertificateHolder` over `AttributeCertificate`/`AttributeCertificateInfo`) and `PKCS7`/`CMS`
//! (`ContentInfo`). Each failure is the exception the parser throws; a valid object is what `PEMToFile` then
//! refuses as no private key.

use std::borrow::Cow;

use super::super::jca::npe;
use super::super::{dotted, iae, java_string, pem_exception, throwable, Failure, IO_EXCEPTION};
use super::{from_byte_array, is_io, sequence, valid_oid, Asn1, Reader, TagBody};

const ILLEGAL_STATE: &str = "java.lang.IllegalStateException";
const CLASS_CAST: &str = "java.lang.ClassCastException";
const OUT_OF_BOUNDS: &str = "java.lang.ArrayIndexOutOfBoundsException";
const CERT_IO: &str = "shaded_package.org.bouncycastle.cert.CertIOException";
const ASN1_PARSING: &str = "shaded_package.org.bouncycastle.asn1.ASN1ParsingException";
const PKCS_IO: &str = "shaded_package.org.bouncycastle.pkcs.PKCSIOException";
const CHALLENGE_PASSWORD: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07];
const ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
const SUBJECT_ALT_PUBLIC_KEY_INFO: &[u8] = &[0x55, 0x1d, 0x48];
const ALT_SIGNATURE_ALGORITHM: &[u8] = &[0x55, 0x1d, 0x49];
const ALT_SIGNATURE_VALUE: &[u8] = &[0x55, 0x1d, 0x4a];

/// Why a structure stops: BouncyCastle's RuntimeException, or a path these checks do not model.
enum Stop {
    Fail(Failure),
    Unmodelled,
}

impl From<Failure> for Stop {
    fn from(e: Failure) -> Stop {
        Stop::Fail(e)
    }
}

type Check<T = ()> = Result<T, Stop>;

/// An extension: its OID and its value, both encoded.
type Extension = (Vec<u8>, Vec<u8>);

fn ise(message: &str) -> Failure {
    throwable(ILLEGAL_STATE, Some(message.into()), None)
}

fn out_of_bounds(index: usize, length: usize) -> Failure {
    throwable(OUT_OF_BOUNDS, Some(format!("Index {index} out of bounds for length {length}")), None)
}

fn bad_size(size: usize) -> Failure {
    iae(format!("Bad sequence size: {size}"))
}

/// `ASN1Util.getTagClassText`.
fn tag_class_text(class: u8) -> &'static str {
    match class {
        0x40 => "APPLICATION",
        0x80 => "CONTEXT",
        0xc0 => "PRIVATE",
        _ => "UNIVERSAL",
    }
}

/// `PrivateKeyInfo.getInstance` of the holder `PEMParser` returns, which is no ASN.1 object.
fn not_private_key(class: &str) -> Option<Failure> {
    Some(iae(format!("unknown object in getInstance: shaded_package.org.bouncycastle.{class}")))
}

/// The `ASN1InputStream` a `LazyEncodedSequence` reads its contents with: lazily evaluating, limited to them.
fn lazy_reader(contents: &[u8]) -> Reader<'_> {
    Reader { data: contents, pos: 0, streams: Vec::new(), lazy: true }
}

/// `throw new ASN1ParsingException("malformed ASN.1: " + e, e)` of `LazyEncodedSequence.force` and
/// `LazyConstructionEnumeration` over the IOException of the deferred read; a RuntimeException passes.
fn malformed_asn1(e: Failure) -> Failure {
    if !is_io(&e) {
        return e;
    }
    throwable(ASN1_PARSING, Some(format!("malformed ASN.1: {}", java_string(&e))), Some(e))
}

/// `LazyEncodedSequence.force`: its elements, read from its contents at once.
fn force(contents: &[u8]) -> Result<Vec<Asn1>, Failure> {
    let mut reader = lazy_reader(contents);
    let mut items = Vec::new();
    while let Some(item) = reader.object(0, contents.len()).map_err(malformed_asn1)? {
        items.push(item);
    }
    Ok(items)
}

/// `LazyEncodedSequence.getObjects`: a `LazyConstructionEnumeration`, which reads one element at a time; the
/// elements read before the failure of the next, if any.
fn enumerate(contents: &[u8]) -> (Vec<Asn1>, Option<Failure>) {
    let mut reader = lazy_reader(contents);
    let mut items = Vec::new();
    loop {
        match reader.object(0, contents.len()) {
            Ok(Some(item)) => items.push(item),
            Ok(None) => return (items, None),
            Err(e) => return (items, Some(malformed_asn1(e))),
        }
    }
}

/// The structures over decoded objects. A SEQUENCE an `ASN1InputStream` evaluating lazily read (as `X509CRLHolder`
/// reads) is an `Asn1::Lazy`, decoded when a structure reads its elements.
struct Structures;

impl Structures {
    fn class(&self, o: &Asn1) -> String {
        o.class()
    }

    fn unknown(&self, o: &Asn1) -> Failure {
        iae(format!("unknown object in getInstance: {}", self.class(o)))
    }

    fn illegal(&self, o: &Asn1) -> Failure {
        iae(format!("illegal object in getInstance: {}", self.class(o)))
    }

    fn factory(&self, o: &Asn1) -> Failure {
        iae(format!("unknown object in factory: {}", self.class(o)))
    }

    /// The JDK's `ClassCastException` for a cast of `o` to the BouncyCastle class `to`.
    fn cast(&self, o: &Asn1, to: &str) -> Failure {
        let (from, to) = (self.class(o), format!("shaded_package.org.bouncycastle.asn1.{to}"));
        let message = format!("class {from} cannot be cast to class {to} ({from} and {to} are in unnamed module of loader 'app')");
        throwable(CLASS_CAST, Some(message), None)
    }

    /// `ASN1Sequence.getInstance(Object)` and its elements (which a `LazyEncodedSequence` reads then).
    fn sequence<'a>(&self, o: &'a Asn1) -> Result<Cow<'a, [Asn1]>, Failure> {
        match o {
            Asn1::Sequence(items, _) => Ok(Cow::Borrowed(items)),
            Asn1::Lazy(contents) => force(contents).map(Cow::Owned),
            other => Err(self.unknown(other)),
        }
    }

    /// `ASN1Sequence.getInstance(Object)` alone, which reads no element.
    fn sequence_instance(&self, o: &Asn1) -> Result<(), Failure> {
        match o {
            Asn1::Sequence(..) | Asn1::Lazy(_) => Ok(()),
            other => Err(self.unknown(other)),
        }
    }

    /// `ASN1Set.getInstance(Object)`.
    fn set(&self, o: &Asn1) -> Result<(), Failure> {
        match o {
            Asn1::Set(..) => Ok(()),
            other => Err(self.unknown(other)),
        }
    }

    /// The `getInstance(Object)` of a primitive type, which accepts only that type.
    fn of_type(&self, o: &Asn1, is: bool) -> Result<(), Failure> {
        if is { Ok(()) } else { Err(self.illegal(o)) }
    }

    fn integer(&self, o: &Asn1) -> Result<(), Failure> {
        self.of_type(o, matches!(o, Asn1::Integer(_)))
    }

    fn oid<'a>(&self, o: &'a Asn1) -> Result<&'a [u8], Failure> {
        match o {
            Asn1::Oid(contents) => Ok(contents),
            other => Err(self.illegal(other)),
        }
    }

    fn bit_string(&self, o: &Asn1) -> Result<(), Failure> {
        self.of_type(o, matches!(o, Asn1::BitString(..)))
    }

    /// `ASN1TaggedObject.getInstance(Object)`: the tag class, number and body.
    fn tagged<'a>(&self, o: &'a Asn1) -> Result<(u8, u32, &'a TagBody), Failure> {
        match o {
            Asn1::Tagged { class, no, body, .. } => Ok((*class, *no, body)),
            other => Err(self.unknown(other)),
        }
    }

    /// `ASN1Util.checkContextTagClass`.
    fn context(class: u8) -> Result<(), Failure> {
        if class == 0x80 {
            return Ok(());
        }
        Err(iae(format!("Expected CONTEXT tag but found {}", tag_class_text(class))))
    }

    /// `getBaseUniversal(true, SEQUENCE)`: the explicitly tagged SEQUENCE.
    fn explicit_base(tagged: &Asn1) -> Result<&Asn1, Failure> {
        match tagged.explicit() {
            None => Err(ise("object implicit - explicit expected.")),
            Some(base @ (Asn1::Sequence(..) | Asn1::Lazy(_))) => Ok(base),
            Some(_) => Err(ise("unexpected explicit encoding")),
        }
    }

    /// The explicitly tagged SEQUENCE's elements.
    fn explicit_sequence(tagged: &Asn1) -> Result<Cow<'_, [Asn1]>, Failure> {
        (Structures).sequence(Self::explicit_base(tagged)?)
    }

    /// `getBaseUniversal(false, SEQUENCE or SET)`: the elements of an implicitly tagged constructed type.
    fn implicit_constructed(body: &TagBody) -> Result<&[Asn1], Failure> {
        match body {
            TagBody::Primitive(_) => Err(ise("unexpected implicit primitive encoding")),
            TagBody::Constructed(items) => Ok(items),
        }
    }

    /// `ASN1Sequence.getInstance(ASN1TaggedObject, explicit)` (`getContextTagged`) and its elements.
    fn tagged_sequence<'a>(&self, o: &'a Asn1, explicit: bool) -> Result<Cow<'a, [Asn1]>, Failure> {
        let (class, _, body) = self.tagged(o)?;
        Self::context(class)?;
        if explicit { Self::explicit_sequence(o) } else { Self::implicit_constructed(body).map(Cow::Borrowed) }
    }

    /// `AlgorithmIdentifier.getInstance(Object)`.
    fn algorithm_identifier(&self, o: &Asn1) -> Result<(), Failure> {
        let items = self.sequence(o)?;
        if items.is_empty() || items.len() > 2 {
            return Err(bad_size(items.len()));
        }
        self.oid(&items[0]).map(|_| ())
    }

    /// `X500Name.getInstance(Object)`: its number of RDNs.
    fn x500_name(&self, o: &Asn1) -> Result<usize, Failure> {
        self.rdns(&self.sequence(o)?)
    }

    /// `X500Name(ASN1Sequence)`: `RDN.getInstance` of each element.
    fn rdns(&self, rdns: &[Asn1]) -> Result<usize, Failure> {
        rdns.iter().try_for_each(|rdn| self.set(rdn))?;
        Ok(rdns.len())
    }

    /// `Time.getInstance(Object)`.
    fn time(&self, o: &Asn1) -> Result<(), Failure> {
        match o {
            Asn1::Other("ASN1UTCTime" | "ASN1GeneralizedTime") => Ok(()),
            other => Err(self.factory(other)),
        }
    }

    /// `SubjectPublicKeyInfo.getInstance(Object)`.
    fn subject_public_key_info(&self, o: &Asn1) -> Result<(), Failure> {
        let items = self.sequence(o)?;
        if items.len() != 2 {
            return Err(bad_size(items.len()));
        }
        self.algorithm_identifier(&items[0])?;
        self.bit_string(&items[1])
    }

    /// `Extensions(ASN1Sequence)` over the sequence's elements: each extension's id and value octets. `unread` is
    /// the failure of a `LazyConstructionEnumeration` reading past them, which it meets before the last element
    /// read is checked, as it reads each element ahead.
    fn extensions(&self, items: &[Asn1], mut unread: Option<Failure>) -> Result<Vec<Extension>, Failure> {
        let mut extensions: Vec<Extension> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            if let Some(e) = unread.take_if(|_| i + 1 == items.len()) {
                return Err(e);
            }
            // `Extension.getInstance`
            let fields = self.sequence(item)?;
            if fields.len() != 2 && fields.len() != 3 {
                return Err(bad_size(fields.len()));
            }
            let id = self.oid(&fields[0])?;
            if fields.len() == 3 {
                self.of_type(&fields[1], matches!(fields[1], Asn1::Other("ASN1Boolean")))?;
            }
            let value = match &fields[fields.len() - 1] {
                Asn1::OctetString(_, octets) => octets,
                other => return Err(self.illegal(other)),
            };
            if extensions.iter().any(|(known, _)| known == id) {
                return Err(iae(format!("repeated extension found: {}", dotted(id))));
            }
            extensions.push((id.to_vec(), value.clone()));
        }
        unread.map_or(Ok(extensions), Err)
    }

    /// `TBSCertList(ASN1Sequence)` of `TBSCertList.getInstance`: its extensions.
    fn tbs_cert_list(&self, o: &Asn1) -> Result<Vec<Extension>, Failure> {
        let items = self.sequence(o)?;
        if items.len() < 3 || items.len() > 7 {
            return Err(bad_size(items.len()));
        }
        let mut pos = usize::from(matches!(items[0], Asn1::Integer(_)));
        self.algorithm_identifier(&items[pos])?;
        if self.x500_name(&items[pos + 1])? == 0 {
            return Err(iae("CRL issuer is an empty distinguished name"));
        }
        // `seq.getObjectAt(seqPos++)`, past the end of three elements after a version
        self.time(items.get(pos + 2).ok_or_else(|| out_of_bounds(pos + 2, items.len()))?)?;
        pos += 3;
        if matches!(items.get(pos), Some(Asn1::Other("ASN1UTCTime" | "ASN1GeneralizedTime"))) {
            pos += 1;
        }
        // revoked certificates: `ASN1Sequence.getInstance`, its entries never read
        if let Some(revoked) = items.get(pos).filter(|o| !matches!(o, Asn1::Tagged { .. })) {
            self.sequence_instance(revoked)?;
            pos += 1;
        }
        let Some(tagged @ Asn1::Tagged { .. }) = items.get(pos) else { return Ok(Vec::new()) };
        let (class, ..) = self.tagged(tagged)?;
        Self::context(class)?;
        // `Extensions.getInstance` enumerates the sequence's elements
        match Self::explicit_base(tagged)? {
            Asn1::Lazy(contents) => {
                let (items, unread) = enumerate(contents);
                self.extensions(&items, unread)
            }
            base => self.extensions(&self.sequence(base)?, None),
        }
    }

    /// `CertificateList(ASN1Sequence)` of `CertificateList.getInstance`: its extensions.
    fn certificate_list(&self, o: &Asn1) -> Result<Vec<Extension>, Failure> {
        let items = self.sequence(o)?;
        if items.len() != 3 {
            return Err(iae("sequence wrong size for CertificateList"));
        }
        let extensions = self.tbs_cert_list(&items[0])?;
        self.algorithm_identifier(&items[1])?;
        self.bit_string(&items[2])?;
        Ok(extensions)
    }

    /// `IssuingDistributionPoint.getInstance(extension.getParsedValue())`, and `isIndirectCRL()` of it.
    fn issuing_distribution_point(&self, value: &[u8]) -> Check {
        // `Extension.convertValueToObject`
        let parsed = match from_byte_array(value) {
            Err(e) if is_io(&e) => return Err(iae(format!("can't convert extension: {}", java_string(&e))).into()),
            Err(e) => return Err(e.into()),
            Ok(None) => {
                const NULL: &str = "Cannot invoke \"shaded_package.org.bouncycastle.asn1.x509.IssuingDistributionPoint.isIndirectCRL()\" because the return value of \"shaded_package.org.bouncycastle.asn1.x509.IssuingDistributionPoint.getInstance(Object)\" is null";
                return Err(npe(NULL).into());
            }
            Ok(Some(parsed)) => parsed,
        };
        for item in self.sequence(&parsed)?.iter() {
            let (class, no, body) = self.tagged(item)?;
            if no > 5 {
                return Err(iae("unknown tag in IssuingDistributionPoint").into());
            }
            Self::context(class)?;
            match (no, body) {
                // distributionPoint: `DistributionPointName.getInstance(o, true)`, a CHOICE
                (0, _) => {
                    let name = item.explicit().ok_or_else(|| ise("object implicit - explicit expected."))?;
                    let Asn1::Tagged { class, no, body, .. } = name else { return Err(self.factory(name).into()) };
                    match (class, no) {
                        (0x80, 0) => {
                            self.general_names(Self::implicit_constructed(body)?)?;
                        }
                        (0x80, 1) => {
                            Self::implicit_constructed(body)?;
                        }
                        _ => return Err(iae(format!("unknown tag: [{} {no}]", tag_class_text(*class))).into()),
                    }
                }
                // onlySomeReasons: an implicit BIT STRING
                (3, TagBody::Primitive(contents)) => {
                    super::bit_string(contents)?;
                }
                (3, TagBody::Constructed(_)) => return Err(Stop::Unmodelled),
                // the BOOLEANs, implicitly tagged
                (_, TagBody::Primitive(contents)) if contents.len() != 1 => return Err(iae("BOOLEAN value should have 1 byte in it").into()),
                (_, TagBody::Constructed(_)) => return Err(ise("unexpected implicit constructed encoding").into()),
                _ => {}
            }
        }
        Ok(())
    }

    /// `Attribute.getInstance` of an element of an attribute set: its type and values.
    fn attribute<'a>(&self, o: &'a Asn1) -> Result<(&'a [u8], &'a [Asn1]), Failure> {
        let Asn1::Sequence(items, _) = o else { return Err(self.factory(o)) };
        let id = match items.first() {
            None => return Err(out_of_bounds(0, 0)),
            Some(Asn1::Oid(id)) => id,
            Some(other) => return Err(self.cast(other, "ASN1ObjectIdentifier")),
        };
        match items.get(1) {
            None => Err(out_of_bounds(1, items.len())),
            Some(Asn1::Set(values, _)) => Ok((id, values)),
            Some(other) => Err(self.cast(other, "ASN1Set")),
        }
    }

    /// `CertificationRequestInfo(ASN1Sequence)` of `CertificationRequestInfo.getInstance`: its attributes.
    fn certification_request_info(&self, o: &Asn1) -> Result<Vec<Asn1>, Failure> {
        let items = self.sequence(o)?;
        let at = |i: usize| items.get(i).ok_or_else(|| out_of_bounds(i, items.len()));
        let version = at(0)?;
        if !matches!(version, Asn1::Integer(_)) {
            return Err(self.cast(version, "ASN1Integer"));
        }
        self.x500_name(at(1)?)?;
        self.subject_public_key_info(at(2)?)?;
        let Some(tagged) = items.get(3) else { return Ok(Vec::new()) };
        // `ASN1Set.getInstance((ASN1TaggedObject) element, false)`
        let Asn1::Tagged { .. } = tagged else { return Err(self.cast(tagged, "ASN1TaggedObject")) };
        let attributes = self.tagged_sequence(tagged, false)?;
        // `validateAttributes`
        for attribute in attributes.iter() {
            let (id, values) = self.attribute(attribute)?;
            if id == CHALLENGE_PASSWORD && values.len() != 1 {
                return Err(iae("challengePassword attribute must have one value"));
            }
        }
        Ok(attributes.into_owned())
    }

    /// `CertificationRequest(ASN1Sequence)` of `CertificationRequest.getInstance`: its attributes.
    fn certification_request(&self, o: &Asn1) -> Result<Vec<Asn1>, Failure> {
        let items = self.sequence(o)?;
        let at = |i: usize| items.get(i).ok_or_else(|| out_of_bounds(i, items.len()));
        let attributes = self.certification_request_info(at(0)?)?;
        self.algorithm_identifier(at(1)?)?;
        match at(2)? {
            Asn1::BitString("DERBitString", ..) => Ok(attributes),
            other => Err(self.cast(other, "DERBitString")),
        }
    }

    /// The `PKCS10CertificationRequest(CertificationRequest)` constructor's alternative signature attributes.
    fn alternative_signature(&self, attributes: &[Asn1]) -> Result<(), Failure> {
        let single = |values: &[Asn1]| -> Result<Asn1, Failure> {
            match values {
                [value] => Ok(value.clone()),
                _ => Err(iae("single value attribute value not size of 1")),
            }
        };
        let (mut algorithm, mut key, mut signature) = (false, false, false);
        for attribute in attributes {
            let (id, values) = self.attribute(attribute)?;
            if id == ALT_SIGNATURE_ALGORITHM {
                self.algorithm_identifier(&single(values)?)?;
                algorithm = true;
            }
            if id == SUBJECT_ALT_PUBLIC_KEY_INFO {
                self.subject_public_key_info(&single(values)?)?;
                key = true;
            }
            if id == ALT_SIGNATURE_VALUE {
                self.bit_string(&single(values)?)?;
                signature = true;
            }
        }
        if (algorithm || key || signature) && !(algorithm && key && signature) {
            return Err(iae("invalid alternate public key details found"));
        }
        Ok(())
    }

    /// `GeneralName.getInstance(Object)`.
    fn general_name(&self, o: &Asn1) -> Check {
        let Asn1::Tagged { class, no, body, .. } = o else { return Err(self.unknown(o).into()) };
        if *class != 0x80 || *no > 8 {
            return Err(iae(format!("unknown tag: [{} {no}]", tag_class_text(*class))).into());
        }
        match (no, body) {
            // directoryName: `X500Name.getTagged(tagObj, true)`
            (4, _) => {
                self.rdns(&Self::explicit_sequence(o)?)?;
            }
            // otherName, x400Address and ediPartyName: an implicit SEQUENCE
            (0 | 3 | 5, TagBody::Primitive(_)) => return Err(ise("unexpected implicit primitive encoding").into()),
            (5, TagBody::Constructed(_)) => return Err(Stop::Unmodelled),
            (0 | 3, TagBody::Constructed(_)) => {}
            // rfc822Name, dNSName, uniformResourceIdentifier (IA5String) and registeredID (OID)
            (1 | 2 | 6 | 8, TagBody::Constructed(_)) => return Err(ise("unexpected implicit constructed encoding").into()),
            (8, TagBody::Primitive(contents)) if contents.len() > 4096 => return Err(iae("exceeded OID contents length limit").into()),
            (8, TagBody::Primitive(contents)) if !valid_oid(contents) => return Err(iae("invalid OID contents").into()),
            // iPAddress: an implicit OCTET STRING, constructed or not
            (7, TagBody::Constructed(_)) => return Err(Stop::Unmodelled),
            _ => {}
        }
        Ok(())
    }

    /// `GeneralNames(ASN1Sequence)`: its number of names.
    fn general_names(&self, items: &[Asn1]) -> Check<usize> {
        items.iter().try_for_each(|name| self.general_name(name))?;
        Ok(items.len())
    }

    /// `IssuerSerial(ASN1Sequence)`.
    fn issuer_serial(&self, items: &[Asn1]) -> Check {
        if items.len() != 2 && items.len() != 3 {
            return Err(bad_size(items.len()).into());
        }
        self.general_names(&self.sequence(&items[0])?)?;
        self.integer(&items[1])?;
        if let Some(id) = items.get(2) {
            self.bit_string(id)?;
        }
        Ok(())
    }

    /// `ObjectDigestInfo(ASN1Sequence)`.
    fn object_digest_info(&self, items: &[Asn1]) -> Check {
        if items.len() < 3 || items.len() > 4 {
            return Err(bad_size(items.len()).into());
        }
        self.of_type(&items[0], matches!(items[0], Asn1::Other("ASN1Enumerated")))?;
        let offset = items.len() - 3;
        if offset == 1 {
            self.oid(&items[1])?;
        }
        self.algorithm_identifier(&items[1 + offset])?;
        self.bit_string(&items[2 + offset])?;
        Ok(())
    }

    /// `Holder.getInstance(Object)`.
    fn holder(&self, o: &Asn1) -> Check {
        if let Asn1::Tagged { class, no, .. } = o {
            return match no {
                0 | 1 => {
                    Self::context(*class)?;
                    let items = Self::explicit_sequence(o)?;
                    if *no == 0 { self.issuer_serial(&items) } else { self.general_names(&items).map(|_| ()) }
                }
                _ => Err(iae("unknown tag in Holder").into()),
            };
        }
        let items = self.sequence(o)?;
        if items.len() > 3 {
            return Err(bad_size(items.len()).into());
        }
        for item in items.iter() {
            let (class, no, body) = self.tagged(item)?;
            if no > 2 {
                return Err(iae("unknown tag in Holder").into());
            }
            Self::context(class)?;
            let fields = Self::implicit_constructed(body)?;
            match no {
                0 => self.issuer_serial(fields)?,
                1 => self.general_names(fields).map(|_| ())?,
                _ => self.object_digest_info(fields)?,
            }
        }
        Ok(())
    }

    /// `V2Form(ASN1Sequence)`: whether it is empty (`AttributeCertificateInfo.isEmptyIssuer`).
    fn v2_form(&self, items: &[Asn1]) -> Check<bool> {
        if items.len() > 3 {
            return Err(bad_size(items.len()).into());
        }
        let mut names = None;
        let mut start = 0;
        if let Some(first) = items.first().filter(|o| !matches!(o, Asn1::Tagged { .. })) {
            names = Some(self.general_names(&self.sequence(first)?)?);
            start = 1;
        }
        let mut identified = false;
        for item in &items[start..] {
            let (class, no, body) = self.tagged(item)?;
            match no {
                0 | 1 => {
                    Self::context(class)?;
                    let fields = Self::implicit_constructed(body)?;
                    if no == 0 { self.issuer_serial(fields)? } else { self.object_digest_info(fields)? }
                    identified = true;
                }
                _ => return Err(iae(format!("Bad tag number: {no}")).into()),
            }
        }
        Ok(match names {
            Some(count) => count == 0,
            None => !identified,
        })
    }

    /// `AttCertIssuer.getInstance(Object)`: whether it is empty.
    fn att_cert_issuer(&self, o: &Asn1) -> Check<bool> {
        match o {
            Asn1::Tagged { .. } => self.v2_form(&self.tagged_sequence(o, false)?),
            Asn1::Sequence(items, _) => Ok(self.general_names(items)? == 0),
            other => Err(self.factory(other).into()),
        }
    }

    /// `AttributeCertificateInfo(ASN1Sequence)` of `AttributeCertificateInfo.getInstance`.
    fn attribute_certificate_info(&self, o: &Asn1) -> Check {
        let items = self.sequence(o)?;
        if items.len() < 6 || items.len() > 9 {
            return Err(bad_size(items.len()).into());
        }
        let start = usize::from(matches!(items[0], Asn1::Integer(_)));
        self.holder(&items[start])?;
        if self.att_cert_issuer(&items[start + 1])? {
            return Err(iae("attribute certificate issuer is empty").into());
        }
        self.algorithm_identifier(&items[start + 2])?;
        self.integer(&items[start + 3])?;
        // `AttCertValidityPeriod`
        let validity = self.sequence(&items[start + 4])?;
        if validity.len() != 2 {
            return Err(bad_size(validity.len()).into());
        }
        for time in validity.iter() {
            self.of_type(time, matches!(time, Asn1::Other("ASN1GeneralizedTime")))?;
        }
        self.sequence(&items[start + 5])?;
        for item in &items[start + 6..] {
            if let Asn1::Sequence(extensions, _) = item {
                self.extensions(extensions, None)?;
            }
        }
        Ok(())
    }

    /// `AttributeCertificate(ASN1Sequence)` of `AttributeCertificate.getInstance`.
    fn attribute_certificate(&self, o: &Asn1) -> Check {
        let items = self.sequence(o)?;
        if items.len() != 3 {
            return Err(bad_size(items.len()).into());
        }
        self.attribute_certificate_info(&items[0])?;
        self.algorithm_identifier(&items[1])?;
        self.bit_string(&items[2])?;
        Ok(())
    }
}

/// `ASN1InputStream.readObject` over the whole content: the first object, past which nothing is read.
fn read_object(content: &[u8]) -> Result<Option<Asn1>, Failure> {
    lazy_reader(content).object(0, content.len())
}

/// `PEMParser.X509CRLParser`: `new X509CRLHolder(content)`, its failure wrapped as `problem parsing cert`.
pub(super) fn crl(content: &[u8]) -> Option<Failure> {
    let problem = |e: Failure| Some(pem_exception(format!("problem parsing cert: {}", java_string(&e)), e));
    let cert_io = |prefix: &str, e: Failure| throwable(CERT_IO, Some(format!("{prefix}: {}", e.message)), Some(e));
    // `parseStream`: an IOException passes, any RuntimeException is malformed data
    let object = match read_object(content) {
        Err(e) => return problem(e),
        Ok(None) => return problem(throwable(IO_EXCEPTION, Some("no content found".into()), None)),
        Ok(Some(object)) => object,
    };
    let structures = Structures;
    let extensions = match structures.certificate_list(&object) {
        Err(e) => return problem(cert_io("malformed data", e)),
        Ok(extensions) => extensions,
    };
    // `init`: `isIndirectCRL`
    if let Some((_, value)) = extensions.iter().find(|(id, _)| *id == ISSUING_DISTRIBUTION_POINT) {
        // the parsed value is read eagerly
        match Structures.issuing_distribution_point(value) {
            Err(Stop::Unmodelled) => return None,
            Err(Stop::Fail(e)) => return problem(cert_io("malformed IssuingDistributionPoint extension", e)),
            Ok(()) => {}
        }
    }
    not_private_key("cert.X509CRLHolder")
}

/// `PEMParser.PKCS10CertificationRequestParser`: `new PKCS10CertificationRequest(content)`, its failure wrapped as
/// `problem parsing certrequest`.
pub(super) fn certification_request(content: &[u8]) -> Option<Failure> {
    let problem = |e: Failure| Some(pem_exception(format!("problem parsing certrequest: {}", java_string(&e)), e));
    let malformed = |e: Failure| throwable(PKCS_IO, Some(format!("malformed data: {}", e.message)), Some(e));
    let object = match from_byte_array(content) {
        Err(e) => return problem(e),
        Ok(None) => return problem(throwable(PKCS_IO, Some("empty data passed to constructor".into()), None)),
        Ok(Some(object)) => object,
    };
    let structures = Structures;
    // `parseBytes` turns a ClassCastException or an IllegalArgumentException into malformed data
    let attributes = match structures.certification_request(&object) {
        Err(e) if [CLASS_CAST, crate::recorded::ILLEGAL_ARGUMENT].contains(&e.classes[0]) => return problem(malformed(e)),
        Err(e) => return problem(e),
        Ok(attributes) => attributes,
    };
    if let Err(e) = structures.alternative_signature(&attributes) {
        return problem(e);
    }
    not_private_key("pkcs.PKCS10CertificationRequest")
}

/// `PEMParser.X509AttributeCertificateParser`: `new X509AttributeCertificateHolder(content)`; its IOException
/// passes, any other failure is wrapped as `problem parsing attribute cert`.
pub(super) fn attribute_certificate(content: &[u8]) -> Option<Failure> {
    // `CertUtils.parseNonEmptyASN1`
    let object = match from_byte_array(content) {
        Err(e) => return Some(e),
        Ok(None) => return Some(throwable(IO_EXCEPTION, Some("no content found".into()), None)),
        Ok(Some(object)) => object,
    };
    match Structures.attribute_certificate(&object) {
        Err(Stop::Unmodelled) => None,
        // `parseBytes` turns a ClassCastException or an IllegalArgumentException into malformed data
        Err(Stop::Fail(e)) if [CLASS_CAST, crate::recorded::ILLEGAL_ARGUMENT].contains(&e.classes[0]) => {
            Some(throwable(CERT_IO, Some(format!("malformed data: {}", e.message)), Some(e)))
        }
        Err(Stop::Fail(e)) => Some(pem_exception(format!("problem parsing attribute cert: {}", java_string(&e)), e)),
        Ok(()) => not_private_key("cert.X509AttributeCertificateHolder"),
    }
}

/// `PEMParser.PKCS7Parser`: `ContentInfo.getInstance(content)`, its failure wrapped as `problem parsing PKCS7 object`;
/// a ContentInfo is an ASN.1 object, whose first element `PrivateKeyInfo.getInstance` then reads as the version.
pub(super) fn content_info(content: &[u8]) -> Option<Failure> {
    let problem = |e: Failure| Some(pem_exception(format!("problem parsing PKCS7 object: {}", java_string(&e)), e));
    let structures = Structures;
    let items = match sequence(content) {
        Err(e) => return problem(e),
        Ok(items) => items,
    };
    if items.is_empty() || items.len() > 2 {
        return problem(bad_size(items.len()));
    }
    if let Err(e) = structures.oid(&items[0]) {
        return problem(e);
    }
    if let Some(content) = items.get(1) {
        // `ASN1TaggedObject.getContextInstance`, explicit and tag 0
        let checked = structures.tagged(content).and_then(|(class, no, _)| {
            Structures::context(class)?;
            if content.explicit().is_none() || no != 0 {
                return Err(iae("Bad tag for 'content'"));
            }
            Ok(())
        });
        if let Err(e) = checked {
            return problem(e);
        }
    }
    Some(iae("illegal object in getInstance: shaded_package.org.bouncycastle.asn1.ASN1ObjectIdentifier"))
}
