//! BouncyCastle 1.86's ASN.1 decoding (`ASN1InputStream`, `DefiniteLengthInputStream`, and for an indefinite length
//! `IndefiniteLengthInputStream` under an `ASN1StreamParser`) and the structures PEMParser builds from a private key's
//! DER (`PrivateKeyInfo`, `RSAPrivateKey`, the SEC1 `ECPrivateKey`), as far as their failures go: each error is the
//! exception BouncyCastle throws, with its texts.

use super::{iae, java_string, pem_exception, throwable, Failure, IO_EXCEPTION, PEM_EXCEPTION};

mod structures;

const ASN1_EXCEPTION: &str = "shaded_package.org.bouncycastle.asn1.ASN1Exception";
const EOF_EXCEPTION: &str = "java.io.EOFException";
const ILLEGAL_STATE: &str = "java.lang.IllegalStateException";

/// A decoded `ASN1Primitive`, as much of it as the structures read.
#[derive(Clone)]
pub(super) enum Asn1 {
    Integer(Vec<u8>),
    /// the OID's content octets
    Oid(Vec<u8>),
    /// `DEROctetString` or `BEROctetString`, and its octets
    OctetString(&'static str, Vec<u8>),
    /// `DERBitString`, `DLBitString` or `BERBitString`: its pad bits and octets
    BitString(&'static str, u8, Vec<u8>),
    /// the elements; `DLSequence`, or `BERSequence` (`true`) for an indefinite length
    Sequence(Vec<Asn1>, bool),
    /// the elements; `DLSet`, or `BERSet` (`true`) for an indefinite length
    Set(Vec<Asn1>, bool),
    /// a `LazyEncodedSequence` (a definite-length SEQUENCE read by a lazily evaluating `ASN1InputStream`): its
    /// contents octets, decoded only when a structure reads its elements
    Lazy(Vec<u8>),
    /// `DLTaggedObject`, or `BERTaggedObject` (`ber`) for an indefinite length, and what it holds
    Tagged { class: u8, no: u32, ber: bool, body: TagBody },
    /// any other primitive, by its simple class name
    Other(&'static str),
}

impl Asn1 {
    /// `getClass().getName()` (shaded).
    pub(super) fn class(&self) -> String {
        let name = match self {
            Asn1::Integer(_) => "ASN1Integer",
            Asn1::Oid(_) => "ASN1ObjectIdentifier",
            Asn1::OctetString(name, _) | Asn1::BitString(name, ..) => name,
            Asn1::Sequence(_, false) => "DLSequence",
            Asn1::Sequence(_, true) => "BERSequence",
            Asn1::Set(_, false) => "DLSet",
            Asn1::Set(_, true) => "BERSet",
            Asn1::Lazy(_) => "LazyEncodedSequence",
            Asn1::Tagged { ber: false, .. } => "DLTaggedObject",
            Asn1::Tagged { ber: true, .. } => "BERTaggedObject",
            Asn1::Other(name) => name,
        };
        format!("shaded_package.org.bouncycastle.asn1.{name}")
    }

    /// The object of a tagged object BouncyCastle parsed as explicit (`PARSED_EXPLICIT`: a constructed encoding
    /// holding exactly one), `None` for any other.
    pub(super) fn explicit(&self) -> Option<&Asn1> {
        match self {
            Asn1::Tagged { body: TagBody::Constructed(items), .. } if items.len() == 1 => Some(&items[0]),
            _ => None,
        }
    }
}

/// What a tagged object holds: a primitive encoding's octets, or a constructed one's objects.
#[derive(Clone)]
pub(super) enum TagBody {
    Primitive(Vec<u8>),
    Constructed(Vec<Asn1>),
}

fn io(message: impl Into<String>) -> Failure {
    throwable(IO_EXCEPTION, Some(message.into()), None)
}

fn eof(message: Option<String>) -> Failure {
    throwable(EOF_EXCEPTION, message, None)
}

fn asn1(message: impl Into<String>, cause: Option<Failure>) -> Failure {
    throwable(ASN1_EXCEPTION, Some(message.into()), cause)
}

/// `new ASN1Exception(e.getMessage(), e)`: `createPrimitiveDERObject` over a constructor's IllegalArgumentException
/// or IllegalStateException.
fn corrupt(class: &'static str, message: &str) -> Failure {
    asn1(message, Some(throwable(class, Some(message.into()), None)))
}

/// `ASN1BitString.createPrimitive` of a BIT STRING's contents: its IllegalArgumentException unwrapped.
fn bit_string(contents: &[u8]) -> Result<Asn1, Failure> {
    let Some(&pad) = contents.first() else { return Err(iae("truncated BIT STRING detected")) };
    if pad > 0 {
        if pad > 7 || contents.len() < 2 {
            return Err(iae("invalid pad bits detected"));
        }
        let last = contents[contents.len() - 1];
        if last != last & (0xffu8 << pad) {
            return Ok(Asn1::BitString("DLBitString", pad, contents[1..].to_vec()));
        }
    }
    Ok(Asn1::BitString("DERBitString", pad, contents[1..].to_vec()))
}

/// `StreamUtil.checkLength`.
fn check_length(length: usize, limit: usize) -> Result<(), Failure> {
    if length > limit {
        return Err(asn1(format!("corrupted stream - out of bounds length found: {length} > {limit}"), None));
    }
    Ok(())
}

/// A stream over the one below it.
enum Stream {
    /// a `DefiniteLengthInputStream`
    Definite { original: usize, remaining: usize },
    /// an `IndefiniteLengthInputStream`: the two octets it has read ahead (`-1` past the end), whether it met its
    /// end-of-contents octets and whether it looks for them
    Indefinite { b1: i32, b2: i32, eof_reached: bool, eof_on_00: bool },
}

/// The input and the streams open over it: level 0 is the `ByteArrayInputStream`, level `n` the `n`-th stream,
/// each reading from the one below; `lazy` when the `ASN1InputStream` evaluates sequences lazily.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    streams: Vec<Stream>,
    lazy: bool,
}

impl Reader<'_> {
    /// `read()` at `level`: `None` at its end. A definite-length stream whose source ends first throws its
    /// truncation; an indefinite-length one, which reads two octets ahead, an `EOFException` without a message.
    fn read(&mut self, level: usize) -> Result<Option<u8>, Failure> {
        if level == 0 {
            let b = self.data.get(self.pos).copied();
            self.pos += usize::from(b.is_some());
            return Ok(b);
        }
        match self.streams[level - 1] {
            Stream::Definite { original, remaining } => {
                if remaining == 0 {
                    return Ok(None);
                }
                let Some(b) = self.read(level - 1)? else { return Err(eof(Some(format!("DEF length {original} object truncated by {remaining}")))) };
                if let Stream::Definite { remaining, .. } = &mut self.streams[level - 1] {
                    *remaining -= 1;
                    if *remaining == 0 {
                        self.parent_eof_detect(level);
                    }
                }
                Ok(Some(b))
            }
            Stream::Indefinite { .. } => {
                if self.check_for_eof(level) {
                    return Ok(None);
                }
                let Some(next) = self.read(level - 1)? else { return Err(eof(None)) };
                let Stream::Indefinite { b1, b2, .. } = &mut self.streams[level - 1] else { unreachable!() };
                let v = *b1;
                (*b1, *b2) = (*b2, i32::from(next));
                Ok(Some(v as u8))
            }
        }
    }

    /// `LimitedInputStream.setParentEofDetect(true)`: an indefinite-length stream below `level` looks for its
    /// end-of-contents octets again.
    fn parent_eof_detect(&mut self, level: usize) {
        if level >= 2 && matches!(self.streams[level - 2], Stream::Indefinite { .. }) {
            self.set_eof_on_00(level - 1, true);
        }
    }

    /// `IndefiniteLengthInputStream.setEofOn00`, when `level` is one.
    fn set_eof_on_00(&mut self, level: usize, on: bool) {
        if let Some(Stream::Indefinite { eof_on_00, .. }) = level.checked_sub(1).and_then(|i| self.streams.get_mut(i)) {
            *eof_on_00 = on;
            self.check_for_eof(level);
        }
    }

    /// `IndefiniteLengthInputStream.checkForEof`.
    fn check_for_eof(&mut self, level: usize) -> bool {
        let Stream::Indefinite { b1, b2, eof_reached, eof_on_00 } = &mut self.streams[level - 1] else { return false };
        if !*eof_reached && *eof_on_00 && *b1 == 0 && *b2 == 0 {
            *eof_reached = true;
            self.parent_eof_detect(level);
            return true;
        }
        *eof_reached
    }

    /// `new IndefiniteLengthInputStream(in)` over `level`: the new level.
    fn open_indefinite(&mut self, level: usize) -> Result<usize, Failure> {
        let b1 = self.read(level)?.map_or(-1, i32::from);
        let b2 = self.read(level)?.map_or(-1, i32::from);
        if b2 < 0 {
            return Err(eof(None));
        }
        self.streams.push(Stream::Indefinite { b1, b2, eof_reached: false, eof_on_00: true });
        let inner = self.streams.len();
        self.check_for_eof(inner);
        Ok(inner)
    }

    /// `new DefiniteLengthInputStream(in, length)` over `level`: the new level.
    fn open_definite(&mut self, level: usize, length: usize) -> usize {
        self.streams.push(Stream::Definite { original: length, remaining: length });
        let inner = self.streams.len();
        if length == 0 {
            self.parent_eof_detect(inner);
        }
        let _ = level;
        inner
    }

    fn close(&mut self, level: usize) {
        self.streams.truncate(level - 1);
    }

    fn remaining(&self, level: usize) -> usize {
        match self.streams[level - 1] {
            Stream::Definite { remaining, .. } => remaining,
            Stream::Indefinite { .. } => 0,
        }
    }

    /// `DefiniteLengthInputStream.toByteArray`.
    fn contents(&mut self, level: usize) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::with_capacity(self.remaining(level));
        while let Some(b) = self.read(level)? {
            out.push(b);
        }
        Ok(out)
    }

    /// `ASN1InputStream.readTagNumber`.
    fn tag_number(&mut self, level: usize, tag: u8) -> Result<u32, Failure> {
        let mut tag_no = u32::from(tag & 0x1f);
        if tag_no == 0x1f {
            let Some(mut b) = self.read(level)? else { return Err(eof(Some("EOF found inside tag value.".into()))) };
            if b < 31 {
                return Err(io("corrupted stream - high tag number < 31 found"));
            }
            tag_no = u32::from(b & 0x7f);
            if tag_no == 0 {
                return Err(io("corrupted stream - invalid high tag number found"));
            }
            while b & 0x80 != 0 {
                if tag_no >> 24 != 0 {
                    return Err(io("Tag number more than 31 bits"));
                }
                tag_no <<= 7;
                let Some(next) = self.read(level)? else { return Err(eof(Some("EOF found inside tag value.".into()))) };
                b = next;
                tag_no |= u32::from(b & 0x7f);
            }
        }
        Ok(tag_no)
    }

    /// `ASN1InputStream.readLength(InputStream)` (`long_form` false) or `readLongLength` (true): `None` for the
    /// indefinite form.
    fn length(&mut self, level: usize, long_form: bool) -> Result<Option<usize>, Failure> {
        let Some(first) = self.read(level)? else { return Err(eof(Some("EOF found when length expected".into()))) };
        if first & 0x80 == 0 {
            return Ok(Some(usize::from(first)));
        }
        if first == 0x80 {
            return Ok(None);
        }
        if first == 0xff {
            return Err(io("invalid long form definite-length 0xFF"));
        }
        let mut length: u64 = 0;
        for _ in 0..(first & 0x7f) {
            let Some(octet) = self.read(level)? else { return Err(eof(Some("EOF found reading length".into()))) };
            if long_form && length >> 55 != 0 {
                return Err(io("long form definite-length more than 63 bits"));
            }
            if !long_form && length >> 23 != 0 {
                return Err(io("long form definite-length more than 31 bits"));
            }
            length = (length << 8) + u64::from(octet);
        }
        Ok(Some(usize::try_from(length).unwrap_or(usize::MAX)))
    }

    /// `ASN1InputStream.readObject` on a stream reading `level` with `limit`: `None` at the end.
    fn object(&mut self, level: usize, limit: usize) -> Result<Option<Asn1>, Failure> {
        match self.read(level)? {
            None => Ok(None),
            Some(0) => Err(io("unexpected end-of-contents marker")),
            Some(tag) => self.build(level, limit, tag).map(Some),
        }
    }

    fn build(&mut self, level: usize, limit: usize, tag: u8) -> Result<Asn1, Failure> {
        let tag_no = self.tag_number(level, tag)?;
        let Some(length) = self.length(level, false)? else {
            if tag & 0x20 == 0 {
                return Err(io("indefinite-length primitive encoding encountered"));
            }
            return self.indefinite(level, limit, tag, tag_no);
        };
        // `buildObject`
        check_length(length, limit)?;
        let inner = self.open_definite(level, length);
        let result = self.definite_object(inner, tag, tag_no);
        self.close(inner);
        result
    }

    fn definite_object(&mut self, level: usize, tag: u8, tag_no: u32) -> Result<Asn1, Failure> {
        if tag & 0xe0 == 0 {
            return self.primitive(level, tag_no);
        }
        if tag & 0xc0 != 0 {
            let body = if tag & 0x20 == 0 { TagBody::Primitive(self.contents(level)?) } else { TagBody::Constructed(self.vector(level)?) };
            return Ok(Asn1::Tagged { class: tag & 0xc0, no: tag_no, ber: false, body });
        }
        match tag_no {
            3 => self.constructed_string(level, "BIT STRING", "BERBitString"),
            4 => self.constructed_string(level, "OCTET STRING", "BEROctetString"),
            16 if self.lazy && self.remaining(level) > 0 => Ok(Asn1::Lazy(self.contents(level)?)),
            16 => Ok(Asn1::Sequence(self.vector(level)?, false)),
            17 => Ok(Asn1::Set(self.vector(level)?, false)),
            8 => self.vector(level).map(|_| Asn1::Other("DERExternal")),
            _ => Err(io(format!("unknown tag {tag_no} encountered"))),
        }
    }

    /// `buildConstructedBitString` / `buildConstructedOctetString`.
    fn constructed_string(&mut self, level: usize, what: &str, class: &'static str) -> Result<Asn1, Failure> {
        let (mut pad, mut octets) = (0, Vec::new());
        for item in self.vector(level)? {
            match item {
                Asn1::BitString(_, p, bytes) if what == "BIT STRING" => {
                    pad = p;
                    octets.extend(bytes);
                }
                Asn1::OctetString(_, bytes) if what == "OCTET STRING" => octets.extend(bytes),
                other => return Err(asn1(format!("unknown object encountered in constructed {what}: class {}", other.class()), None)),
            }
        }
        Ok(if what == "OCTET STRING" { Asn1::OctetString(class, octets) } else { Asn1::BitString(class, pad, octets) })
    }

    /// `readVector(DefiniteLengthInputStream)`: the elements, read by a sub-stream limited to what remains.
    fn vector(&mut self, level: usize) -> Result<Vec<Asn1>, Failure> {
        let limit = self.remaining(level);
        let mut items = Vec::new();
        if limit < 1 {
            return Ok(items);
        }
        while let Some(item) = self.object(level, limit)? {
            items.push(item);
        }
        Ok(items)
    }

    /// `ASN1InputStream.readObject`'s indefinite length: an `IndefiniteLengthInputStream` and an `ASN1StreamParser`
    /// over it, its object loaded.
    fn indefinite(&mut self, level: usize, limit: usize, tag: u8, tag_no: u32) -> Result<Asn1, Failure> {
        let inner = self.open_indefinite(level)?;
        let result = if tag & 0xc0 == 0 && ![3, 4, 8, 16, 17].contains(&tag_no) {
            Err(io("unknown BER object encountered"))
        } else {
            self.parsed_constructed(inner, limit, tag, tag_no, true)
        };
        self.close(inner);
        result
    }

    /// `ASN1StreamParser.implParseObject` and the loaded object of the parser it makes, for an object whose tag
    /// octet has been read from `level`.
    fn parsed(&mut self, level: usize, limit: usize, tag: u8) -> Result<Asn1, Failure> {
        self.set_eof_on_00(level, false);
        let tag_no = self.tag_number(level, tag)?;
        let Some(length) = self.length(level, true)? else {
            if tag & 0x20 == 0 {
                return Err(io("indefinite-length primitive encoding encountered"));
            }
            let inner = self.open_indefinite(level)?;
            let result = self.parsed_constructed(inner, limit, tag, tag_no, true);
            self.close(inner);
            return result;
        };
        let inner = self.open_definite(level, length);
        let limit = limit.min(length);
        let result = if tag & 0xe0 == 0 {
            // `parseImplicitPrimitive`
            match tag_no {
                8 => Err(asn1("externals must use constructed encoding (see X.690 8.18)", None)),
                16 => Err(asn1("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)", None)),
                17 => Err(asn1("sets must use constructed encoding (see X.690 8.11.1/8.12.1)", None)),
                // `DLBitStringParser`: loaded outside `createPrimitiveDERObject`, which wraps a constructor's failure
                3 => self.contents(inner).and_then(|contents| bit_string(&contents)),
                4 => self.contents(inner).map(|octets| Asn1::OctetString("DEROctetString", octets)),
                _ => check_length(self.remaining(inner), limit).and_then(|()| self.primitive(inner, tag_no)),
            }
        } else if tag & 0xc0 != 0 && tag & 0x20 == 0 {
            self.contents(inner).map(|octets| Asn1::Tagged { class: tag & 0xc0, no: tag_no, ber: false, body: TagBody::Primitive(octets) })
        } else {
            self.parsed_constructed(inner, limit, tag, tag_no, false)
        };
        self.close(inner);
        result
    }

    /// `ASN1StreamParser.readVector` over `level`.
    fn parsed_vector(&mut self, level: usize, limit: usize) -> Result<Vec<Asn1>, Failure> {
        let mut items = Vec::new();
        while let Some(tag) = self.read(level)? {
            items.push(self.parsed(level, limit, tag)?);
        }
        Ok(items)
    }

    /// A constructed object of a stream parser (`ber` for an indefinite length): `parseImplicitConstructedIL` /
    /// `DL` or a tagged object parser, loaded.
    fn parsed_constructed(&mut self, level: usize, limit: usize, tag: u8, tag_no: u32, ber: bool) -> Result<Asn1, Failure> {
        if tag & 0xc0 != 0 {
            return Ok(Asn1::Tagged { class: tag & 0xc0, no: tag_no, ber, body: TagBody::Constructed(self.parsed_vector(level, limit)?) });
        }
        let unknown = |o: &Asn1| io(format!("unknown object encountered: class {}", o.class()));
        match tag_no {
            3 => {
                let (mut pad, mut octets) = (0, Vec::new());
                for item in self.parsed_vector(level, limit)? {
                    let Asn1::BitString(_, p, bytes) = item else { return Err(unknown(&item)) };
                    pad = p;
                    octets.extend(bytes);
                }
                Ok(Asn1::BitString("BERBitString", pad, octets))
            }
            4 => {
                let mut octets = Vec::new();
                for item in self.parsed_vector(level, limit)? {
                    let Asn1::OctetString(_, bytes) = item else { return Err(unknown(&item)) };
                    octets.extend(bytes);
                }
                Ok(Asn1::OctetString("BEROctetString", octets))
            }
            8 => {
                if self.parsed_vector(level, limit)?.is_empty() {
                    return Err(asn1("corrupted stream detected", Some(iae("too few objects in input sequence"))));
                }
                Ok(Asn1::Other("DLExternal"))
            }
            16 => Ok(Asn1::Sequence(self.parsed_vector(level, limit)?, ber)),
            17 => Ok(Asn1::Set(self.parsed_vector(level, limit)?, ber)),
            _ => Err(asn1(format!("unknown {} object encountered: 0x{tag_no:x}", if ber { "BER" } else { "DL" }), None)),
        }
    }

    /// `createPrimitiveDERObject`.
    fn primitive(&mut self, level: usize, tag_no: u32) -> Result<Asn1, Failure> {
        const IAE: &str = crate::recorded::ILLEGAL_ARGUMENT;
        let string = |class: &'static str, r: &mut Self| r.contents(level).map(|_| Asn1::Other(class));
        match tag_no {
            1 => {
                if self.remaining(level) != 1 {
                    return Err(corrupt(IAE, "BOOLEAN value should have 1 byte in it"));
                }
                self.read(level)?;
                Ok(Asn1::Other("ASN1Boolean"))
            }
            2 => {
                let contents = self.contents(level)?;
                if malformed_integer(&contents) {
                    return Err(corrupt(IAE, "malformed integer"));
                }
                Ok(Asn1::Integer(contents))
            }
            3 => {
                let contents = self.contents(level)?;
                bit_string(&contents).map_err(|e| corrupt(crate::recorded::ILLEGAL_ARGUMENT, &e.message))
            }
            4 => self.contents(level).map(|octets| Asn1::OctetString("DEROctetString", octets)),
            5 => {
                if self.remaining(level) != 0 {
                    return Err(corrupt(ILLEGAL_STATE, "malformed NULL encoding encountered"));
                }
                Ok(Asn1::Other("DERNull"))
            }
            6 | 13 => {
                if self.remaining(level) > 4096 {
                    return Err(corrupt(IAE, "exceeded OID contents length limit"));
                }
                let contents = self.contents(level)?;
                if !valid_oid(&contents) {
                    return Err(corrupt(IAE, if tag_no == 6 { "invalid OID contents" } else { "invalid relative OID contents" }));
                }
                Ok(if tag_no == 6 { Asn1::Oid(contents) } else { Asn1::Other("ASN1RelativeOID") })
            }
            10 => {
                let contents = self.contents(level)?;
                match contents.len() {
                    0 => return Err(corrupt(IAE, "ENUMERATED has zero length")),
                    1 => {}
                    _ if malformed_integer(&contents) => return Err(corrupt(IAE, "malformed enumerated")),
                    _ if contents[0] & 0x80 != 0 => return Err(corrupt(IAE, "enumerated must be non-negative")),
                    _ => {}
                }
                Ok(Asn1::Other("ASN1Enumerated"))
            }
            30 => {
                if self.remaining(level) & 1 != 0 {
                    return Err(io("malformed BMPString encoding encountered"));
                }
                string("DERBMPString", self)
            }
            7 => string("ASN1ObjectDescriptor", self),
            12 => string("DERUTF8String", self),
            18 => string("DERNumericString", self),
            19 => string("DERPrintableString", self),
            20 => string("DERT61String", self),
            21 => string("DERVideotexString", self),
            22 => string("DERIA5String", self),
            23 => string("ASN1UTCTime", self),
            24 => string("ASN1GeneralizedTime", self),
            25 => string("DERGraphicString", self),
            26 => string("DERVisibleString", self),
            27 => string("DERGeneralString", self),
            28 => string("DERUniversalString", self),
            14 | 31..=36 => Err(io(format!("unsupported tag {tag_no} encountered"))),
            _ => Err(io(format!("unknown tag {tag_no} encountered"))),
        }
    }
}

/// `ASN1Integer.isMalformed`.
fn malformed_integer(bytes: &[u8]) -> bool {
    match bytes {
        [] => true,
        [_] => false,
        [first, second, ..] => *first as i8 == (*second as i8) >> 7,
    }
}

/// `ASN1RelativeOID.isValidContents`.
fn valid_oid(contents: &[u8]) -> bool {
    if contents.is_empty() {
        return false;
    }
    let mut start = true;
    for &b in contents {
        if start && b == 0x80 {
            return false;
        }
        start = b & 0x80 == 0;
    }
    start
}

/// `ASN1Primitive.fromByteArray`: the object, `None` for no input, or the IOException.
pub(super) fn from_byte_array(der: &[u8]) -> Result<Option<Asn1>, Failure> {
    let mut reader = Reader { data: der, pos: 0, streams: Vec::new(), lazy: false };
    let object = reader.object(0, der.len())?;
    if reader.pos != der.len() {
        return Err(io("Extra data detected in stream"));
    }
    Ok(object)
}

/// Whether `catch (IOException e)` catches `e`.
fn is_io(e: &Failure) -> bool {
    [IO_EXCEPTION, EOF_EXCEPTION, ASN1_EXCEPTION].contains(&e.classes[0])
}

/// `ASN1Sequence.getInstance(byte[])`: the elements, or its IllegalArgumentException (a RuntimeException from
/// the decoder passes through).
pub(super) fn sequence(der: &[u8]) -> Result<Vec<Asn1>, Failure> {
    match from_byte_array(der) {
        Err(e) if is_io(&e) => Err(throwable(crate::recorded::ILLEGAL_ARGUMENT, Some("failed to construct sequence from byte[]".into()), Some(e))),
        Err(e) => Err(e),
        Ok(Some(Asn1::Sequence(items, _))) => Ok(items),
        Ok(other) => Err(iae(format!("unexpected object: {}", other.map_or("null".into(), |o| o.class())))),
    }
}

/// `ASN1Sequence.getInstance(Object)` of a decoded object.
pub(super) fn sequence_of(object: &Asn1) -> Result<&[Asn1], Failure> {
    match object {
        Asn1::Sequence(items, _) => Ok(items),
        other => Err(iae(format!("unknown object in getInstance: {}", other.class()))),
    }
}

/// The JDK's `ClassCastException` for a cast of `object` to the BouncyCastle class `to`.
pub(super) fn cast(object: &Asn1, to: &str) -> Failure {
    let (from, to) = (object.class(), format!("shaded_package.org.bouncycastle.asn1.{to}"));
    let message = format!("class {from} cannot be cast to class {to} ({from} and {to} are in unnamed module of loader 'app')");
    throwable("java.lang.ClassCastException", Some(message), None)
}

/// `Enumeration.nextElement` past the end.
pub(super) fn no_such_element() -> Failure {
    throwable("java.util.NoSuchElementException", None, None)
}

/// `ASN1Integer.intValueExact`.
pub(super) fn int_value_exact(bytes: &[u8]) -> Result<i64, Failure> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] as i8 == (bytes[start + 1] as i8) >> 7 {
        start += 1;
    }
    let value = &bytes[start..];
    if value.len() > 4 {
        return Err(throwable("java.lang.ArithmeticException", Some("ASN.1 Integer out of int range".into()), None));
    }
    Ok(value.iter().fold(i64::from(value[0] as i8 >> 7), |acc, b| (acc << 8) | i64::from(*b)))
}

/// A `PrivateKeyInfo`: its algorithm's OID (content octets) and parameters, its private key's octets, and its
/// `[1]` public key (the tagged object).
pub(super) struct PrivateKeyInfo {
    pub algorithm: Vec<u8>,
    pub parameters: Option<Asn1>,
    pub key: Vec<u8>,
    pub public_key: Option<Asn1>,
}

/// `PrivateKeyInfo.getInstance(byte[])`.
pub(super) fn private_key_info(der: &[u8]) -> Result<PrivateKeyInfo, Failure> {
    private_key_info_of(&sequence(der)?)
}

/// `PrivateKeyInfo.getInstance(ASN1Sequence)`.
pub(super) fn private_key_info_of(items: &[Asn1]) -> Result<PrivateKeyInfo, Failure> {
    let mut elements = items.iter();
    let mut next = || elements.next().ok_or_else(no_such_element);
    let illegal = |o: &Asn1| iae(format!("illegal object in getInstance: {}", o.class()));
    let version = match next()? {
        Asn1::Integer(bytes) => int_value_exact(bytes)?,
        other => return Err(illegal(other)),
    };
    if !(0..=1).contains(&version) {
        return Err(iae("invalid version for private key info"));
    }
    let (algorithm, parameters) = match next()? {
        Asn1::Sequence(algorithm, _) => {
            if algorithm.is_empty() || algorithm.len() > 2 {
                return Err(iae(format!("Bad sequence size: {}", algorithm.len())));
            }
            let Asn1::Oid(oid) = &algorithm[0] else { return Err(illegal(&algorithm[0])) };
            (oid.clone(), algorithm.get(1).cloned())
        }
        other => return Err(iae(format!("unknown object in getInstance: {}", other.class()))),
    };
    let key = match next()? {
        Asn1::OctetString(_, octets) => octets.clone(),
        other => return Err(illegal(other)),
    };
    let mut last = -1i64;
    let mut public_key = None;
    for element in elements {
        let Asn1::Tagged { no, .. } = element else { return Err(cast(element, "ASN1TaggedObject")) };
        let no = i64::from(*no);
        if no <= last {
            return Err(iae("invalid optional field in private key info"));
        }
        last = no;
        match no {
            0 => {}
            1 if version < 1 => return Err(iae("'publicKey' requires version v2(1) or later")),
            1 => public_key = Some(element.clone()),
            _ => return Err(iae("unknown optional field in private key info")),
        }
    }
    Ok(PrivateKeyInfo { algorithm, parameters, key, public_key })
}

/// The content octets of the OID `dotted`.
pub(super) fn oid_content(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().expect("an OID")).collect();
    let mut out = vec![(40 * arcs[0] + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v != 0 {
            chunk.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        out.extend(chunk.iter().rev());
    }
    out
}

/// `RSAPrivateKey(ASN1Sequence)`: the contents of its nine INTEGERs (version, n, e, d, p, q, dp, dq, qi).
pub(super) fn rsa_private_key(items: &[Asn1]) -> Result<Vec<Vec<u8>>, Failure> {
    let mut elements = items.iter();
    let mut integer = || match elements.next() {
        None => Err(no_such_element()),
        Some(Asn1::Integer(bytes)) => Ok(bytes.clone()),
        Some(other) => Err(cast(other, "ASN1Integer")),
    };
    let version = integer()?;
    if !(0..=1).contains(&int_value_exact(&version)?) {
        return Err(iae("wrong version for RSA private key"));
    }
    let mut values = vec![version];
    for _ in 0..8 {
        values.push(integer()?);
    }
    match items.get(9) {
        Some(other) if !matches!(other, Asn1::Sequence(..)) => Err(cast(other, "ASN1Sequence")),
        _ => Ok(values),
    }
}

/// `PEMParser.RSAKeyPairParser.parse`: the key's nine INTEGERs, or the PEMException.
pub(super) fn rsa_key_pair(der: &[u8]) -> Result<Vec<Vec<u8>>, Failure> {
    let problem = |e: Failure| pem_exception(format!("problem creating RSA private key: {}", java_string(&e)), e);
    let items = sequence(der).map_err(problem)?;
    if items.len() != 9 {
        return Err(throwable(PEM_EXCEPTION, Some("malformed sequence in RSA private key".into()), None));
    }
    rsa_private_key(&items).map_err(problem)
}

/// `PEMParser.ECDSAKeyPairParser.parse` up to `ECPrivateKey.getInstance`: the key's elements, or the PEMException.
pub(super) fn ec_key_pair(der: &[u8]) -> Result<Vec<Asn1>, Failure> {
    sequence(der).map_err(|e| pem_exception(format!("problem creating EC private key: {}", java_string(&e)), e))
}

/// `PEMParser.DSAKeyPairParser.parse`: the contents of the key's INTEGERs after its version (p, q, g, y, x), or the
/// PEMException (its own `malformed sequence` and `wrong version` ones without a cause).
pub(super) fn dsa_key_pair(der: &[u8]) -> Result<Vec<Vec<u8>>, Failure> {
    let problem = |e: Failure| pem_exception(format!("problem creating DSA private key: {}", java_string(&e)), e);
    let items = sequence(der).map_err(problem)?;
    if items.len() != 6 {
        return Err(throwable(PEM_EXCEPTION, Some("malformed sequence in DSA private key".into()), None));
    }
    // `ASN1Integer.getInstance`
    let integer = |object: &Asn1| match object {
        Asn1::Integer(bytes) => Ok(bytes.clone()),
        other => Err(problem(iae(format!("illegal object in getInstance: {}", other.class())))),
    };
    // `hasValue(0)` of a minimally encoded INTEGER
    if integer(&items[0])?.iter().any(|b| *b != 0) {
        return Err(throwable(PEM_EXCEPTION, Some("wrong version for DSA private key".into()), None));
    }
    items[1..].iter().map(integer).collect()
}

/// `AlgorithmIdentifier.getInstance` of an element.
fn algorithm_identifier(object: &Asn1) -> Result<(), Failure> {
    let items = sequence_of(object)?;
    if items.is_empty() || items.len() > 2 {
        return Err(iae(format!("Bad sequence size: {}", items.len())));
    }
    match &items[0] {
        Asn1::Oid(_) => Ok(()),
        other => Err(iae(format!("illegal object in getInstance: {}", other.class()))),
    }
}

/// What `PEMParser.readObject` and `PrivateKeyInfo.getInstance` make of a PEM object of another type than a private
/// key (`CERTIFICATE`, `PUBLIC KEY`, ...): the exception `PEMToFile.privateKeyFromPEM` catches, or `None` where it is
/// not modelled (a certificate's structure past its outer SEQUENCE's size, and what `structures` leaves out).
pub(super) fn other_object(kind: &str, content: &[u8]) -> Option<Failure> {
    let wrapped = |prefix: &str, e: Failure| pem_exception(format!("{prefix}: {}", java_string(&e)), e);
    // `PrivateKeyInfo.getInstance` of the object the parser returns
    let not_private_key = |class: &str| Some(iae(format!("unknown object in getInstance: shaded_package.org.bouncycastle.{class}")));
    let illegal_first = |class: &str| Some(iae(format!("illegal object in getInstance: shaded_package.org.bouncycastle.{class}")));
    // a holder's `parseBytes`: `fromByteArray`, then the structure's IllegalArgumentException as `malformed data`
    let holder = |exception: &'static str, structure: &dyn Fn(&[Asn1]) -> Option<Failure>| -> Option<Failure> {
        let malformed = |e: Failure| throwable(exception, Some(format!("malformed data: {}", e.message)), Some(e));
        match from_byte_array(content) {
            Err(e) => Some(e),
            Ok(Some(Asn1::Sequence(items, _))) => structure(&items).map(malformed),
            Ok(other) => Some(malformed(iae(format!("unknown object in getInstance: {}", other.map_or("null".into(), |o| o.class()))))),
        }
    };
    const CERT_IO: &str = "shaded_package.org.bouncycastle.cert.CertIOException";
    match kind {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
            let certificate = |items: &[Asn1]| (items.len() != 3).then(|| iae("sequence wrong size for a certificate"));
            if let Some(e) = holder(CERT_IO, &certificate) {
                return Some(wrapped("problem parsing cert", e));
            }
            if x509_parser::parse_x509_certificate(content).is_err() {
                return None;
            }
            if kind == "TRUSTED CERTIFICATE" { not_private_key("openssl.X509TrustedCertificateBlock") } else { not_private_key("cert.X509CertificateHolder") }
        }
        "X509 CRL" => structures::crl(content),
        "ATTRIBUTE CERTIFICATE" => structures::attribute_certificate(content),
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => structures::certification_request(content),
        "PUBLIC KEY" | "RSA PUBLIC KEY" => {
            let items = match sequence(content) {
                Err(e) => return Some(wrapped("problem extracting key", e)),
                Ok(items) => items,
            };
            if items.len() != 2 {
                return Some(wrapped("problem extracting key", iae(format!("Bad sequence size: {}", items.len()))));
            }
            let structure = if kind == "PUBLIC KEY" {
                algorithm_identifier(&items[0]).and_then(|()| match &items[1] {
                    Asn1::BitString(..) => Ok(()),
                    other => Err(iae(format!("illegal object in getInstance: {}", other.class()))),
                })
            } else {
                match items.iter().find(|o| !matches!(o, Asn1::Integer(_))) {
                    Some(other) => Err(iae(format!("illegal object in getInstance: {}", other.class()))),
                    None => Ok(()),
                }
            };
            match structure {
                Err(e) => Some(wrapped("problem extracting key", e)),
                Ok(()) => illegal_first("asn1.x509.AlgorithmIdentifier"),
            }
        }
        "EC PARAMETERS" => match from_byte_array(content) {
            Err(e) => Some(e),
            Ok(Some(Asn1::Oid(_))) => not_private_key("asn1.ASN1ObjectIdentifier"),
            Ok(Some(Asn1::Sequence(items, _))) if items.is_empty() => {
                Some(throwable(PEM_EXCEPTION, Some("exception extracting EC named curve: java.lang.ArrayIndexOutOfBoundsException: Index 0 out of bounds for length 0".into()), None))
            }
            Ok(Some(Asn1::Sequence(..))) => None,
            // the parser returns null
            Ok(_) => Some(super::null_private_key_info()),
        },
        "PKCS7" | "CMS" => structures::content_info(content),
        "ENCRYPTED PRIVATE KEY" => {
            let problem = |e: Failure| wrapped("problem parsing ENCRYPTED PRIVATE KEY", e);
            let items = match sequence(content) {
                Err(e) => return Some(problem(e)),
                Ok(items) => items,
            };
            let mut elements = items.iter();
            let algorithm = match elements.next() {
                None => return Some(problem(no_such_element())),
                Some(a) => a,
            };
            if let Err(e) = algorithm_identifier(algorithm) {
                return Some(problem(e));
            }
            match elements.next() {
                None => Some(problem(no_such_element())),
                Some(Asn1::OctetString(..)) => not_private_key("pkcs.PKCS8EncryptedPrivateKeyInfo"),
                Some(other) => Some(problem(iae(format!("illegal object in getInstance: {}", other.class())))),
            }
        }
        _ => None,
    }
}
