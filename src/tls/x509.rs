//! The JDK's X.509 certificate reading (`sun.security.provider.X509Factory` over `sun.security.x509` and
//! `sun.security.util.DerValue`, as in the oracle's Temurin 26.0.2), as far as a CA chain file or a JWK `x5c` entry
//! can make it fail: [`generate_certificates`] is `CertificateFactory.generateCertificates` (a PEM or DER block
//! sequence, or one PKCS#7 bundle) and [`generate_certificate`] is `generateCertificate` (one block). Each failure is
//! the [`Throwable`] the JDK throws, with its causes, so a caller can print the chain as the console does.
//!
//! Ported: the DER layer (definite and indefinite lengths, `DerIndefLenConverter`), `X509CertImpl` and
//! `X509CertInfo` (version, serial number, algorithm identifiers named by `KnownOIDs` with their parameters,
//! `X500Name`/`RDN`/`AVA`, validity times, `X509Key` over the key factories of SunRsaSign, SunEC, SUN, SunJCE and
//! BouncyCastle, unique identifiers, extensions and their `verifyCert`), every extension class `OIDMap` names
//! (with `GeneralNames`, `URIName` through `java.net.URI` and `GeneralSubtrees`), and PKCS#7 `SignedData` (new and
//! old style, with signer attributes and CRLs) and the Netscape certificate sequence. The first
//! part is checked by `tests/files/x509/vectors.tsv`, the rest by `more.tsv`.

use num_bigint::{BigInt, BigUint};
use std::rc::Rc;

pub const IO: &str = "java.io.IOException";
const EOF: &str = "java.io.EOFException";
pub const CERTIFICATE: &str = "java.security.cert.CertificateException";
const CERTIFICATE_PARSING: &str = "java.security.cert.CertificateParsingException";
const PARSING: &str = "sun.security.pkcs.ParsingException";
const INVALID_KEY: &str = "java.security.InvalidKeyException";
const INVALID_KEY_SPEC: &str = "java.security.spec.InvalidKeySpecException";
const INDEX_OUT_OF_BOUNDS: &str = "java.lang.ArrayIndexOutOfBoundsException";

/// A Java throwable: its class, message and cause.
#[derive(Clone, Debug, PartialEq)]
pub struct Throwable {
    pub class: &'static str,
    pub message: Option<String>,
    pub cause: Option<Box<Throwable>>,
}

impl Throwable {
    pub fn new(class: &'static str, message: impl Into<String>) -> Throwable {
        Throwable { class, message: Some(message.into()), cause: None }
    }

    fn caused(class: &'static str, message: impl Into<String>, cause: Throwable) -> Throwable {
        Throwable { class, message: Some(message.into()), cause: Some(Box::new(cause)) }
    }

    /// `new X(cause)`: the cause's `toString` is the message.
    fn wrapping(class: &'static str, cause: Throwable) -> Throwable {
        Throwable { class, message: Some(cause.line()), cause: Some(Box::new(cause)) }
    }

    /// `Throwable.toString`
    pub fn line(&self) -> String {
        match &self.message {
            Some(m) => format!("{}: {m}", self.class),
            None => self.class.to_string(),
        }
    }

    /// `toString` of this throwable and of each cause, outermost first.
    pub fn chain(&self) -> Vec<String> {
        let mut out = vec![self.line()];
        let mut at = &self.cause;
        while let Some(c) = at {
            out.push(c.line());
            at = &c.cause;
        }
        out
    }

    pub fn message(&self) -> String {
        self.message.clone().unwrap_or_else(|| "null".into())
    }

    /// `instanceof IOException`
    fn is_io(&self) -> bool {
        matches!(self.class, IO | EOF | PARSING)
    }
}

type JResult<T> = Result<T, Throwable>;

fn io<T>(message: impl Into<String>) -> JResult<T> {
    Err(Throwable::new(IO, message))
}

fn index_out_of_bounds(index: i64, length: usize) -> Throwable {
    Throwable::new(INDEX_OUT_OF_BOUNDS, format!("Index {index} out of bounds for length {length}"))
}

/// A tag as the JDK prints it: a signed `byte`.
fn signed(tag: u8) -> i8 {
    tag as i8
}

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OBJECT_ID: u8 = 0x06;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_T61_STRING: u8 = 0x14;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_GENERAL_STRING: u8 = 0x1b;
const TAG_UNIVERSAL_STRING: u8 = 0x1c;
const TAG_BMP_STRING: u8 = 0x1e;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

// ---------------------------------------------------------------------------------------------------------------
// DER

/// `DerOutputStream.putLength`
fn put_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 1 << 8 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 1 << 16 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else if len < 1 << 24 {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[0x84, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}

fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    put_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// `DerInputStream`
#[derive(Clone)]
struct DerInputStream {
    data: Rc<Vec<u8>>,
    start: usize,
    end: usize,
    allow_ber: bool,
    pos: usize,
}

impl DerInputStream {
    fn of(bytes: Vec<u8>) -> DerInputStream {
        let end = bytes.len();
        DerInputStream { data: Rc::new(bytes), start: 0, end, allow_ber: true, pos: 0 }
    }

    fn available(&self) -> usize {
        self.end - self.pos
    }

    fn byte_array(&self) -> Vec<u8> {
        self.data[self.pos..self.end].to_vec()
    }

    fn get_der_value(&mut self) -> JResult<DerValue> {
        let result = DerValue::parse(self.data.clone(), self.pos, self.end - self.pos, self.allow_ber, true)?;
        if !Rc::ptr_eq(&result.buffer, &self.data) {
            let unused = result.buffer.len() - result.end;
            self.pos = self.end - unused;
        } else {
            self.pos = result.end;
        }
        Ok(result)
    }

    fn get_sequence(&mut self) -> JResult<Vec<DerValue>> {
        self.get_der_value()?.subs(TAG_SEQUENCE)
    }

    fn get_set(&mut self) -> JResult<Vec<DerValue>> {
        self.get_der_value()?.subs(TAG_SET)
    }

    /// `getSet(startLen, implicit = true)`
    fn get_implicit_set(&mut self) -> JResult<Vec<DerValue>> {
        self.get_der_value()?.subs(0)
    }

    fn get_oid(&mut self) -> JResult<Oid> {
        self.get_der_value()?.get_oid()
    }

    fn get_big_integer(&mut self) -> JResult<BigInt> {
        self.get_der_value()?.get_big_integer()
    }

    fn get_positive_big_integer(&mut self) -> JResult<BigUint> {
        self.get_der_value()?.get_positive_big_integer()
    }

    fn get_octet_string(&mut self) -> JResult<Vec<u8>> {
        let mut v = self.get_der_value()?;
        if v.tag != TAG_OCTET_STRING {
            return io("DER input not an octet string");
        }
        v.get_octet_string()
    }

    fn get_unaligned_bit_string(&mut self) -> JResult<BitArray> {
        self.get_der_value()?.get_unaligned_bit_string(false)
    }

    fn get_utc_time(&mut self) -> JResult<()> {
        self.get_der_value()?.get_utc_time()
    }

    fn get_generalized_time(&mut self) -> JResult<()> {
        self.get_der_value()?.get_generalized_time()
    }

    fn peek_byte(&self) -> JResult<u8> {
        if self.pos == self.end {
            return io("At end");
        }
        Ok(self.data[self.pos])
    }
}

/// `DerValue`: a tag and the bytes of its value, `data` the stream over them.
#[derive(Clone)]
struct DerValue {
    tag: u8,
    buffer: Rc<Vec<u8>>,
    start: usize,
    end: usize,
    data: DerInputStream,
}

impl DerValue {
    fn with(tag: u8, buffer: Rc<Vec<u8>>, start: usize, end: usize, allow_ber: bool) -> DerValue {
        let data = DerInputStream { data: buffer.clone(), start, end, allow_ber, pos: start };
        DerValue { tag, buffer, start, end, data }
    }

    /// `new DerValue(tag, byte[] value)`
    fn of(tag: u8, value: Vec<u8>) -> DerValue {
        let end = value.len();
        DerValue::with(tag, Rc::new(value), 0, end, true)
    }

    /// `new DerValue(byte[] encoding)`
    fn from(encoding: &[u8]) -> JResult<DerValue> {
        DerValue::parse(Rc::new(encoding.to_vec()), 0, encoding.len(), true, false)
    }

    /// `DerValue(byte[] buf, int offset, int len, boolean allowBER, boolean allowMore)`
    fn parse(buffer: Rc<Vec<u8>>, offset: usize, len: usize, allow_ber: bool, allow_more: bool) -> JResult<DerValue> {
        if len < 2 {
            return io("Too short");
        }
        let (mut buf, mut offset, mut len) = (buffer, offset, len);
        let mut pos = offset;
        let tag = buf[pos];
        pos += 1;
        if tag & 0x1f == 0x1f {
            return io(format!("Tag number over 30 at {offset} is not supported"));
        }
        let mut len_byte = buf[pos] as i8 as i32;
        pos += 1;
        if len_byte == -128 {
            if !allow_ber {
                return io("Indefinite length encoding not supported with DER");
            }
            if tag & 0x20 == 0 {
                return io("Indefinite length encoding not supported with non-constructed data");
            }
            let converted = indefinite::convert_stream(&buf[pos..offset + len], tag)?;
            buf = Rc::new(converted);
            offset = 0;
            len = buf.len();
            pos = 2;
            if tag != buf[0] {
                return io("Indefinite length encoding not supported");
            }
            len_byte = buf[1] as i8 as i32;
            if len_byte == -128 {
                return io("Indefinite len conversion failed");
            }
        }
        let length: i32 = if len_byte & 0x80 == 0 {
            len_byte
        } else {
            let mut count = len_byte & 0x7f;
            if count > 4 {
                return io("Invalid lenByte");
            }
            if (len as i64) < 2 + count as i64 {
                return io("Not enough length bytes");
            }
            let mut value = i32::from(buf[pos]);
            pos += 1;
            count -= 1;
            if value == 0 && !allow_ber {
                return io("Redundant length bytes found");
            }
            while count > 0 {
                value = value.wrapping_shl(8).wrapping_add(i32::from(buf[pos]));
                pos += 1;
                count -= 1;
            }
            if value < 0 {
                return io("Invalid length bytes");
            } else if value <= 127 && !allow_ber {
                return io("Should use short form for length");
            }
            value
        };
        let (len, length) = (len as i64, i64::from(length));
        if len - length < (pos - offset) as i64 {
            return Err(Throwable::new(EOF, "not enough content"));
        }
        if len - length > (pos - offset) as i64 && !allow_more {
            return io("extra data at the end");
        }
        let end = pos + length as usize;
        Ok(DerValue::with(tag, buf, pos, end, allow_ber))
    }

    fn allow_ber(&self) -> bool {
        self.data.allow_ber
    }

    fn length(&self) -> usize {
        self.end - self.start
    }

    fn bytes(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    fn is_context_specific(&self) -> bool {
        self.tag & 0xc0 == 0x80
    }

    fn is_context(&self, n: u8) -> bool {
        self.is_context_specific() && self.tag & 0x1f == n
    }

    fn is_constructed(&self) -> bool {
        self.tag & 0x20 == 0x20
    }

    /// `resetTag`
    fn retag(&mut self, tag: u8) {
        self.tag = tag;
    }

    /// `data()`: a fresh stream over the value.
    fn fresh(&self) -> DerInputStream {
        DerInputStream { data: self.buffer.clone(), start: self.start, end: self.end, allow_ber: self.allow_ber(), pos: self.start }
    }

    fn reach_end(&mut self) {
        self.data.pos = self.data.end;
    }

    fn byte_array(&mut self) -> Vec<u8> {
        self.data.pos = self.data.start;
        encode(self.tag, self.bytes())
    }

    fn der_input_stream(&mut self) -> JResult<&mut DerInputStream> {
        if self.tag == TAG_SEQUENCE || self.tag == TAG_SET {
            return Ok(&mut self.data);
        }
        io(format!("toDerInputStream rejects tag type {}", signed(self.tag)))
    }

    fn subs(&self, expected: u8) -> JResult<Vec<DerValue>> {
        if expected != 0 && expected != self.tag {
            return io("Not the correct tag");
        }
        let mut out = Vec::new();
        let mut dis = self.fresh();
        while dis.available() > 0 {
            out.push(dis.get_der_value()?);
        }
        Ok(out)
    }

    fn get_boolean(&mut self) -> JResult<bool> {
        if self.tag != TAG_BOOLEAN {
            return io(format!("DerValue.getBoolean, not a BOOLEAN {}", signed(self.tag)));
        }
        if self.length() != 1 {
            return io(format!("DerValue.getBoolean, invalid length {}", self.length()));
        }
        self.reach_end();
        Ok(self.buffer[self.start] != 0)
    }

    fn get_oid(&mut self) -> JResult<Oid> {
        if self.tag != TAG_OBJECT_ID {
            return io(format!("DerValue.getOID, not an OID {}", signed(self.tag)));
        }
        self.reach_end();
        Oid::new(self.bytes().to_vec())
    }

    fn get_octet_string(&mut self) -> JResult<Vec<u8>> {
        self.octet_string(0)
    }

    fn octet_string(&mut self, limit: u32) -> JResult<Vec<u8>> {
        let limit = limit + 1;
        if limit > 30 {
            return io("Nested OctetString limit reached (30).");
        }
        if self.tag != TAG_OCTET_STRING && !(self.is_constructed() && self.tag & 0x1f == TAG_OCTET_STRING) {
            return io(format!("DerValue.getOctetString, not an Octet String: {}", signed(self.tag)));
        }
        if self.length() == 0 {
            return Ok(Vec::new());
        }
        self.reach_end();
        if !self.is_constructed() {
            return Ok(self.bytes().to_vec());
        }
        let mut out = Vec::new();
        let mut dis = self.fresh();
        while dis.available() > 0 {
            out.extend(dis.get_der_value()?.octet_string(limit)?);
        }
        Ok(out)
    }

    fn big_integer(&mut self, expected: u8) -> JResult<&[u8]> {
        if self.tag != expected {
            return io(format!("DerValue.getBigIntegerInternal, not expected {}", signed(self.tag)));
        }
        if self.end == self.start {
            return io("Invalid encoding: zero length Int value");
        }
        self.reach_end();
        let b = self.bytes();
        if !self.allow_ber() && b.len() >= 2 && b[0] == 0 && b[1] < 0x80 {
            return io("Invalid encoding: redundant leading 0s");
        }
        Ok(&self.buffer[self.start..self.end])
    }

    fn get_big_integer(&mut self) -> JResult<BigInt> {
        Ok(BigInt::from_signed_bytes_be(self.big_integer(TAG_INTEGER)?))
    }

    fn get_positive_big_integer(&mut self) -> JResult<BigUint> {
        Ok(BigUint::from_bytes_be(self.big_integer(TAG_INTEGER)?))
    }

    fn get_integer(&mut self) -> JResult<i32> {
        self.integer(TAG_INTEGER)
    }

    fn get_enumerated(&mut self) -> JResult<i32> {
        self.integer(TAG_ENUMERATED)
    }

    /// `getIntegerInternal`
    fn integer(&mut self, expected: u8) -> JResult<i32> {
        let value = BigInt::from_signed_bytes_be(self.big_integer(expected)?);
        if value < BigInt::from(i32::MIN) {
            return io("Integer below minimum valid value");
        }
        if value > BigInt::from(i32::MAX) {
            return io("Integer exceeds maximum valid value");
        }
        Ok(i32::try_from(&value).unwrap_or_default())
    }

    /// `checkPaddedBits`: the bit length.
    fn check_padded_bits(&self, pad: i8) -> JResult<usize> {
        if !(0..=7).contains(&pad) {
            return io("Invalid number of padding bits");
        }
        let bits = ((self.length() as i64 - 1) << 3) - i64::from(pad);
        if bits < 0 {
            return io("Not enough bytes in BitString");
        }
        if !self.allow_ber() && pad != 0 && self.buffer[self.end - 1] & (0xffu8 >> (8 - pad)) != 0 {
            return io("Invalid value of padding bits");
        }
        Ok(bits as usize)
    }

    fn get_bit_string(&mut self) -> JResult<Vec<u8>> {
        if self.tag != TAG_BIT_STRING {
            return io(format!("DerValue.getBitString, not a bit string {}", signed(self.tag)));
        }
        if self.end == self.start {
            return io("Invalid encoding: zero length bit string");
        }
        self.reach_end();
        let pad = self.buffer[self.start] as i8;
        self.check_padded_bits(pad)?;
        let mut out = self.buffer[self.start + 1..self.end].to_vec();
        if pad != 0 && let Some(last) = out.last_mut() {
            *last &= 0xffu8 << pad;
        }
        Ok(out)
    }

    fn get_unaligned_bit_string(&mut self, implicit: bool) -> JResult<BitArray> {
        if !implicit && self.tag != TAG_BIT_STRING {
            return io(format!("DerValue.getBitString, not a bit string {}", signed(self.tag)));
        }
        if self.end == self.start {
            return io("Invalid encoding: zero length bit string");
        }
        self.reach_end();
        let pad = self.buffer[self.start] as i8;
        let bits = self.check_padded_bits(pad)?;
        Ok(BitArray::new(bits, &self.buffer[self.start + 1..self.end]))
    }

    /// `readStringInternal`, as far as the tag check (the readers decode with replacement, so never fail).
    fn string(&mut self, expected: u8) -> JResult<String> {
        if self.tag != expected {
            return io(format!("Incorrect string type {} is not {}", signed(self.tag), signed(expected)));
        }
        self.reach_end();
        Ok(self.bytes().iter().map(|&b| if b < 0x80 { char::from(b) } else { '\u{fffd}' }).collect())
    }

    /// `validateBMPString`: a decoded surrogate pair is refused at its index.
    fn validate_bmp_string(&mut self) -> JResult<()> {
        self.string(TAG_BMP_STRING)?;
        let bytes = self.bytes();
        let units: Vec<u16> = bytes.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        let (mut i, mut index) = (0, 0);
        while i < units.len() {
            let high = (0xd800..0xdc00).contains(&units[i]);
            if high && units.get(i + 1).is_some_and(|u| (0xdc00..0xe000).contains(u)) {
                return io(format!("Illegal character in BMPString, index: {index}"));
            }
            i += 1;
            index += 1;
        }
        Ok(())
    }

    fn get_utc_time(&mut self) -> JResult<()> {
        if self.tag != TAG_UTC_TIME {
            return io(format!("DerValue.getUTCTime, not a UtcTime: {}", signed(self.tag)));
        }
        if self.length() < 11 || self.length() > 17 {
            return io("DER UTC Time length error");
        }
        self.reach_end();
        self.time(false)
    }

    fn get_generalized_time(&mut self) -> JResult<()> {
        if self.tag != TAG_GENERALIZED_TIME {
            return io(format!("DerValue.getGeneralizedTime, not a GeneralizedTime: {}", signed(self.tag)));
        }
        if self.length() < 13 {
            return io("DER Generalized Time length error");
        }
        self.reach_end();
        self.time(true)
    }

    /// `getTimeInternal`, as far as it can fail (reading past the value is an index error, as in Java).
    fn time(&self, generalized: bool) -> JResult<()> {
        let kind = if generalized { "Generalized" } else { "UTC" };
        let buffer = &self.buffer;
        let mut pos = self.start;
        let mut len = self.length() as i64;
        let at = |pos: usize| buffer.get(pos).copied().ok_or_else(|| index_out_of_bounds(pos as i64, buffer.len()));
        let digit = |b: u8| -> JResult<i32> {
            if !b.is_ascii_digit() {
                return io(format!("Parse {kind} time, invalid format"));
            }
            Ok(i32::from(b - b'0'))
        };
        let two = |pos: &mut usize| -> JResult<i32> {
            let d = 10 * digit(at(*pos)?)? + digit(at(*pos + 1)?)?;
            *pos += 2;
            Ok(d)
        };
        two(&mut pos)?;
        if generalized {
            two(&mut pos)?;
            len -= 2;
        }
        let month = two(&mut pos)?;
        let day = two(&mut pos)?;
        let hour = two(&mut pos)?;
        let minute = two(&mut pos)?;
        len -= 10;
        let mut second = 0;
        if len > 2 {
            second = two(&mut pos)?;
            len -= 2;
            if generalized && matches!(at(pos)?, b'.' | b',') {
                len -= 1;
                if len == 0 {
                    return io(format!("Parse {kind} time, empty fractional part"));
                }
                pos += 1;
                let mut precision = 0;
                while !matches!(at(pos)?, b'Z' | b'+' | b'-') {
                    digit(at(pos)?)?;
                    precision += 1;
                    len -= 1;
                    if len == 0 {
                        return io(format!("Parse {kind} time, invalid fractional part"));
                    }
                    pos += 1;
                }
                if precision == 0 {
                    return io(format!("Parse {kind} time, empty fractional part"));
                }
            }
        }
        if month == 0 || day == 0 || month > 12 || day > 31 || hour >= 24 || minute >= 60 || second >= 60 {
            return io(format!("Parse {kind} time, invalid format"));
        }
        if len != 1 && len != 5 {
            return io(format!("Parse {kind} time, invalid offset"));
        }
        let sign = at(pos)?;
        pos += 1;
        match sign {
            b'+' | b'-' => {
                if len != 5 {
                    return io(format!("Parse {kind} time, invalid offset"));
                }
                let hr = two(&mut pos)?;
                let min = two(&mut pos)?;
                if hr >= 24 || min >= 60 {
                    return io(format!("Parse {kind} time, {}hhmm", char::from(sign)));
                }
            }
            b'Z' => {
                if len != 1 {
                    return io(format!("Parse {kind} time, invalid format"));
                }
            }
            _ => return io(format!("Parse {kind} time, garbage offset")),
        }
        Ok(())
    }
}

/// `BitArray(length, a, offset)`: the bits, the unused ones of the last byte cleared.
#[derive(Clone)]
struct BitArray {
    length: usize,
    bytes: Vec<u8>,
}

impl BitArray {
    fn new(length: usize, a: &[u8]) -> BitArray {
        let rep = length.div_ceil(8);
        let unused = rep * 8 - length;
        let mut bytes = a[..rep].to_vec();
        if let Some(last) = bytes.last_mut() {
            *last &= 0xffu8 << unused;
        }
        BitArray { length, bytes }
    }
}

/// `DerIndefLenConverter`: indefinite lengths rewritten as definite ones.
mod indefinite {
    use super::{index_out_of_bounds, io, JResult, Throwable, INDEX_OUT_OF_BOUNDS};

    enum Entry {
        Start(usize),
        Length(Vec<u8>),
    }

    struct Converter<'a> {
        data: &'a [u8],
        data_pos: usize,
        data_size: usize,
        unresolved: i32,
        ndefs: Vec<Entry>,
        total_len_bytes: i64,
        new_data: Vec<u8>,
        new_pos: usize,
        index: usize,
    }

    fn length_bytes(len: i64) -> Vec<u8> {
        let len = len as i32;
        if len < 128 {
            vec![len as u8]
        } else if len < 1 << 8 {
            vec![0x81, len as u8]
        } else if len < 1 << 16 {
            vec![0x82, (len >> 8) as u8, len as u8]
        } else if len < 1 << 24 {
            vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
        } else {
            vec![0x84, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    impl Converter<'_> {
        fn byte(&self, at: usize) -> JResult<u8> {
            self.data.get(at).copied().ok_or_else(|| index_out_of_bounds(at as i64, self.data.len()))
        }

        fn is_eoc(&self, at: usize) -> JResult<bool> {
            Ok(self.byte(at)? == 0 && self.byte(at + 1)? == 0)
        }

        fn parse_tag(&mut self) -> JResult<()> {
            if self.is_eoc(self.data_pos)? {
                let mut encapsulated = 0i64;
                let mut found = None;
                for (i, e) in self.ndefs.iter().enumerate().rev() {
                    match e {
                        Entry::Start(at) => {
                            found = Some((i, *at));
                            break;
                        }
                        Entry::Length(b) => encapsulated += b.len() as i64 - 3,
                    }
                }
                let Some((i, at)) = found else { return io("EOC does not have matching indefinite-length tag") };
                let section = self.data_pos as i64 - at as i64 + encapsulated;
                let bytes = length_bytes(section);
                self.total_len_bytes += bytes.len() as i64 - 3;
                self.ndefs[i] = Entry::Length(bytes);
                self.unresolved -= 1;
            }
            self.data_pos += 1;
            Ok(())
        }

        fn parse_length(&mut self) -> JResult<i64> {
            if self.data_pos == self.data_size {
                return Ok(0);
            }
            let mut len_byte = usize::from(self.byte(self.data_pos)?);
            self.data_pos += 1;
            if len_byte == 0x80 {
                self.ndefs.push(Entry::Start(self.data_pos));
                self.unresolved += 1;
                return Ok(0);
            }
            let mut cur: i32 = 0;
            if len_byte & 0x80 != 0 {
                len_byte &= 0x7f;
                if len_byte > 4 {
                    return io("Too much data");
                }
                if (self.data_size as i64 - self.data_pos as i64) < len_byte as i64 + 1 {
                    return Ok(-1);
                }
                for _ in 0..len_byte {
                    cur = cur.wrapping_shl(8).wrapping_add(i32::from(self.byte(self.data_pos)?));
                    self.data_pos += 1;
                }
                if cur < 0 {
                    return io("Invalid length bytes");
                }
            } else {
                cur = (len_byte & 0x7f) as i32;
            }
            Ok(i64::from(cur))
        }

        fn put(&mut self, b: u8) -> JResult<()> {
            if self.new_pos >= self.new_data.len() {
                return Err(index_out_of_bounds(self.new_pos as i64, self.new_data.len()));
            }
            self.new_data[self.new_pos] = b;
            self.new_pos += 1;
            Ok(())
        }

        fn write_tag(&mut self) -> JResult<()> {
            while self.data_pos < self.data_size {
                if self.is_eoc(self.data_pos)? {
                    self.data_pos += 2;
                } else {
                    let b = self.byte(self.data_pos)?;
                    self.data_pos += 1;
                    self.put(b)?;
                    break;
                }
            }
            Ok(())
        }

        fn write_length_and_value(&mut self) -> JResult<()> {
            if self.data_pos == self.data_size {
                return Ok(());
            }
            let mut len_byte = usize::from(self.byte(self.data_pos)?);
            self.data_pos += 1;
            if len_byte == 0x80 {
                let Some(Entry::Length(bytes)) = self.ndefs.get(self.index) else { return io("Indefinite len conversion failed") };
                let bytes = bytes.clone();
                self.index += 1;
                for b in bytes {
                    self.put(b)?;
                }
                return Ok(());
            }
            let mut cur: i32 = 0;
            if len_byte & 0x80 != 0 {
                len_byte &= 0x7f;
                for _ in 0..len_byte {
                    cur = cur.wrapping_shl(8).wrapping_add(i32::from(self.byte(self.data_pos)?));
                    self.data_pos += 1;
                }
                if cur < 0 {
                    return io("Invalid length bytes");
                }
            } else {
                cur = (len_byte & 0x7f) as i32;
            }
            for b in length_bytes(i64::from(cur)) {
                self.put(b)?;
            }
            // `System.arraycopy(data, dataPos, newData, newDataPos, curLen)`
            let cur = cur as usize;
            if self.data_pos + cur > self.data.len() {
                return Err(Throwable::new(INDEX_OUT_OF_BOUNDS, format!("arraycopy: last source index {} out of bounds for byte[{}]", self.data_pos + cur, self.data.len())));
            }
            if self.new_pos + cur > self.new_data.len() {
                return Err(Throwable::new(INDEX_OUT_OF_BOUNDS, format!("arraycopy: last destination index {} out of bounds for byte[{}]", self.new_pos + cur, self.new_data.len())));
            }
            self.new_data[self.new_pos..self.new_pos + cur].copy_from_slice(&self.data[self.data_pos..self.data_pos + cur]);
            self.data_pos += cur;
            self.new_pos += cur;
            Ok(())
        }
    }

    /// `convertBytes`: `None` when more data is needed.
    fn convert_bytes(data: &[u8]) -> JResult<Option<Vec<u8>>> {
        let mut c = Converter { data, data_pos: 0, data_size: data.len(), unresolved: 0, ndefs: Vec::new(), total_len_bytes: 0, new_data: Vec::new(), new_pos: 0, index: 0 };
        while c.data_pos < c.data_size {
            if c.data_pos + 2 > c.data_size {
                return Ok(None);
            }
            c.parse_tag()?;
            let len = c.parse_length()?;
            if len < 0 {
                return Ok(None);
            }
            c.data_pos += len as usize;
            if c.unresolved == 0 {
                break;
            }
        }
        if c.unresolved != 0 {
            return Ok(None);
        }
        let unused = c.data_size as i64 - c.data_pos as i64;
        let size = c.data_pos as i64 + c.total_len_bytes + unused;
        if size < 0 || unused < 0 {
            return Err(Throwable::new("java.lang.NegativeArraySizeException", format!("{size}")));
        }
        c.data_size = c.data_pos;
        c.new_data = vec![0; size as usize];
        c.data_pos = 0;
        c.new_pos = 0;
        c.index = 0;
        while c.data_pos < c.data_size {
            c.write_tag()?;
            c.write_length_and_value()?;
        }
        let from = c.data_size;
        let to = (c.data_size as i64 + c.total_len_bytes) as usize;
        c.new_data[to..].copy_from_slice(&data[from..from + unused as usize]);
        Ok(Some(c.new_data))
    }

    /// `convertStream(in, tag)` over the bytes after an indefinite length octet.
    pub fn convert_stream(rest: &[u8], tag: u8) -> JResult<Vec<u8>> {
        let mut data = vec![tag, 0x80];
        data.extend_from_slice(rest);
        match convert_bytes(&data)? {
            Some(result) => Ok(result),
            None => io("not enough data to resolve indef len BER"),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ObjectIdentifier and AlgorithmId

/// `ObjectIdentifier`: its DER contents.
#[derive(Clone, PartialEq)]
struct Oid(Vec<u8>);

impl Oid {
    /// `ObjectIdentifier(byte[])`: `checkOidSize` and `check`.
    fn new(encoding: Vec<u8>) -> JResult<Oid> {
        if encoding.len() > 4096 {
            return io(format!("ObjectIdentifier encoded length exceeds the restriction in JDK (OId length(>=): {}, Restriction: 4096)", encoding.len()));
        }
        if encoding.last().is_none_or(|b| b & 0x80 != 0) {
            return io("ObjectIdentifier() -- Invalid DER encoding, not ended");
        }
        for i in 0..encoding.len() {
            if encoding[i] == 0x80 && (i == 0 || encoding[i - 1] & 0x80 == 0) {
                return io("ObjectIdentifier() -- Invalid DER encoding, useless extra octet detected");
            }
        }
        Ok(Oid(encoding))
    }

    fn is(&self, dotted: &str) -> bool {
        self.to_string() == dotted
    }
}

impl std::fmt::Display for Oid {
    /// `ObjectIdentifier.toString`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        let mut from = 0;
        for i in 0..self.0.len() {
            if self.0[i] & 0x80 != 0 {
                continue;
            }
            if from != 0 {
                out.push('.');
            }
            let section = &self.0[from..=i];
            let mut value = BigUint::ZERO;
            for b in section {
                value = (value << 7u32) | BigUint::from(b & 0x7f);
            }
            if from == 0 {
                if section.len() > 4 {
                    out.push_str(&format!("2.{}", value - 80u32));
                } else {
                    let v = u32::try_from(&value).unwrap_or_default();
                    if v < 80 {
                        out.push_str(&format!("{}.{}", v / 40, v % 40));
                    } else {
                        out.push_str(&format!("2.{}", v - 80));
                    }
                }
            } else {
                out.push_str(&value.to_string());
            }
            from = i + 1;
        }
        f.write_str(&out)
    }
}

/// The OIDs `AlgorithmId.getName` calls "RSA" (`KnownOIDs` PKCS1, RSA, ITUX509_RSA).
const RSA_KEYS: &[&str] = &["1.2.840.113549.1.1", "1.2.840.113549.1.1.1", "2.5.8.1.1"];
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// `CurveDB`'s named curves (by OID) and their field sizes.
const CURVES: &[(&str, usize)] = &[
    ("1.2.840.10045.3.0.11", 239), ("1.2.840.10045.3.0.12", 239), ("1.2.840.10045.3.0.13", 239), ("1.2.840.10045.3.0.18", 359),
    ("1.2.840.10045.3.0.20", 431), ("1.2.840.10045.3.0.5", 191), ("1.2.840.10045.3.0.6", 191), ("1.2.840.10045.3.0.7", 191),
    ("1.2.840.10045.3.1.1", 192), ("1.2.840.10045.3.1.2", 192), ("1.2.840.10045.3.1.3", 192), ("1.2.840.10045.3.1.4", 239),
    ("1.2.840.10045.3.1.5", 239), ("1.2.840.10045.3.1.6", 239), ("1.2.840.10045.3.1.7", 256), ("1.3.132.0.1", 163),
    ("1.3.132.0.10", 256), ("1.3.132.0.15", 163), ("1.3.132.0.16", 283), ("1.3.132.0.17", 283), ("1.3.132.0.2", 163),
    ("1.3.132.0.22", 131), ("1.3.132.0.23", 131), ("1.3.132.0.24", 193), ("1.3.132.0.25", 193), ("1.3.132.0.26", 233),
    ("1.3.132.0.27", 233), ("1.3.132.0.28", 128), ("1.3.132.0.29", 128), ("1.3.132.0.3", 239), ("1.3.132.0.30", 160),
    ("1.3.132.0.31", 192), ("1.3.132.0.32", 224), ("1.3.132.0.33", 224), ("1.3.132.0.34", 384), ("1.3.132.0.35", 521),
    ("1.3.132.0.36", 409), ("1.3.132.0.37", 409), ("1.3.132.0.38", 571), ("1.3.132.0.39", 571), ("1.3.132.0.4", 113),
    ("1.3.132.0.5", 113), ("1.3.132.0.6", 112), ("1.3.132.0.7", 112), ("1.3.132.0.8", 160), ("1.3.132.0.9", 160),
    ("1.3.36.3.3.2.8.1.1.1", 160), ("1.3.36.3.3.2.8.1.1.11", 384), ("1.3.36.3.3.2.8.1.1.13", 512), ("1.3.36.3.3.2.8.1.1.3", 192),
    ("1.3.36.3.3.2.8.1.1.5", 224), ("1.3.36.3.3.2.8.1.1.7", 256), ("1.3.36.3.3.2.8.1.1.9", 320),
];

/// The prime-field curves of `CURVES` (`CurveDB`): OID, p, a, b in hex, for BouncyCastle's point decompression.
const PRIME_CURVES: &[(&str, &str, &str, &str)] = &[
    ("1.2.840.10045.3.1.1", "fffffffffffffffffffffffffffffffeffffffffffffffff", "fffffffffffffffffffffffffffffffefffffffffffffffc", "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"),
    ("1.2.840.10045.3.1.2", "fffffffffffffffffffffffffffffffeffffffffffffffff", "fffffffffffffffffffffffffffffffefffffffffffffffc", "cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953"),
    ("1.2.840.10045.3.1.3", "fffffffffffffffffffffffffffffffeffffffffffffffff", "fffffffffffffffffffffffffffffffefffffffffffffffc", "22123dc2395a05caa7423daeccc94760a7d462256bd56916"),
    ("1.2.840.10045.3.1.4", "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a"),
    ("1.2.840.10045.3.1.5", "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", "617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c"),
    ("1.2.840.10045.3.1.6", "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", "255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e"),
    ("1.2.840.10045.3.1.7", "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    ("1.3.132.0.10", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "0", "7"),
    ("1.3.132.0.28", "fffffffdffffffffffffffffffffffff", "fffffffdfffffffffffffffffffffffc", "e87579c11079f43dd824993c2cee5ed3"),
    ("1.3.132.0.29", "fffffffdffffffffffffffffffffffff", "d6031998d1b3bbfebf59cc9bbff9aee1", "5eeefca380d02919dc2c6558bb6d8a5d"),
    ("1.3.132.0.30", "fffffffffffffffffffffffffffffffeffffac73", "fffffffffffffffffffffffffffffffeffffac70", "b4e134d3fb59eb8bab57274904664d5af50388ba"),
    ("1.3.132.0.31", "fffffffffffffffffffffffffffffffffffffffeffffee37", "0", "3"),
    ("1.3.132.0.32", "fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d", "0", "5"),
    ("1.3.132.0.33", "ffffffffffffffffffffffffffffffff000000000000000000000001", "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
    ("1.3.132.0.34", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
    ("1.3.132.0.35", "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
    ("1.3.132.0.6", "db7c2abf62e35e668076bead208b", "db7c2abf62e35e668076bead2088", "659ef8ba043916eede8911702b22"),
    ("1.3.132.0.7", "db7c2abf62e35e668076bead208b", "6127c24c05f38a0aaaf65c0ef02c", "51def1815db5ed74fcc34c85d709"),
    ("1.3.132.0.8", "ffffffffffffffffffffffffffffffff7fffffff", "ffffffffffffffffffffffffffffffff7ffffffc", "1c97befc54bd7a8b65acf89f81d4d4adc565fa45"),
    ("1.3.132.0.9", "fffffffffffffffffffffffffffffffeffffac73", "0", "7"),
    ("1.3.36.3.3.2.8.1.1.1", "e95e4a5f737059dc60dfc7ad95b3d8139515620f", "340e7be2a280eb74e2be61bada745d97e8f7c300", "1e589a8595423412134faa2dbdec95c8d8675e58"),
    ("1.3.36.3.3.2.8.1.1.11", "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826", "4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11"),
    ("1.3.36.3.3.2.8.1.1.13", "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723"),
    ("1.3.36.3.3.2.8.1.1.3", "c302f41d932a36cda7a3463093d18db78fce476de1a86297", "6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef", "469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9"),
    ("1.3.36.3.3.2.8.1.1.5", "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43", "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b"),
    ("1.3.36.3.3.2.8.1.1.7", "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9", "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6"),
    ("1.3.36.3.3.2.8.1.1.9", "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4", "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6"),
];

/// `AlgorithmId`: the OID, its encoded parameters (an ASN.1 NULL is none) and, for an EC key, the named curve and its
/// field size (`ECParameters`).
#[derive(Clone)]
struct AlgorithmId {
    oid: Oid,
    params: Option<Vec<u8>>,
    curve: Option<(String, usize)>,
}

impl PartialEq for AlgorithmId {
    fn eq(&self, other: &AlgorithmId) -> bool {
        self.oid == other.oid && self.params == other.params
    }
}

impl AlgorithmId {
    /// `AlgorithmId.parse`
    fn parse(val: &mut DerValue) -> JResult<AlgorithmId> {
        if val.tag != TAG_SEQUENCE {
            return io("algid parse error, not a sequence");
        }
        let input = val.der_input_stream()?;
        let oid = input.get_oid()?;
        let mut params = None;
        if input.available() != 0 {
            let p = input.get_der_value()?;
            if p.tag == TAG_NULL {
                if p.length() != 0 {
                    return io("invalid NULL");
                }
            } else {
                params = Some(p);
            }
            if input.available() != 0 {
                return io("Invalid AlgorithmIdentifier: extra data");
            }
        }
        let mut algid = AlgorithmId { oid, params: None, curve: None };
        if let Some(mut p) = params {
            algid.params = Some(p.byte_array());
            algid.decode_params()?;
        }
        Ok(algid)
    }

    /// `getName`: the `KnownOIDs` standard name, else the dotted OID.
    fn name(&self) -> String {
        let dotted = self.oid.to_string();
        super::known_oids::std_name(&dotted).map(str::to_string).unwrap_or(dotted)
    }

    /// `decodeParams`: `AlgorithmParameters.getInstance(getName()).init(encodedParams)`, for the algorithms with
    /// parameters a certificate's keys can have (SunEC's EC, SUN's DSA, SunJCE's DiffieHellman, SunRsaSign's
    /// RSASSA-PSS, and BouncyCastle's EdDSA ones, which refuse any); no parameters class, nothing decoded.
    fn decode_params(&mut self) -> JResult<()> {
        let encoded = self.params.clone().unwrap_or_default();
        match self.name().as_str() {
            "EC" => {
                let mut encoded = DerValue::from(&encoded)?;
                if encoded.tag != TAG_OBJECT_ID {
                    return io("Only named ECParameters supported");
                }
                let curve = encoded.get_oid()?.to_string();
                let Some((_, size)) = CURVES.iter().find(|(o, _)| *o == curve) else { return io(format!("Unknown named curve: {curve}")) };
                self.curve = Some((curve, *size));
            }
            // `DSAParameters.engineInit`
            "DSA" => {
                let mut params = DerValue::from(&encoded)?;
                if params.tag != TAG_SEQUENCE {
                    return io("DSA params parsing error");
                }
                for _ in 0..3 {
                    params.data.get_big_integer()?;
                }
                if params.data.available() != 0 {
                    return io(format!("encoded params have {} extra bytes", params.data.available()));
                }
            }
            // `DHParameters.engineInit`
            "DiffieHellman" => {
                let mut params = DerValue::from(&encoded)?;
                if params.tag != TAG_SEQUENCE {
                    return io("DH params parsing error");
                }
                params.data.get_big_integer()?;
                params.data.get_big_integer()?;
                if params.data.available() != 0 {
                    params.data.get_der_value()?.get_integer()?;
                }
                if params.data.available() != 0 {
                    return io("DH parameter parsing error: Extra data");
                }
            }
            "RSASSA-PSS" => pss_parameters(&encoded)?,
            "Ed25519" | "Ed448" => return io("EdDSA parameters have no encoded form (RFC 8410)"),
            _ => {}
        }
        Ok(())
    }
}

/// `PSSParameters.engineInit`
fn pss_parameters(encoded: &[u8]) -> JResult<()> {
    const MGF1: &str = "1.2.840.113549.1.1.8";
    const DIGESTS: &[&str] = &["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"];
    for mut d in DerInputStream::of(encoded.to_vec()).get_sequence()? {
        if d.is_context(0) {
            AlgorithmId::parse(&mut d.data.get_der_value()?)?;
        } else if d.is_context(1) {
            let mgf = AlgorithmId::parse(&mut d.data.get_der_value()?)?;
            if !mgf.oid.is(MGF1) {
                return io("Only MGF1 mgf is supported");
            }
            let Some(params) = &mgf.params else { return io("Missing MGF1 parameters") };
            let digest = AlgorithmId::parse(&mut DerValue::from(params)?)?.name();
            if !DIGESTS.contains(&digest.as_str()) {
                return io(format!("Unrecognized message digest algorithm {digest}"));
            }
        } else if d.is_context(2) {
            if d.data.get_der_value()?.get_integer()? < 0 {
                return io("Negative value for saltLength");
            }
        } else if d.is_context(3) {
            let trailer = d.data.get_der_value()?.get_integer()?;
            if trailer != 1 {
                return io(format!("Unsupported trailerField value {trailer}"));
            }
        } else {
            return io("Invalid encoded PSSParameters");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Keys

/// A certificate's public key, as nimbus compares it with a JWK.
#[derive(Clone, Debug, PartialEq)]
pub enum PublicKey {
    Rsa { modulus: BigUint, exponent: BigUint },
    Ec { x: BigUint, y: BigUint },
    /// A key of an algorithm this port does not build (or a JDK 1.1-style `X509Key`).
    Other,
}

/// An `InvalidKeyException` from a key factory, as `X509Key.buildX509Key` rethrows it: through the factory's
/// `InvalidKeySpecException`, then `new InvalidKeyException(e.getMessage(), e)`.
fn key_spec_failure(cause: Throwable) -> Throwable {
    let spec = Throwable::wrapping(INVALID_KEY_SPEC, cause);
    Throwable::caused(INVALID_KEY, spec.message(), spec)
}

/// `X509Key.parse`: the key and its key bits (`X509Key.getKey()`, unused trailing bits cleared).
fn parse_x509_key(val: &mut DerValue) -> JResult<(PublicKey, Vec<u8>)> {
    if val.tag != TAG_SEQUENCE {
        return io("corrupt subject key");
    }
    let mut algid_value = val.data.get_der_value()?;
    let algid = AlgorithmId::parse(&mut algid_value)?;
    let bits = val.data.get_unaligned_bit_string()?;
    // an `InvalidKeyException` becomes an `IOException`; anything else a key factory throws escapes
    let key = build_x509_key(&algid, &bits).map_err(|e| if e.class == INVALID_KEY { Throwable::caused(IO, format!("subject key, {}", e.message()), e) } else { e })?;
    if val.data.available() != 0 {
        return io("excess subject key");
    }
    Ok((key, bits.bytes))
}

/// `X509Key.buildX509Key`: `KeyFactory.getInstance(algid.getName()).generatePublic` over the providers MockServer has
/// (SunRsaSign, SunEC, SUN, SunJCE, then BouncyCastle, which `generatePublic` falls over to when the first refuses);
/// an `Err` is the `InvalidKeyException`, or a runtime exception a factory throws. A key without a factory here is
/// kept opaque, as the JDK keeps a key without a factory (ML-DSA, ML-KEM and the like have one, which these
/// certificates never make fail).
fn build_x509_key(algid: &AlgorithmId, bits: &BitArray) -> JResult<PublicKey> {
    let name = algid.name();
    if RSA_KEYS.contains(&algid.oid.to_string().as_str()) || name == "RSASSA-PSS" {
        // `parsePKCS1` of the key bits
        let components = (|| -> JResult<(BigUint, BigUint)> {
            let mut der = DerValue::from(&bits.bytes)?;
            if der.tag != TAG_SEQUENCE {
                return io("Not a SEQUENCE");
            }
            let n = der.data.get_positive_big_integer()?;
            let e = der.data.get_positive_big_integer()?;
            if der.data.available() != 0 {
                return io("Extra data available");
            }
            Ok((n, e))
        })();
        let (n, e) = components.map_err(|cause| key_spec_failure(Throwable::caused(INVALID_KEY, "Invalid RSA public key", cause)))?;
        // `KeyFactory.generatePublic` tries the next provider after SunRsaSign: BouncyCastle, which MockServer has
        // registered by then; when that fails too, SunRsaSign's failure is the one thrown
        let fail = |m: String| {
            if bouncy_castle_accepts(algid, bits, &n, &e) {
                return Ok(PublicKey::Rsa { modulus: n.clone(), exponent: e.clone() });
            }
            Err(key_spec_failure(Throwable::new(INVALID_KEY, m)))
        };
        // `checkRSAProviderKeyLengths`, then `checkExponentRange`
        let modulus_bits = (n.bits() as i64 + 7) & !7;
        if modulus_bits < 512 {
            return fail("RSA keys must be at least 512 bits long".into());
        }
        if modulus_bits > 16384 {
            return fail("RSA keys must be no longer than 16384 bits".into());
        }
        if modulus_bits > 3072 && e.bits() > 64 {
            return fail("RSA exponents can be no longer than 64 bits  if modulus is greater than 3072 bits".into());
        }
        if e >= n {
            return fail("exponent is larger than modulus".into());
        }
        if e < BigUint::from(3u8) {
            return fail("exponent is smaller than 3".into());
        }
        return Ok(PublicKey::Rsa { modulus: n, exponent: e });
    }
    if algid.oid.is(EC_PUBLIC_KEY) {
        let Some((curve, field)) = &algid.curve else {
            return Err(key_spec_failure(Throwable::new(INVALID_KEY, "EC domain parameters must be encoded in the algorithm identifier")));
        };
        // `ECUtil.decodePoint`
        let data = &bits.bytes;
        let invalid = |m: &str| Err(key_spec_failure(Throwable::caused(INVALID_KEY, "Invalid EC key", Throwable::new(IO, m))));
        if data.first() != Some(&4) {
            // BouncyCastle's factory reads compressed and hybrid points
            if let Some((x, y)) = bouncy_castle_point(curve, data) {
                return Ok(PublicKey::Ec { x, y });
            }
            return invalid("Only uncompressed point format supported");
        }
        let field = *field;
        let n = (data.len() - 1) / 2;
        if n != (field + 7) >> 3 {
            return invalid("Point does not match field size");
        }
        return Ok(PublicKey::Ec { x: BigUint::from_bytes_be(&data[1..1 + n]), y: BigUint::from_bytes_be(&data[n + 1..n + 1 + n]) });
    }
    let key = &bits.bytes;
    match name.as_str() {
        // SUN's `DSAKeyFactory`: `DSAPublicKeyImpl` reads `y` from the key bits; the factory keeps only the message
        "DSA" => {
            if let Err(e) = DerInputStream::of(key.clone()).get_big_integer() {
                let m = format!("Inappropriate key specification: Invalid key: y value\n{}", e.message());
                return Err(Throwable::caused(INVALID_KEY, m.clone(), Throwable::new(INVALID_KEY_SPEC, m)));
            }
        }
        // SunJCE's `DHKeyFactory`: `DHPublicKey.decode` of the re-encoded key, whose parameters `DHParameters` has
        // read already (NULL ones are re-encoded as none)
        "DiffieHellman" => {
            let failure = |cause: Throwable| {
                let invalid = Throwable::caused(INVALID_KEY, "Invalid encoding", cause);
                let spec = Throwable::caused(INVALID_KEY_SPEC, "Inappropriate key specification", invalid);
                Throwable::caused(INVALID_KEY, "Inappropriate key specification", spec)
            };
            if algid.params.is_none() {
                return Err(failure(Throwable::new(IO, "Parameters missing")));
            }
            DerInputStream::of(key.clone()).get_big_integer().map_err(failure)?;
        }
        // SunEC's `EdDSAKeyFactory` and `XDHKeyFactory`: an EdDSA point's last byte (its x bit) is read, and an X25519
        // u's top byte masked (255 bits), before the length is checked
        "Ed25519" | "Ed448" | "X25519" | "X448" => {
            let (length, read) = match name.as_str() {
                "Ed25519" => (32, Some(-1)),
                "Ed448" => (57, Some(-1)),
                "X25519" => (32, Some(0)),
                _ => (56, None),
            };
            if let (true, Some(index)) = (key.is_empty(), read) {
                return Err(index_out_of_bounds(index, 0));
            }
            if key.len() != length {
                return Err(key_spec_failure(Throwable::new(INVALID_KEY, format!("key length must be {length}"))));
            }
        }
        _ => {}
    }
    Ok(PublicKey::Other)
}

/// BouncyCastle's `ECCurve.decodePoint` for the point SunEC refused, on a prime-field named curve: a compressed
/// point (`02`/`03`, x below p with a square root of x³ + ax + b) or a hybrid one (`06`/`07`, on the curve, y's parity
/// as its prefix says). The binary-field curves are not decompressed here.
fn bouncy_castle_point(curve: &str, data: &[u8]) -> Option<(BigUint, BigUint)> {
    let (_, p, a, b) = PRIME_CURVES.iter().find(|c| c.0 == curve)?;
    let hex = |h: &str| BigUint::parse_bytes(h.as_bytes(), 16).expect("curve parameter");
    let (p, a, b) = (hex(p), hex(a), hex(b));
    let n = (p.bits() as usize).div_ceil(8);
    let rhs = |x: &BigUint| (x.modpow(&BigUint::from(3u8), &p) + &a * x + &b) % &p;
    match *data.first()? {
        prefix @ (2 | 3) if data.len() == n + 1 => {
            let x = BigUint::from_bytes_be(&data[1..]);
            if x >= p {
                return None;
            }
            let y = sqrt_mod(&rhs(&x), &p)?;
            let y = if y.bit(0) == (prefix == 3) { y } else { (&p - &y) % &p };
            Some((x, y))
        }
        prefix @ (6 | 7) if data.len() == 2 * n + 1 => {
            let (x, y) = (BigUint::from_bytes_be(&data[1..=n]), BigUint::from_bytes_be(&data[n + 1..]));
            (x < p && y < p && y.bit(0) == (prefix == 7) && y.modpow(&BigUint::from(2u8), &p) == rhs(&x)).then_some((x, y))
        }
        _ => None,
    }
}

/// A square root of `v` modulo the odd prime `p` (Tonelli-Shanks), `None` for a non-residue.
pub(super) fn sqrt_mod(v: &BigUint, p: &BigUint) -> Option<BigUint> {
    let one = BigUint::from(1u8);
    if v == &BigUint::ZERO {
        return Some(BigUint::ZERO);
    }
    let minus_one = p - &one;
    if v.modpow(&(&minus_one >> 1), p) != one {
        return None;
    }
    let s = minus_one.trailing_zeros().unwrap_or(0);
    let q = &minus_one >> s;
    let mut z = BigUint::from(2u8);
    while z.modpow(&(&minus_one >> 1), p) != minus_one {
        z += 1u8;
    }
    let (mut m, mut c, mut t, mut r) = (s, z.modpow(&q, p), v.modpow(&q, p), v.modpow(&((&q + &one) >> 1), p));
    while t != one {
        let mut i = 0;
        let mut t2 = t.clone();
        while t2 != one {
            t2 = &t2 * &t2 % p;
            i += 1;
        }
        let b = c.modpow(&(one.clone() << (m - i - 1)), p);
        m = i;
        c = &b * &b % p;
        t = t * &c % p;
        r = r * b % p;
    }
    Some(r)
}

/// BouncyCastle 1.86's RSA `KeyFactorySpi` for the key SunRsaSign refused: an RSA algorithm OID, octet-aligned key
/// bits holding a SEQUENCE of two minimally encoded INTEGERs, then `RSAKeyParameters` (an odd exponent; an odd
/// modulus of at most 16384 bits without a prime factor up to 743, and composite).
fn bouncy_castle_accepts(algid: &AlgorithmId, bits: &BitArray, n: &BigUint, e: &BigUint) -> bool {
    const RSA_OIDS: [&str; 4] = ["1.2.840.113549.1.1.1", "2.5.8.1.1", "1.2.840.113549.1.1.7", "1.2.840.113549.1.1.10"];
    if !RSA_OIDS.contains(&algid.oid.to_string().as_str()) || !bits.length.is_multiple_of(8) {
        return false;
    }
    let well_formed = || -> JResult<bool> {
        let parts = DerValue::from(&bits.bytes)?.subs(TAG_SEQUENCE)?;
        // `ASN1Integer.isMalformed`
        Ok(parts.len() == 2 && parts.iter().all(|p| p.tag == TAG_INTEGER && match p.bytes() {
            [] => false,
            [_] => true,
            [a, b, ..] => *a != ((*b as i8) >> 7) as u8,
        }))
    };
    if !well_formed().unwrap_or(false) || !e.bit(0) || !n.bit(0) || n.bits() > 16384 {
        return false;
    }
    let small_factor = (3u32..=743).filter(|p| (3..*p).take_while(|d| d * d <= *p).all(|d| p % d != 0)).any(|p| n % p == BigUint::ZERO);
    !small_factor && n > &BigUint::from(3u8) && !probably_prime(n)
}

/// Miller-Rabin over the first prime bases, enough to tell BouncyCastle's "RSA modulus is not composite".
fn probably_prime(n: &BigUint) -> bool {
    let one = BigUint::from(1u8);
    let minus_one = n - &one;
    let s = minus_one.trailing_zeros().unwrap_or(0);
    let d = &minus_one >> s;
    [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71].iter().all(|&a| {
        let a = BigUint::from(a);
        if &a >= n {
            return true;
        }
        let mut x = a.modpow(&d, n);
        if x == one || x == minus_one {
            return true;
        }
        for _ in 1..s {
            x = x.modpow(&BigUint::from(2u8), n);
            if x == minus_one {
                return true;
            }
        }
        false
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Names

/// `X500Name(DerInputStream)`: whether every RDN is empty (`isEmpty`).
fn x500_name(input: &mut DerInputStream) -> JResult<bool> {
    let der_bytes = input.byte_array();
    let names = match input.get_sequence() {
        Ok(names) => names,
        Err(e) if e.is_io() => {
            let wrapped = DerValue::of(TAG_SEQUENCE, der_bytes).byte_array();
            DerInputStream::of(wrapped).get_sequence()?
        }
        Err(e) => return Err(e),
    };
    let mut empty = true;
    for name in names {
        if rdn(name)? != 0 {
            empty = false;
        }
    }
    Ok(empty)
}

/// `RDN(DerValue)`: the number of AVAs.
fn rdn(mut value: DerValue) -> JResult<usize> {
    if value.tag != TAG_SET {
        return io("X500 RDN");
    }
    let avas = DerInputStream::of(value.byte_array()).get_set()?;
    let count = avas.len();
    for mut ava in avas {
        // `AVA(DerValue)`
        if ava.tag != TAG_SEQUENCE {
            return io("AVA not a sequence");
        }
        ava.data.get_oid()?;
        let mut v = ava.data.get_der_value()?;
        if ava.data.available() != 0 {
            return io(format!("AVA, extra bytes = {}", ava.data.available()));
        }
        if v.tag == TAG_BMP_STRING {
            v.validate_bmp_string()?;
        }
    }
    Ok(count)
}

/// `GeneralNames(DerValue)`: the number of names.
fn general_names(val: &mut DerValue) -> JResult<usize> {
    if val.tag != TAG_SEQUENCE {
        return io("Invalid encoding for GeneralNames.");
    }
    if val.data.available() == 0 {
        return io("No data available in passed DER encoded value.");
    }
    let mut count = 0;
    while val.data.available() != 0 {
        let name = val.data.get_der_value()?;
        general_name(name, false)?;
        count += 1;
    }
    Ok(count)
}

/// `GeneralName(DerValue, nameConstraint)`
fn general_name(mut name: DerValue, constraint: bool) -> JResult<()> {
    let tag = name.tag & 0x1f;
    let (context, constructed) = (name.is_context_specific(), name.is_constructed());
    match tag {
        0 => {
            if !(context && constructed) {
                return io("Invalid encoding of Other-Name");
            }
            name.retag(TAG_SEQUENCE);
            // `OtherName(DerValue)`
            let input = name.der_input_stream()?;
            input.get_oid()?;
            let value = input.get_der_value()?;
            if !(value.is_context(0) && value.is_constructed()) {
                return io("value is not EXPLICTly tagged [0]");
            }
        }
        1 => {
            if !context || constructed {
                return io("Invalid encoding of RFC822 name");
            }
            name.retag(TAG_IA5_STRING);
            let text = name.string(TAG_IA5_STRING)?;
            // `RFC822Name.parseName`
            if text.is_empty() {
                return io("RFC822Name may not be null or empty");
            }
            let domain = &text[text.find('@').map_or(0, |i| i + 1)..];
            if domain.is_empty() {
                return io("RFC822Name may not end with @");
            }
            if domain == "." {
                return io("RFC822Name domain may not be just .");
            }
        }
        2 => {
            if !context || constructed {
                return io("Invalid encoding of DNSName");
            }
            name.retag(TAG_IA5_STRING);
            name.string(TAG_IA5_STRING)?;
        }
        3 => {
            if !(context && constructed) {
                return io("Invalid encoding of X400Address name");
            }
        }
        6 => {
            if !context || constructed {
                return io("Invalid encoding of URI");
            }
            name.retag(TAG_IA5_STRING);
            let text = name.string(TAG_IA5_STRING)?;
            if constraint {
                uri_name_constraint(&text)?;
            } else {
                uri_name(&text)?;
            }
        }
        7 => {
            if !context || constructed {
                return io("Invalid encoding of IP address");
            }
            name.retag(TAG_OCTET_STRING);
            let address = name.get_octet_string()?;
            if ![4, 8, 16, 32].contains(&address.len()) {
                return io("Invalid IPAddressName");
            }
        }
        8 => {
            if !context || constructed {
                return io("Invalid encoding of OID name");
            }
            name.retag(TAG_OBJECT_ID);
            name.get_oid()?;
        }
        4 => {
            if !(context && constructed) {
                return io("Invalid encoding of Directory name");
            }
            x500_name(&mut name.data)?;
        }
        5 => {
            if !(context && constructed) {
                return io("Invalid encoding of EDI name");
            }
            name.retag(TAG_SEQUENCE);
            edi_party_name(&mut name)?;
        }
        other => return io(format!("Unrecognized GeneralName tag, ({other})")),
    }
    Ok(())
}

/// `EDIPartyName(DerValue)`
fn edi_party_name(name: &mut DerValue) -> JResult<()> {
    let seq = DerInputStream::of(name.byte_array()).get_sequence()?;
    if seq.is_empty() || seq.len() > 2 {
        return io("Invalid encoding of EDIPartyName");
    }
    let (mut assigner, mut party) = (false, false);
    for mut opt in seq {
        if opt.is_context(0) && !opt.is_constructed() {
            if assigner {
                return io("Duplicate nameAssigner found in EDIPartyName");
            }
            opt = opt.data.get_der_value()?;
            assigner = true;
        }
        if opt.is_context(1) && !opt.is_constructed() {
            if party {
                return io("Duplicate partyName found in EDIPartyName");
            }
            opt = opt.data.get_der_value()?;
            // `getAsString`: null for a tag that is not a string
            party = matches!(opt.tag, TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_T61_STRING | TAG_IA5_STRING | TAG_UNIVERSAL_STRING | TAG_BMP_STRING | TAG_GENERAL_STRING);
        }
    }
    if !party {
        return io("party cannot be missing");
    }
    Ok(())
}

/// `URIName(String)`: a URI with a scheme, whose host (if any) is a DNS name or an IP address; a host that is neither
/// a DNS name nor an IP literal is resolved, as `IPAddressName(String)` does through `InetAddress.getByName`.
fn uri_name(name: &str) -> JResult<()> {
    let uri = match crate::java_uri::parse(name) {
        Ok(uri) => uri,
        Err(e) => return Err(Throwable::caused(IO, format!("invalid URI name:{name}"), Throwable::new("java.net.URISyntaxException", e))),
    };
    if uri.scheme.is_none() {
        return io(format!("URI name must include scheme:{name}"));
    }
    if let Some(host) = uri.host.as_deref().filter(|h| !h.is_empty()) {
        if let Some(v6) = host.strip_prefix('[') {
            if v6.trim_end_matches(']').parse::<std::net::Ipv6Addr>().is_err() {
                return io(format!("invalid URI name (host portion is not a valid IPv6 address):{name}"));
            }
        } else if dns_name(host).is_err() && !ip_address_name(host) {
            return io(format!("invalid URI name (host portion is not a valid DNSName, IPv4 address, or IPv6 address):{name}"));
        }
    }
    Ok(())
}

/// `new IPAddressName(String)` of a URI's host that is not a DNS name (so not bracketed and without a `/`): whether
/// it reads. A name with a dot is looked up by `InetAddress.getByName`; one without is refused.
fn ip_address_name(host: &str) -> bool {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.contains(':') || !host.contains('.') {
        return false;
    }
    std::net::ToSocketAddrs::to_socket_addrs(&(host, 0)).is_ok_and(|mut a| a.next().is_some())
}

/// `URIName.nameConstraint(DerValue)`: a URI without a scheme whose scheme-specific part (after a leading `.`) is a
/// DNS name.
fn uri_name_constraint(name: &str) -> JResult<()> {
    let uri = match crate::java_uri::parse(name) {
        Ok(uri) => uri,
        Err(e) => {
            return Err(Throwable::caused(IO, format!("invalid URI name constraint:{name}"), Throwable::new("java.net.URISyntaxException", e)));
        }
    };
    if uri.scheme.is_some() {
        return io(format!("invalid URI name constraint (should not include scheme):{name}"));
    }
    // `getSchemeSpecificPart`: everything before the fragment, decoded
    let raw = name.split('#').next().unwrap_or_default();
    let host = java_uri_decode(raw);
    dns_name(host.strip_prefix('.').unwrap_or(&host))
        .map_err(|m| Throwable::caused(IO, format!("invalid URI name constraint:{name}"), Throwable::new(IO, m)))
}

/// `URI.decode`: `%XX` escapes as UTF-8 bytes (malformed sequences replaced).
fn java_uri_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
    while i < b.len() {
        let hex = |c: u8| char::from(c).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `DNSName(String, allowWildcard = false)`: `Err` with the `IOException`'s message.
fn dns_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("DNSName must not be null or empty");
    }
    if name.contains(' ') {
        return Err("DNSName with blank components is not permitted");
    }
    if name.starts_with('.') || name.ends_with('.') {
        return Err("DNSName may not begin or end with a .");
    }
    for label in name.split('.') {
        let mut chars = label.chars();
        match chars.next() {
            None => return Err("DNSName with empty components are not permitted"),
            Some(c) if !c.is_ascii_alphanumeric() => return Err("DNSName components must begin with a letter or digit"),
            Some(_) => {}
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("DNSName components must consist of letters, digits, and hyphens");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Extensions

/// `CertificateExtensions(DerInputStream)`: whether there is a parsed SubjectAlternativeName extension, and its
/// criticality and number of names, for `verifyCert`.
#[derive(Default)]
struct Extensions {
    subject_alt_name: Option<(bool, usize)>,
}

fn certificate_extensions(input: &mut DerInputStream) -> JResult<Extensions> {
    let mut parsed = Extensions::default();
    let mut seen: Vec<String> = Vec::new();
    for ext in input.get_sequence()? {
        let (id, critical, value) = extension_fields(ext)?;
        // `parseExtension`
        match extension(&id, critical, &value) {
            Ok(names) => {
                if seen.contains(&id) {
                    return io("Duplicate extensions not allowed");
                }
                seen.push(id.clone());
                if id == SUBJECT_ALT_NAME {
                    parsed.subject_alt_name = Some((critical, names));
                }
            }
            Err(e) if !critical => {
                // an unparseable non-critical extension is kept aside
                let _ = e;
            }
            Err(e) if e.is_io() => return Err(e),
            Err(e) => return Err(Throwable::wrapping(IO, e)),
        }
    }
    Ok(parsed)
}

/// `Extension(DerValue)`: the OID, criticality and value.
fn extension_fields(mut ext: DerValue) -> JResult<(String, bool, Vec<u8>)> {
    let ext_in = ext.der_input_stream()?;
    let oid = ext_in.get_oid()?;
    let mut val = ext_in.get_der_value()?;
    let mut critical = false;
    if val.tag == TAG_BOOLEAN {
        critical = val.get_boolean()?;
        val = ext_in.get_der_value()?;
    }
    Ok((oid.to_string(), critical, val.get_octet_string()?))
}

const SUBJECT_ALT_NAME: &str = "2.5.29.17";

/// The extension class `OIDMap` names for `oid` (any extension without one is kept as it is): `Ok` with the number
/// of names for the alternative-name extensions, else what its constructor throws (`cert_string` prints that of a
/// non-critical one as `UnparseableExtension.toString`).
pub(super) fn extension(oid: &str, critical: bool, value: &[u8]) -> JResult<usize> {
    let der = || DerValue::from(value);
    match oid {
        // SubjectKeyIdentifier: `KeyIdentifier(DerValue)`
        "2.5.29.14" => {
            der()?.get_octet_string()?;
        }
        // KeyUsage
        "2.5.29.15" => {
            let Some(&first) = value.first() else { return Err(index_out_of_bounds(0, 0)) };
            let inner = if first == TAG_OCTET_STRING { der()?.get_octet_string()? } else { value.to_vec() };
            DerValue::from(&inner)?.get_unaligned_bit_string(false)?;
        }
        // SubjectAlternativeName, IssuerAlternativeName
        "2.5.29.17" | "2.5.29.18" => {
            let mut val = der()?;
            return general_names(&mut val);
        }
        // BasicConstraints
        "2.5.29.19" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding of BasicConstraints");
            }
            if val.data.available() == 0 {
                return Ok(0);
            }
            let mut opt = val.data.get_der_value()?;
            if opt.tag != TAG_BOOLEAN {
                return Ok(0);
            }
            opt.get_boolean()?;
            if val.data.available() == 0 {
                return Ok(0);
            }
            let mut opt = val.data.get_der_value()?;
            if opt.tag != TAG_INTEGER {
                return io("Invalid encoding of BasicConstraints");
            }
            opt.get_integer()?;
        }
        // AuthorityKeyIdentifier
        "2.5.29.35" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for AuthorityKeyIdentifierExtension.");
            }
            let (mut id, mut names, mut serial) = (false, false, false);
            while val.data.available() != 0 {
                let mut opt = val.data.get_der_value()?;
                if opt.is_context(0) && !opt.is_constructed() {
                    if id {
                        return io("Duplicate KeyIdentifier in AuthorityKeyIdentifier.");
                    }
                    opt.retag(TAG_OCTET_STRING);
                    opt.get_octet_string()?;
                    id = true;
                } else if opt.is_context(1) && opt.is_constructed() {
                    if names {
                        return io("Duplicate GeneralNames in AuthorityKeyIdentifier.");
                    }
                    opt.retag(TAG_SEQUENCE);
                    general_names(&mut opt)?;
                    names = true;
                } else if opt.is_context(2) && !opt.is_constructed() {
                    if serial {
                        return io("Duplicate SerialNumber in AuthorityKeyIdentifier.");
                    }
                    opt.retag(TAG_INTEGER);
                    opt.get_big_integer()?;
                    serial = true;
                } else {
                    return io("Invalid encoding of AuthorityKeyIdentifierExtension.");
                }
            }
        }
        // ExtendedKeyUsage
        "2.5.29.37" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for ExtendedKeyUsageExtension.");
            }
            while val.data.available() != 0 {
                val.data.get_der_value()?.get_oid()?;
            }
        }
        // CertificatePolicies
        "2.5.29.32" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for CertificatePoliciesExtension.");
            }
            while val.data.available() != 0 {
                policy_information(val.data.get_der_value()?)?;
            }
        }
        // CRLDistributionPoints, FreshestCRL
        "2.5.29.31" | "2.5.29.46" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                let name = if oid == "2.5.29.31" { "CRLDistributionPoints" } else { "FreshestCRL" };
                return io(format!("Invalid encoding for {name} extension."));
            }
            while val.data.available() != 0 {
                distribution_point(val.data.get_der_value()?)?;
            }
        }
        // AuthorityInfoAccess, SubjectInfoAccess
        "1.3.6.1.5.5.7.1.1" | "1.3.6.1.5.5.7.1.11" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                let name = if oid == "1.3.6.1.5.5.7.1.1" { "AuthorityInfoAccessExtension" } else { "SubjectInfoAccessExtension" };
                return io(format!("Invalid encoding for {name}."));
            }
            while val.data.available() != 0 {
                // `AccessDescription(DerValue)`
                let mut description = val.data.get_der_value()?;
                description.data.get_oid()?;
                let location = description.data.get_der_value()?;
                general_name(location, false)?;
            }
        }
        // PrivateKeyUsage
        "2.5.29.16" => {
            let (mut before, mut after) = (false, false);
            for mut opt in DerInputStream::of(value.to_vec()).get_sequence()? {
                let (seen, which) = match () {
                    _ if opt.is_context(0) && !opt.is_constructed() => (&mut before, "notBefore"),
                    _ if opt.is_context(1) && !opt.is_constructed() => (&mut after, "notAfter"),
                    _ => return io("Invalid encoding of PrivateKeyUsageExtension"),
                };
                if *seen {
                    return Err(Throwable::new(CERTIFICATE_PARSING, format!("Duplicate {which} in PrivateKeyUsage.")));
                }
                opt.retag(TAG_GENERALIZED_TIME);
                DerInputStream::of(opt.byte_array()).get_generalized_time()?;
                *seen = true;
            }
        }
        // CRLNumber, DeltaCRLIndicator
        "2.5.29.20" | "2.5.29.27" => {
            der()?.get_big_integer()?;
        }
        // CRLReasonCode
        "2.5.29.21" => {
            der()?.get_enumerated()?;
        }
        // NameConstraints
        "2.5.29.30" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for NameConstraintsExtension.");
            }
            let (mut permitted, mut excluded) = (false, false);
            while val.data.available() != 0 {
                let mut opt = val.data.get_der_value()?;
                let (seen, which) = match () {
                    _ if opt.is_context(0) && opt.is_constructed() => (&mut permitted, "permitted"),
                    _ if opt.is_context(1) && opt.is_constructed() => (&mut excluded, "excluded"),
                    _ => return io("Invalid encoding of NameConstraintsExtension."),
                };
                if *seen {
                    return io(format!("Duplicate {which} GeneralSubtrees in NameConstraintsExtension."));
                }
                opt.retag(TAG_SEQUENCE);
                general_subtrees(&mut opt)?;
                *seen = true;
            }
        }
        // PolicyMappings
        "2.5.29.33" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for PolicyMappingsExtension.");
            }
            while val.data.available() != 0 {
                // `CertificatePolicyMap(DerValue)`
                let mut map = val.data.get_der_value()?;
                if map.tag != TAG_SEQUENCE {
                    return io("Invalid encoding for CertificatePolicyMap");
                }
                map.data.get_der_value()?.get_oid()?;
                map.data.get_der_value()?.get_oid()?;
            }
        }
        // PolicyConstraints
        "2.5.29.36" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Sequence tag missing for PolicyConstraint.");
            }
            let (mut require, mut inhibit) = (false, false);
            while val.data.available() != 0 {
                let mut next = val.data.get_der_value()?;
                let (seen, which) = match () {
                    _ if next.is_context(0) && !next.is_constructed() => (&mut require, "requireExplicitPolicy"),
                    _ if next.is_context(1) && !next.is_constructed() => (&mut inhibit, "inhibitPolicyMapping"),
                    _ => return io("Invalid encoding of PolicyConstraint"),
                };
                if *seen {
                    return io(format!("Duplicate {which} found in the PolicyConstraintsExtension"));
                }
                next.retag(TAG_INTEGER);
                next.get_integer()?;
                *seen = true;
            }
        }
        // NetscapeCertType
        "2.16.840.1.113730.1.1" => {
            der()?.get_unaligned_bit_string(false)?;
        }
        // InhibitAnyPolicy
        "2.5.29.54" => {
            if !critical {
                return io("Criticality cannot be false for InhibitAnyPolicy");
            }
            let mut val = der()?;
            if val.tag != TAG_INTEGER {
                return io("Invalid encoding of InhibitAnyPolicy: data not integer");
            }
            if val.get_integer()? < -1 {
                return io("Invalid value for skipCerts");
            }
        }
        // CertificateIssuer
        "2.5.29.29" => {
            general_names(&mut der()?)?;
        }
        // IssuingDistributionPoint
        "2.5.29.28" => {
            let mut val = der()?;
            if val.tag != TAG_SEQUENCE {
                return io("Invalid encoding for IssuingDistributionPointExtension.");
            }
            while val.data.available() != 0 {
                let mut opt = val.data.get_der_value()?;
                if opt.is_context(0) && opt.is_constructed() {
                    distribution_point_name(opt.data.get_der_value()?)?;
                } else if opt.is_context(3) && !opt.is_constructed() {
                    // `ReasonFlags(DerValue)`
                    opt.get_unaligned_bit_string(true)?;
                } else if [1, 2, 4, 5].iter().any(|&n| opt.is_context(n)) && !opt.is_constructed() {
                    opt.retag(TAG_BOOLEAN);
                    opt.get_boolean()?;
                } else {
                    return io("Invalid encoding of IssuingDistributionPoint");
                }
            }
        }
        // OCSPNoCheck: the value is not read
        _ => {}
    }
    Ok(0)
}

/// `GeneralSubtrees(DerValue)`
fn general_subtrees(val: &mut DerValue) -> JResult<()> {
    if val.tag != TAG_SEQUENCE {
        return io("Invalid encoding of GeneralSubtrees.");
    }
    while val.data.available() != 0 {
        // `GeneralSubtree(DerValue)`
        let mut tree = val.data.get_der_value()?;
        if tree.tag != TAG_SEQUENCE {
            return io("Invalid encoding for GeneralSubtree.");
        }
        general_name(tree.data.get_der_value()?, true)?;
        while tree.data.available() != 0 {
            let mut opt = tree.data.get_der_value()?;
            if (opt.is_context(0) || opt.is_context(1)) && !opt.is_constructed() {
                opt.retag(TAG_INTEGER);
                opt.get_integer()?;
            } else {
                return io("Invalid encoding of GeneralSubtree.");
            }
        }
    }
    Ok(())
}

/// `DistributionPointName(DerValue)`
fn distribution_point_name(mut point: DerValue) -> JResult<()> {
    if point.is_context(0) && point.is_constructed() {
        point.retag(TAG_SEQUENCE);
        general_names(&mut point)?;
    } else if point.is_context(1) && point.is_constructed() {
        point.retag(TAG_SET);
        rdn(point)?;
    } else {
        return io("Invalid encoding for DistributionPointName");
    }
    Ok(())
}

/// `PolicyInformation(DerValue)`
fn policy_information(mut val: DerValue) -> JResult<()> {
    if val.tag != TAG_SEQUENCE {
        return io("Invalid encoding of PolicyInformation");
    }
    val.data.get_der_value()?.get_oid()?;
    if val.data.available() != 0 {
        let mut opt = val.data.get_der_value()?;
        if opt.tag != TAG_SEQUENCE {
            return io("Invalid encoding of PolicyInformation");
        }
        if opt.data.available() == 0 {
            return io("No data available in policyQualifiers");
        }
        while opt.data.available() != 0 {
            // `PolicyQualifierInfo(byte[])`
            let encoded = opt.data.get_der_value()?.byte_array();
            let mut qualifier = DerValue::from(&encoded)?;
            if qualifier.tag != TAG_SEQUENCE {
                return io("Invalid encoding for PolicyQualifierInfo");
            }
            qualifier.data.get_der_value()?.get_oid()?;
        }
    }
    Ok(())
}

/// `DistributionPoint(DerValue)`
fn distribution_point(mut val: DerValue) -> JResult<()> {
    if val.tag != TAG_SEQUENCE {
        return io("Invalid encoding of DistributionPoint.");
    }
    let (mut name, mut reasons, mut issuer) = (false, false, false);
    while val.data.available() != 0 {
        let mut opt = val.data.get_der_value()?;
        if opt.is_context(0) && opt.is_constructed() {
            if name {
                return io("Duplicate DistributionPointName in DistributionPoint.");
            }
            let mut point = opt.data.get_der_value()?;
            if point.is_context(0) && point.is_constructed() {
                point.retag(TAG_SEQUENCE);
                general_names(&mut point)?;
            } else if point.is_context(1) && point.is_constructed() {
                point.retag(TAG_SET);
                rdn(point)?;
            } else {
                return io("Invalid DistributionPointName in DistributionPoint");
            }
            name = true;
        } else if opt.is_context(1) && !opt.is_constructed() {
            if reasons {
                return io("Duplicate Reasons in DistributionPoint.");
            }
            opt.retag(TAG_BIT_STRING);
            opt.get_unaligned_bit_string(false)?;
            reasons = true;
        } else if opt.is_context(2) && opt.is_constructed() {
            if issuer {
                return io("Duplicate CRLIssuer in DistributionPoint.");
            }
            opt.retag(TAG_SEQUENCE);
            general_names(&mut opt)?;
            issuer = true;
        } else {
            return io("Invalid encoding of DistributionPoint.");
        }
    }
    if !issuer && !name {
        return io("One of fullName, relativeName,  and crlIssuer has to be set");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Certificates

/// What a parsed certificate gives its readers.
#[derive(Clone, Debug)]
pub struct Certificate {
    pub public_key: PublicKey,
    /// The subject key's bits (an EC key's point, an RSA key's PKCS#1 sequence, another algorithm's key).
    pub key_bits: Vec<u8>,
    /// The block the certificate was read from (BER as given, indefinite lengths included).
    pub encoded: Vec<u8>,
    /// `getEncoded()`: the certificate with its indefinite lengths made definite (`DerIndefLenConverter`).
    pub der: Vec<u8>,
}

/// `X509CertImpl(byte[])`
fn x509_cert_impl(data: &[u8]) -> JResult<Certificate> {
    let result = DerValue::from(data).and_then(|mut val| {
        let der = val.byte_array();
        cert_parse(&mut val).map(|(public_key, key_bits)| (public_key, key_bits, der))
    });
    let (public_key, key_bits, der) = result.map_err(|e| if e.is_io() { Throwable::caused(CERTIFICATE, format!("Unable to initialize, {}", e.line()), e) } else { e })?;
    Ok(Certificate { public_key, key_bits, encoded: data.to_vec(), der })
}

/// `RSAPublicKeyImpl.parseKeyBits` up to its tag check: `new DerValue(keyBits)` (no data after the value), then
/// `Not a SEQUENCE`. The IOException it throws, `None` for a SEQUENCE (whose integers are not read).
pub fn pkcs1_sequence_failure(bits: &[u8]) -> Option<Throwable> {
    match DerValue::from(bits) {
        Err(e) => Some(e),
        Ok(value) if value.tag != TAG_SEQUENCE => Some(Throwable::new(IO, "Not a SEQUENCE")),
        Ok(_) => None,
    }
}

/// `X509CertImpl.parse`: the subject's public key.
fn cert_parse(val: &mut DerValue) -> JResult<(PublicKey, Vec<u8>)> {
    if val.tag != TAG_SEQUENCE {
        return Err(Throwable::new(CERTIFICATE_PARSING, "invalid DER-encoded certificate data"));
    }
    let mut tbs = val.data.get_der_value()?;
    let mut algid_value = val.data.get_der_value()?;
    let mut signature = val.data.get_der_value()?;
    if val.data.available() != 0 {
        return Err(Throwable::new(CERTIFICATE_PARSING, format!("signed overrun, bytes = {}", val.data.available())));
    }
    if tbs.tag != TAG_SEQUENCE {
        return Err(Throwable::new(CERTIFICATE_PARSING, "signed fields invalid"));
    }
    let algid = AlgorithmId::parse(&mut algid_value)?;
    signature.get_bit_string()?;
    // `new X509CertInfo(seq[0])`: an `IOException` becomes a `CertificateParsingException`
    let (info_algid, key) = cert_info(&mut tbs).map_err(|e| if e.is_io() { Throwable::wrapping(CERTIFICATE_PARSING, e) } else { e })?;
    if algid != info_algid {
        return Err(Throwable::new(CERTIFICATE, "Signature algorithm mismatch"));
    }
    Ok(key)
}

/// `X509CertInfo.parse`: the signature algorithm and the subject's key.
fn cert_info(val: &mut DerValue) -> JResult<(AlgorithmId, (PublicKey, Vec<u8>))> {
    if val.tag != TAG_SEQUENCE {
        return Err(Throwable::new(CERTIFICATE_PARSING, "signed fields invalid"));
    }
    let input = &mut val.data;
    let parsing = |m: &str| Err(Throwable::new(CERTIFICATE_PARSING, m));
    // `CertificateVersion`: V1 (0) unless a constructed [0] holds an INTEGER
    let mut version = 0;
    let mut tmp = input.get_der_value()?;
    if tmp.is_context(0) {
        if tmp.is_constructed() {
            let mut inner = tmp.data.get_der_value()?;
            version = inner.get_integer()?;
        }
        tmp = input.get_der_value()?;
    }
    // `SerialNumber`
    tmp.get_big_integer()?;
    let mut algid_value = input.get_der_value()?;
    let algid = AlgorithmId::parse(&mut algid_value)?;
    if x500_name(input)? {
        return parsing("Empty issuer DN not allowed in X509Certificates");
    }
    // `CertificateValidity(DerInputStream)`
    let mut validity = input.get_der_value()?;
    if validity.tag != TAG_SEQUENCE {
        return io("Invalid encoded CertificateValidity, starting sequence tag missing.");
    }
    if validity.data.available() == 0 {
        return io("No data encoded for CertificateValidity");
    }
    let seq = DerInputStream::of(validity.byte_array()).get_sequence()?;
    if seq.len() != 2 {
        return io("Invalid encoding for CertificateValidity");
    }
    for time in &seq {
        match time.tag {
            TAG_UTC_TIME => validity.data.get_utc_time()?,
            TAG_GENERALIZED_TIME => validity.data.get_generalized_time()?,
            _ => return io("Invalid encoding for CertificateValidity"),
        }
    }
    let subject_empty = x500_name(input)?;
    if version == 0 && subject_empty {
        return parsing("Empty subject DN not allowed in v1 certificate");
    }
    let mut key_value = input.get_der_value()?;
    let key = parse_x509_key(&mut key_value)?;
    if input.available() == 0 {
        return Ok((algid, key));
    }
    if version == 0 {
        return parsing("no more data allowed for version 1 certificate");
    }
    let mut tmp = input.get_der_value()?;
    for n in [1, 2] {
        if tmp.is_context(n) {
            // `UniqueIdentity`
            tmp.get_unaligned_bit_string(true)?;
            if input.available() == 0 {
                return Ok((algid, key));
            }
            tmp = input.get_der_value()?;
        }
    }
    if version != 2 {
        return parsing("Extensions not allowed in v2 certificate");
    }
    let extensions = if tmp.is_constructed() && tmp.is_context(3) { Some(certificate_extensions(&mut tmp.data)?) } else { None };
    // `verifyCert`
    if subject_empty {
        let incomplete = |m: &str| parsing(&format!("X.509 Certificate is incomplete: {m}"));
        let Some(extensions) = extensions else { return incomplete("subject field is empty, and certificate has no extensions") };
        let Some((critical, names)) = extensions.subject_alt_name else { return incomplete("subject field is empty, and SubjectAlternativeName extension is absent") };
        if names == 0 {
            return incomplete("subject field is empty, and SubjectAlternativeName extension is empty");
        }
        if !critical {
            return incomplete("SubjectAlternativeName extension MUST be marked critical when subject field is empty");
        }
    }
    Ok((algid, key))
}

// ---------------------------------------------------------------------------------------------------------------
// PKCS#7

/// `new PKCS7(data)`: the certificates of a PKCS#7 bundle, `None` when it is not one (a `ParsingException`, after
/// which `X509Factory` reads the data as certificates); `Err` is a runtime exception, which escapes.
fn pkcs7(data: &[u8]) -> JResult<Option<Vec<Certificate>>> {
    let attempt = |old: bool| -> JResult<Vec<Certificate>> {
        let mut input = DerInputStream::of(data.to_vec());
        // `ContentInfo(DerInputStream, oldStyle)`
        let type_and_content = input.get_sequence()?;
        if type_and_content.is_empty() || type_and_content.len() > 2 {
            return Err(Throwable::new(PARSING, "Invalid length for ContentInfo"));
        }
        let content_type = DerInputStream::of(type_and_content[0].clone().byte_array()).get_oid()?.to_string();
        let mut content = None;
        if let Some(tagged) = type_and_content.get(1) {
            if old {
                content = Some(tagged.clone());
            } else {
                let contents = DerInputStream::of(tagged.clone().byte_array()).get_implicit_set()?;
                if contents.len() != 1 {
                    return Err(Throwable::new(PARSING, "ContentInfo encoding error"));
                }
                content = contents.into_iter().next();
            }
        }
        let Some(mut content) = content else { return Err(Throwable::new(PARSING, "content is null")) };
        match content_type.as_str() {
            "1.2.840.113549.1.7.2" => signed_data(&mut content, false),
            "1.2.840.1113549.1.7.2" => signed_data(&mut content, true),
            "2.16.840.1.113730.2.5" => {
                // `parseNetscapeCertChain`
                let mut certificates = Vec::new();
                for mut value in DerInputStream::of(content.byte_array()).get_sequence()? {
                    certificates.push(embedded_certificate(&mut value)?);
                }
                Ok(certificates)
            }
            other => Err(Throwable::new(PARSING, format!("content type {other} not supported."))),
        }
    };
    // `parse(derin)`: the new style, then the old one; only an `IOException` is caught
    let runtime = |e: &Throwable| !e.is_io();
    match attempt(false) {
        Ok(certificates) => Ok(Some(certificates)),
        Err(e) if runtime(&e) => Err(e),
        Err(_) => match attempt(true) {
            Ok(certificates) => Ok(Some(certificates)),
            Err(e) if runtime(&e) => Err(e),
            Err(_) => Ok(None),
        },
    }
}

/// A certificate inside a PKCS#7 bundle: `generateCertificate` of its encoding.
fn embedded_certificate(value: &mut DerValue) -> JResult<Certificate> {
    let encoded = value.byte_array();
    generate_certificate(&encoded).map_err(|e| Throwable::caused(PARSING, e.message(), e))
}

/// `parseSignedData` / `parseOldSignedData`
fn signed_data(val: &mut DerValue, old: bool) -> JResult<Vec<Certificate>> {
    let dis = val.der_input_stream()?;
    dis.get_big_integer()?;
    for mut algid in dis.get_set()? {
        AlgorithmId::parse(&mut algid).map_err(|e| Throwable::caused(PARSING, format!("Error parsing digest AlgorithmId IDs: {}", e.message()), e))?;
    }
    // `ContentInfo(DerInputStream)`: the new style
    let type_and_content = dis.get_sequence()?;
    if type_and_content.is_empty() || type_and_content.len() > 2 {
        return Err(Throwable::new(PARSING, "Invalid length for ContentInfo"));
    }
    let content_info_type = &type_and_content[0];
    DerInputStream::of(content_info_type.clone().byte_array()).get_oid()?;
    if let Some(tagged) = type_and_content.get(1).filter(|_| !old) {
        let contents = DerInputStream::of(tagged.clone().byte_array()).get_implicit_set()?;
        if contents.len() != 1 {
            return Err(Throwable::new(PARSING, "ContentInfo encoding error"));
        }
    }
    let mut certificates = Vec::new();
    if old {
        for mut value in dis.get_set()? {
            certificates.push(embedded_certificate(&mut value)?);
        }
        dis.get_set()?;
    } else {
        // `getOptionalImplicitContextSpecific(0, SET OF)`
        if dis.available() > 0 && dis.data[dis.pos] & 0xc0 == 0x80 && dis.data[dis.pos] & 0x1f == 0 {
            let value = dis.get_der_value()?;
            for mut cert in DerValue::with(TAG_SET, value.buffer.clone(), value.start, value.end, value.allow_ber()).subs(TAG_SET)? {
                if cert.tag == TAG_SEQUENCE {
                    certificates.push(embedded_certificate(&mut cert)?);
                }
            }
        }
        if dis.available() > 0 && dis.data[dis.pos] & 0xc0 == 0x80 && dis.data[dis.pos] & 0x1f == 1 {
            // `certfac.generateCRL` of each: a `CRLException` becomes a `ParsingException`
            let value = dis.get_der_value()?;
            for mut crl in DerValue::with(TAG_SET, value.buffer.clone(), value.start, value.end, value.allow_ber()).subs(TAG_SET)? {
                generate_crl(&crl.byte_array()).map_err(|e| if e.class == CRL { Throwable::caused(PARSING, e.message(), e) } else { e })?;
            }
        }
    }
    for mut info in dis.get_set()? {
        signer_info(info.der_input_stream()?, old)?;
    }
    Ok(certificates)
}

/// `SignerInfo(DerInputStream, oldStyle)`, its attributes and the CMSAlgorithmProtection check.
fn signer_info(derin: &mut DerInputStream, old: bool) -> JResult<()> {
    derin.get_big_integer()?;
    let mut issuer_and_serial = derin.get_sequence()?;
    if issuer_and_serial.len() != 2 {
        return Err(Throwable::new(PARSING, "Invalid length for IssuerAndSerialNumber"));
    }
    let issuer = issuer_and_serial[0].byte_array();
    x500_name(&mut DerValue::of(TAG_SEQUENCE, issuer).der_input_stream()?.clone())?;
    issuer_and_serial[1].get_big_integer()?;
    let digest = AlgorithmId::parse(&mut derin.get_der_value()?)?;
    let mut authenticated = None;
    if old {
        derin.get_set()?;
    } else if derin.peek_byte()? == 0xa0 {
        authenticated = Some(pkcs9_attributes(derin)?);
    }
    let encryption = AlgorithmId::parse(&mut derin.get_der_value()?)?;
    derin.get_octet_string()?;
    if old {
        derin.get_set()?;
    } else if derin.available() != 0 && derin.peek_byte()? == 0xa1 {
        pkcs9_attributes(derin)?;
    }
    if derin.available() != 0 {
        return Err(Throwable::new(PARSING, "extra data at the end"));
    }
    // `checkCMSAlgorithmProtection`
    let Some(Some(protection)) = authenticated else { return Ok(()) };
    let mut data = DerValue::from(&protection)?.fresh();
    let d = AlgorithmId::parse(&mut data.get_der_value()?)?;
    let mut ds = data.get_der_value()?;
    if data.available() > 0 {
        return io("Unknown field in CMSAlgorithmProtection");
    }
    if !ds.is_context(1) {
        return io("No signature algorithm in CMSAlgorithmProtection");
    }
    ds.retag(TAG_SEQUENCE);
    let s = AlgorithmId::parse(&mut ds)?;
    if s != encryption || d != digest {
        return io("CMSAlgorithmProtection check failed");
    }
    Ok(())
}

const CMS_ALGORITHM_PROTECTION: &str = "1.2.840.113549.1.9.52";

/// `PKCS9Attributes(DerInputStream)`: the implicitly tagged SET of attributes, each read by `PKCS9Attribute`; the
/// CMSAlgorithmProtection value's encoding when there is one.
fn pkcs9_attributes(derin: &mut DerInputStream) -> JResult<Option<Vec<u8>>> {
    let mut encoding = derin.get_der_value()?.byte_array();
    encoding[0] = TAG_SET;
    let mut seen: Vec<String> = Vec::new();
    let mut protection = None;
    for attribute in DerInputStream::of(encoding).get_implicit_set()? {
        let (oid, value) = pkcs9_attribute(attribute)?;
        if seen.contains(&oid) {
            return io(format!("Duplicate PKCS9 attribute: {oid}"));
        }
        if oid == CMS_ALGORITHM_PROTECTION {
            protection = value;
        }
        seen.push(oid);
    }
    Ok(protection)
}

/// `PKCS9Attribute(DerValue)`: the OID and, for CMSAlgorithmProtection, its value's encoding. Single-valued
/// attributes read their first value whatever the count, so an empty SET is an index error.
fn pkcs9_attribute(mut attribute: DerValue) -> JResult<(String, Option<Vec<u8>>)> {
    const STRINGS: &[u8] = &[TAG_PRINTABLE_STRING, TAG_T61_STRING, TAG_BMP_STRING, TAG_UNIVERSAL_STRING, TAG_UTF8_STRING];
    let mut der_in = DerInputStream::of(attribute.byte_array());
    let mut val = der_in.get_sequence()?;
    if der_in.available() != 0 {
        return io("Excess data parsing PKCS9Attribute");
    }
    if val.len() != 2 {
        return io("PKCS9Attribute doesn't have two components");
    }
    let oid = val[0].get_oid()?.to_string();
    let content = val[1].byte_array();
    let mut elems = DerInputStream::of(content).get_set()?;
    let ia5_and_strings: Vec<u8> = [&[TAG_IA5_STRING][..], STRINGS].concat();
    let (single, tags): (bool, &[u8]) = match oid.as_str() {
        "1.2.840.113549.1.9.1" => (false, &[TAG_IA5_STRING]),
        "1.2.840.113549.1.9.2" => (false, &ia5_and_strings),
        "1.2.840.113549.1.9.3" => (true, &[TAG_OBJECT_ID]),
        "1.2.840.113549.1.9.4" => (true, &[TAG_OCTET_STRING]),
        "1.2.840.113549.1.9.5" => (true, &[TAG_UTC_TIME, TAG_GENERALIZED_TIME]),
        "1.2.840.113549.1.9.6" => (false, &[TAG_SEQUENCE]),
        "1.2.840.113549.1.9.7" => (true, STRINGS),
        "1.2.840.113549.1.9.8" => (false, STRINGS),
        "1.2.840.113549.1.9.14" | "1.2.840.113549.1.9.16.2.12" | "1.2.840.113549.1.9.16.2.14" | CMS_ALGORITHM_PROTECTION => (true, &[TAG_SEQUENCE]),
        _ => return Ok((oid, None)),
    };
    let name = super::known_oids::std_name(&oid).unwrap_or_default();
    if single && elems.len() > 1 {
        return io(format!("Single-value attribute {oid} ({name}) has multiple values."));
    }
    if let Some(e) = elems.iter().find(|e| !tags.contains(&e.tag)) {
        return io(format!("Value of attribute {oid} ({name}) has wrong tag: {}", signed(e.tag)));
    }
    if single && elems.is_empty() {
        return Err(index_out_of_bounds(0, 0));
    }
    let mut value = None;
    for elem in elems.iter_mut() {
        match oid.as_str() {
            "1.2.840.113549.1.9.3" => {
                elem.get_oid()?;
            }
            "1.2.840.113549.1.9.4" => {
                elem.get_octet_string()?;
            }
            "1.2.840.113549.1.9.5" => {
                if elem.tag == TAG_UTC_TIME {
                    elem.get_utc_time()?;
                } else {
                    elem.get_generalized_time()?;
                }
            }
            "1.2.840.113549.1.9.6" => signer_info(elem.der_input_stream()?, false)?,
            "1.2.840.113549.1.9.14" => {
                certificate_extensions(&mut DerInputStream::of(elem.byte_array()))?;
            }
            "1.2.840.113549.1.9.16.2.12" => signing_certificate(&elem.byte_array())?,
            CMS_ALGORITHM_PROTECTION => value = Some(elem.byte_array()),
            // the string attributes and the timestamp token are not read further
            _ => {}
        }
    }
    Ok((oid, value))
}

/// `SigningCertificateInfo(byte[])`: ESSCertIDs, then policies whose entries are not read.
fn signing_certificate(bytes: &[u8]) -> JResult<()> {
    let mut value = DerValue::from(bytes)?;
    if value.tag != TAG_SEQUENCE {
        return io("Bad encoding for signingCertificate");
    }
    for mut id in value.data.get_sequence()? {
        // `ESSCertId(DerValue)`
        id.data.get_der_value()?;
        if id.data.available() > 0 {
            let mut issuer_serial = id.data.get_der_value()?;
            general_names(&mut issuer_serial.data.get_der_value()?)?;
            issuer_serial.data.get_der_value()?.get_big_integer()?;
        }
    }
    if value.data.available() > 0 {
        value.data.get_sequence()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// CRLs

const CRL: &str = "java.security.cert.CRLException";

fn crl_failure<T>(message: impl Into<String>) -> JResult<T> {
    Err(Throwable::new(CRL, message))
}

/// `X509Factory.engineGenerateCRL`: `readOneBlock`, then `new X509CRLImpl(encoding)`; any failure is the
/// `CRLException` (runtime exceptions included: the extension classes are called by reflection).
fn generate_crl(data: &[u8]) -> JResult<()> {
    let mut at = 0;
    let block = match read_one_block(data, &mut at) {
        Ok(Some(block)) => block,
        Ok(None) => return crl_failure("Empty input"),
        Err(e) => return crl_failure(e.message()),
    };
    x509_crl_impl(&block).map_err(|e| if e.class == CRL { e } else { Throwable::caused(CRL, format!("Parsing error: {}", e.message()), e) })
}

/// `X509CRLImpl.parse`
fn x509_crl_impl(data: &[u8]) -> JResult<()> {
    let mut val = DerValue::from(data)?;
    if val.tag != TAG_SEQUENCE {
        return crl_failure("Invalid DER-encoded CRL data");
    }
    let mut tbs = val.data.get_der_value()?;
    let mut algid_value = val.data.get_der_value()?;
    let mut signature = val.data.get_der_value()?;
    if val.data.available() != 0 {
        return crl_failure(format!("signed overrun, bytes = {}", val.data.available()));
    }
    let info_algid = tbs_cert_list(&mut tbs)?;
    if AlgorithmId::parse(&mut algid_value)? != info_algid {
        return crl_failure("Signature algorithm mismatch");
    }
    signature.get_bit_string()?;
    Ok(())
}

/// `TBSCertList(DerValue)`: the signature algorithm.
fn tbs_cert_list(value: &mut DerValue) -> JResult<AlgorithmId> {
    if value.tag != TAG_SEQUENCE {
        return crl_failure("signed CRL fields invalid");
    }
    let input = &mut value.data;
    if input.peek_byte()? == TAG_INTEGER && input.get_der_value()?.get_integer()? != 1 {
        return crl_failure("Invalid version");
    }
    let algid = AlgorithmId::parse(&mut input.get_der_value()?)?;
    if x500_name(input)? {
        return crl_failure("Empty issuer DN not allowed in X509CRLs");
    }
    match input.peek_byte()? {
        TAG_UTC_TIME => input.get_utc_time()?,
        TAG_GENERALIZED_TIME => input.get_generalized_time()?,
        other => return crl_failure(format!("Invalid encoding for thisUpdate (tag={})", signed(other))),
    }
    if input.available() == 0 {
        return Ok(algid);
    }
    match input.peek_byte()? {
        TAG_UTC_TIME => input.get_utc_time()?,
        TAG_GENERALIZED_TIME => input.get_generalized_time()?,
        _ => {}
    }
    if input.available() == 0 {
        return Ok(algid);
    }
    if input.peek_byte()? == TAG_SEQUENCE {
        for entry in input.get_sequence()? {
            // `X509CRLEntryImpl(DerValue)`, then `getCertIssuer`
            let extensions = crl_entry(entry)?;
            if let Some((_, value)) = extensions.iter().find(|(oid, _)| oid == "2.5.29.29") && !DerValue::from(value)?.subs(TAG_SEQUENCE)?.iter().any(|name| name.is_context(4)) {
                return crl_failure("Parsing error: CertificateIssuer field does not contain an X.500 DN");
            }
        }
    }
    if input.available() == 0 {
        return Ok(algid);
    }
    let mut tmp = input.get_der_value()?;
    if tmp.is_constructed() && tmp.is_context(0) {
        crl_extensions(&mut tmp.data)?;
    }
    Ok(algid)
}

/// `X509CRLEntryImpl.parse`: the entry's extensions.
fn crl_entry(mut entry: DerValue) -> JResult<Vec<(String, Vec<u8>)>> {
    if entry.tag != TAG_SEQUENCE {
        return crl_failure("Invalid encoded RevokedCertificate, starting sequence tag missing.");
    }
    if entry.data.available() == 0 {
        return crl_failure("No data encoded for RevokedCertificates");
    }
    let input = entry.der_input_stream()?;
    input.get_der_value()?.get_big_integer()?;
    match input.peek_byte()? {
        TAG_UTC_TIME => input.get_utc_time()?,
        TAG_GENERALIZED_TIME => input.get_generalized_time()?,
        _ => return crl_failure("Invalid encoding for revocation date"),
    }
    if input.available() == 0 {
        return Ok(Vec::new());
    }
    crl_extensions(input)
}

/// `CRLExtensions(DerInputStream)`: unlike a certificate's, any extension that does not parse fails the CRL.
fn crl_extensions(input: &mut DerInputStream) -> JResult<Vec<(String, Vec<u8>)>> {
    let first = input.peek_byte()?;
    let mut explicit;
    let input = if first & 0xc0 == 0x80 && first & 0x1f == 0 {
        explicit = input.get_der_value()?;
        &mut explicit.data
    } else {
        input
    };
    let mut parsed: Vec<(String, Vec<u8>)> = Vec::new();
    for ext in input.get_sequence()? {
        let (id, critical, value) = extension_fields(ext)?;
        extension(&id, critical, &value).map_err(|e| Throwable::new(CRL, e.message()))?;
        if parsed.iter().any(|(o, _)| *o == id) {
            return crl_failure("Duplicate extensions not allowed");
        }
        parsed.push((id, value));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------------------------------------------
// X509Factory

/// `X509Factory.readBERInternal`: the bytes of one BER value starting at `at` (its tag already read when `tag` is
/// given), indefinite lengths included.
fn read_ber(data: &[u8], at: &mut usize, out: &mut Vec<u8>, tag: Option<u8>, depth: u32) -> JResult<u8> {
    if depth == 0 {
        return io("Nesting sequence depth limit reached.");
    }
    let mut read = || {
        let b = data.get(*at).copied();
        if b.is_some() {
            *at += 1;
        }
        b
    };
    let tag = match tag {
        Some(tag) => tag,
        None => {
            let Some(tag) = read() else { return io("BER/DER tag info absent") };
            if tag & 0x1f == 0x1f {
                return io("Multi octets tag not supported");
            }
            out.push(tag);
            tag
        }
    };
    let Some(n) = read() else { return io("BER/DER length info absent") };
    out.push(n);
    if n == 0x80 {
        if tag & 0x20 != 0x20 {
            return io("Non constructed encoding must have definite length");
        }
        while read_ber(data, at, out, None, depth - 1)? != 0 {}
        return Ok(tag);
    }
    let length: i64 = match n {
        0..=0x7f => i64::from(n),
        0x81..=0x84 => {
            let count = usize::from(n - 0x80);
            let bytes: Vec<Option<u8>> = (0..count).map(|_| read()).collect();
            if bytes.last().copied().flatten().is_none() {
                return io("Incomplete BER/DER length info");
            }
            if count == 4 && bytes[0].is_some_and(|b| b > 127) {
                return io("Invalid BER/DER data (a little huge?)");
            }
            // a missing byte before the last reads as -1 in Java; with the last present none is missing
            let bytes: Vec<u8> = bytes.into_iter().flatten().collect();
            out.extend_from_slice(&bytes);
            bytes.iter().fold(0i64, |v, b| v << 8 | i64::from(*b))
        }
        _ => return io("Invalid BER/DER data (too huge?)"),
    };
    let available = (data.len() - *at) as i64;
    let take = length.min(available).max(0) as usize;
    out.extend_from_slice(&data[*at..*at + take]);
    *at += take;
    if (take as i64) != length {
        return io("Incomplete BER/DER data");
    }
    Ok(tag)
}

/// `X509Factory.readOneBlock`: `Ok(None)` at the end of the data, else the next block's bytes (a BER value, or a
/// PEM block's decoded body); `Err` is the `IOException`.
fn read_one_block(data: &[u8], at: &mut usize) -> JResult<Option<Vec<u8>>> {
    let Some(&c) = data.get(*at) else { return Ok(None) };
    if c == TAG_SEQUENCE {
        *at += 1;
        let mut out = vec![c];
        read_ber(data, at, &mut out, Some(c), 128)?;
        return Ok(Some(out));
    }
    pem::read_one_block(data, at)
}

/// `CertificateFactory.generateCertificates`, `X509Factory.parseX509orPKCS7Cert`: the certificates of a CA chain
/// file (the empty file has none).
pub fn generate_certificates(data: &[u8]) -> JResult<Vec<Certificate>> {
    // `engineGenerateCertificates`: an `IOException` becomes `new CertificateException(ioe)`
    let wrap = |e: Throwable| if e.is_io() { Throwable::wrapping(CERTIFICATE, e) } else { e };
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut at = 0;
    let Some(first) = read_one_block(data, &mut at).map_err(wrap)? else {
        return Err(Throwable::new(CERTIFICATE, "No certificate data found"));
    };
    if let Some(certificates) = pkcs7(&first)? {
        return Ok(certificates);
    }
    let mut certificates = Vec::new();
    let mut block = Some(first);
    while let Some(data_block) = block {
        certificates.push(x509_cert_impl(&data_block)?);
        block = read_one_block(data, &mut at).map_err(wrap)?;
    }
    Ok(certificates)
}

/// `CertificateFactory.generateCertificate`: the first block's certificate.
pub fn generate_certificate(data: &[u8]) -> JResult<Certificate> {
    let mut at = 0;
    let not_parsed = |e: Throwable| Throwable::caused(CERTIFICATE, format!("Could not parse certificate: {}", e.line()), e);
    match read_one_block(data, &mut at) {
        Ok(Some(block)) => x509_cert_impl(&block),
        Ok(None) => Err(not_parsed(Throwable::new(IO, "Empty input"))),
        Err(e) if e.is_io() => Err(not_parsed(e)),
        Err(e) => Err(e),
    }
}

pub(crate) use pem::java_base64_decode;

/// The PEM side of `readOneBlock`.
mod pem {
    use super::{JResult, Throwable, IO};

    enum Failure {
        /// An `EOFException`, which `readOneBlock` takes as the end of the data.
        End,
        Io(String),
        Thrown(Throwable),
    }

    /// `X509Factory.readOneBlock` after its first byte (consumed at `at`), over JDK 26's `Pem.readPEM`: `Ok(None)` at
    /// the end of the data (an `EOFException` anywhere in the block included), else the block's Base64 body decoded.
    pub fn read_one_block(data: &[u8], at: &mut usize) -> JResult<Option<Vec<u8>>> {
        let short = data[*at] == b'-';
        *at += 1;
        let text = match read_pem(data, at, short) {
            Ok(text) => text,
            Err(Failure::End) => return Ok(None),
            Err(Failure::Io(m)) => return Err(Throwable::new(IO, m)),
            Err(Failure::Thrown(t)) => return Err(t),
        };
        java_base64_decode(text.as_bytes()).map(Some).map_err(|m| {
            let iae = Throwable::new("java.lang.IllegalArgumentException", m);
            Throwable::caused(IO, iae.line(), iae)
        })
    }

    /// `Pem.readPEM(is, shortHeader)`: the Base64 text of the block (whitespace dropped).
    fn read_pem(data: &[u8], at: &mut usize, short: bool) -> Result<String, Failure> {
        let mut read = || {
            let c = data.get(*at).map_or(-1, |b| i32::from(*b));
            if c >= 0 {
                *at += 1;
            }
            c
        };
        let io = |m: String| Err(Failure::Io(m));
        let ch = |c: i32| char::from(c as u8);
        // up to `-----B`, anywhere
        let mut hyphen = i32::from(short);
        loop {
            match read() {
                -1 => return Err(Failure::End),
                0x2d => hyphen += 1,
                0x42 if hyphen == 5 => break,
                _ => hyphen = 0,
            }
        }
        let mut header = String::from("-----B");
        hyphen = 0;
        while hyphen == 0 {
            match read() {
                0x2d => hyphen += 1,
                -1 => return Err(Failure::End),
                0x0a | 0x0d => return io("Incomplete header".into()),
                c => header.push(ch(c)),
            }
        }
        while hyphen < 5 {
            match read() {
                0x2d => hyphen += 1,
                _ => return io("Incomplete header".into()),
            }
        }
        header.push_str("-----");
        if header.chars().count() < 16 || !header.starts_with("-----BEGIN ") || !header.ends_with("-----") {
            return io(format!("Illegal header: {header}"));
        }
        let mut body = String::new();
        let mut eol = 0;
        match read() {
            0x20 => {}
            0x0d => {
                let c = read();
                if c == 0x0a {
                    eol = 0x0a;
                } else {
                    eol = 0x0d;
                    body.push(ch(c));
                }
            }
            0x0a => eol = 0x0a,
            _ => return io("No EOL character found".into()),
        }
        hyphen = 0;
        while hyphen == 0 {
            match read() {
                -1 => return Err(Failure::End),
                0x2d => hyphen += 1,
                0x20 | 0x09 | 0x0d | 0x0a => {}
                c => body.push(ch(c)),
            }
        }
        while hyphen < 5 {
            match read() {
                0x2d => hyphen += 1,
                -1 => return Err(Failure::End),
                _ => return io("Incomplete footer".into()),
            }
        }
        let mut footer = String::from("-----");
        hyphen = 0;
        while hyphen == 0 {
            match read() {
                0x2d => hyphen += 1,
                -1 => return Err(Failure::End),
                c => footer.push(ch(c)),
            }
        }
        while hyphen < 5 {
            match read() {
                0x2d => hyphen += 1,
                -1 => return Err(Failure::End),
                _ => return io("Incomplete footer".into()),
            }
        }
        loop {
            let c = read();
            if c == eol || c == -1 || c == 0x20 {
                break;
            }
            if c == 0x0d {
                continue;
            }
            return io(format!("Invalid PEM format:  No EOL char found in footer:  0x{c:02x}"));
        }
        footer.push_str("-----");
        if footer.chars().count() < 14 || !footer.starts_with("-----END ") || !footer.ends_with("-----") {
            return io(format!("Illegal footer: {footer}"));
        }
        let header_type: String = header.chars().skip(11).take(header.chars().count() - 16).collect();
        let footer_type: String = footer.chars().skip(9).take(footer.chars().count() - 14).collect();
        if header_type != footer_type {
            return io(format!("Header and footer do not match: {header_type} {footer_type}"));
        }
        // the `PEM` record's own check, an `IllegalArgumentException` that `readOneBlock` wraps
        if header_type.starts_with('-') || header_type.starts_with("BEGIN ") || header_type.starts_with("END ") {
            let iae = Throwable::new("java.lang.IllegalArgumentException", "PEM syntax labels found. Only the PEM type identifier is allowed.");
            return Err(Failure::Thrown(Throwable::caused(IO, iae.line(), iae)));
        }
        Ok(body)
    }

    /// `java.util.Base64.getDecoder().decode(byte[])`, with its `IllegalArgumentException` messages.
    pub(crate) fn java_base64_decode(src: &[u8]) -> Result<Vec<u8>, String> {
        if src.is_empty() {
            return Ok(Vec::new());
        }
        if src.len() < 2 {
            return Err("Input byte[] should at least have 2 bytes for base64 bytes".into());
        }
        let digit = |c: u8| match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(c - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        };
        let mut out = Vec::with_capacity(src.len() * 3 / 4);
        let (mut bits, mut shift, mut sp) = (0u32, 18i32, 0usize);
        while sp < src.len() {
            let c = src[sp];
            sp += 1;
            let Some(d) = digit(c) else {
                if c == b'=' {
                    // `xx=` must be `xx==`, and `=` cannot open a unit
                    if (shift == 6 && (sp == src.len() || {
                        sp += 1;
                        src[sp - 1] != b'='
                    })) || shift == 18
                    {
                        return Err("Input byte array has wrong 4-byte ending unit".into());
                    }
                    break;
                }
                // `Integer.toString(byte, 16)` of a signed byte
                let signed = c as i8;
                let hex = if signed < 0 { format!("-{:x}", -i32::from(signed)) } else { format!("{signed:x}") };
                return Err(format!("Illegal base64 character {hex}"));
            };
            bits |= d << shift;
            shift -= 6;
            if shift < 0 {
                out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
                shift = 18;
                bits = 0;
            }
        }
        match shift {
            6 => out.push((bits >> 16) as u8),
            0 => out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8]),
            12 => return Err("Last unit does not have enough valid bits".into()),
            _ => {}
        }
        if sp < src.len() {
            return Err(format!("Input byte array has incorrect ending byte at {sp}"));
        }
        Ok(out)
    }
}
