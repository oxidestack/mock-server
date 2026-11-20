//! `org.mockserver.model.MediaType`: how a `Content-Type` decides a body's class and charset, and
//! `BodyDecoderEncoder.bytesToBody`.

use base64::Engine;

#[derive(Debug, Clone, Default)]
pub struct MediaType {
    kind: Option<String>,
    subtype: Option<String>,
    charset: Option<String>,
    blank: bool,
}

const KNOWN_BINARY_SUBTYPES: &[&str] =
    &["octet-stream", "binary", "pdf", "zip", "gzip", "tar", "protobuf", "grpc", "thrift", "avro", "msgpack", "pkcs", "pkix", "x509", "woff", "woff2"];

/// `MediaType.parse(header).toString()`: `type/subtype` lower-cased, then the parameters lower-cased, unquoted and
/// sorted by name, each `; name=value`.
pub fn normalise(header: &str) -> String {
    if header.trim().is_empty() {
        return String::new();
    }
    let (mut out, params_start) = match header.find('/') {
        Some(_) => {
            let end = header.find(';').unwrap_or(header.len());
            let (t, s) = header[..end].trim().split_once('/').unwrap_or_default();
            (format!("{}/{}", t.trim().to_lowercase(), s.trim().to_lowercase()), if end < header.len() { end + 1 } else { end })
        }
        None => (String::new(), 0),
    };
    let params = header[params_start..].trim().to_lowercase().replace('"', "");
    let mut sorted: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for p in params.split(';') {
        let p = p.trim();
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        if !k.trim().is_empty() && !v.trim().is_empty() {
            sorted.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    if !sorted.is_empty() {
        let joined: Vec<String> = sorted.iter().map(|(k, v)| format!("{k}={v}")).collect();
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(&joined.join("; "));
    }
    out
}

impl MediaType {
    /// `MediaType.parse(header)`.
    pub fn parse(header: Option<&str>) -> MediaType {
        let Some(header) = header.filter(|h| !h.trim().is_empty()) else {
            return MediaType { blank: true, ..MediaType::default() };
        };
        let mut media = MediaType::default();
        let mut params_start = 0;
        if header.contains('/') {
            let end = header.find(';').unwrap_or(header.len());
            let type_string = header[..end].trim();
            let (t, s) = type_string.split_once('/').unwrap_or((type_string, ""));
            media.kind = Some(t.trim().to_lowercase());
            media.subtype = Some(s.trim().to_lowercase());
            params_start = if end < header.len() { end + 1 } else { end };
        }
        let params = header[params_start..].trim().to_lowercase().replace('"', "");
        for p in params.split(';') {
            let (k, v) = p.trim().split_once('=').unwrap_or((p.trim(), ""));
            // `Charset.forName`: a charset Java does not know is ignored.
            if k.trim() == "charset" && !v.trim().is_empty() {
                media.charset = canonical_charset(v.trim()).map(str::to_string);
            }
        }
        media
    }

    fn contains(&self, subs: &[&str]) -> bool {
        match (&self.kind, &self.subtype) {
            (Some(t), Some(s)) => {
                let both = format!("{t}/{s}");
                subs.iter().any(|x| both.contains(x))
            }
            _ => false,
        }
    }

    /// Whether the type and subtype are these (lower case).
    pub fn is(&self, kind: &str, subtype: &str) -> bool {
        self.kind.as_deref() == Some(kind) && self.subtype.as_deref() == Some(subtype)
    }

    pub fn is_json(&self) -> bool {
        !self.blank && self.contains(&["json"]) && !self.contains(&["ndjson"])
    }

    pub fn is_xml(&self) -> bool {
        !self.blank && self.contains(&["xml"])
    }

    fn is_binary_subtype(&self) -> bool {
        if matches!(self.kind.as_deref(), Some("image" | "audio" | "video")) {
            return true;
        }
        self.subtype.as_deref().is_some_and(|s| KNOWN_BINARY_SUBTYPES.iter().any(|b| s.contains(b)))
    }

    pub fn is_string(&self) -> bool {
        if self.blank || (self.kind.is_none() && self.charset.is_some()) {
            return true;
        }
        if self.contains(&[
            "text", "json", "css", "html", "xhtml", "form", "javascript", "ecmascript", "xml", "wsdl", "csv", "urlencoded", "yaml", "graphql",
        ]) {
            return true;
        }
        self.charset.is_some() && !self.is_binary_subtype()
    }

    /// The charset the header names, if Java knows it, by its canonical name lower-cased.
    pub fn charset(&self) -> Option<&str> {
        self.charset.as_deref()
    }

    /// `getCharsetOrDefault()`: the named charset, else UTF-8 for blank / JSON / XML, else ISO-8859-1 for text.
    pub fn charset_or_default(&self) -> Option<&str> {
        if let Some(c) = &self.charset {
            return Some(c);
        }
        if self.blank || self.is_json() || self.is_xml() {
            Some("utf-8")
        } else if self.is_string() {
            Some("iso-8859-1")
        } else {
            None
        }
    }
}

/// `Charset.forName(name).name()`, lower-cased; `None` where Java throws (an unknown or illegal name). The names
/// and aliases are those of the oracle's JVM (`src/java_charsets.bin.gz`).
pub fn canonical_charset(name: &str) -> Option<&'static str> {
    java_charset(name).map(|c| c.lower.as_str())
}

/// `new String(bytes, charset)`, unknown charsets as UTF-8.
pub fn decode(bytes: &[u8], charset: Option<&str>) -> String {
    match charset.and_then(java_charset) {
        Some(c) => c.decode(bytes),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// `text.getBytes(charset)`: unmappable characters become the charset's replacement (`?`), unknown charsets
/// encode as UTF-8.
pub fn encode(text: &str, charset: Option<&str>) -> Vec<u8> {
    match charset.and_then(java_charset) {
        Some(c) => c.encode(text),
        None => text.as_bytes().to_vec(),
    }
}

/// The charsets of the oracle's JVM, dumped by `conformance/charsets/DumpCharsets.java` (format there).
static JAVA_CHARSETS: &[u8] = include_bytes!("java_charsets.bin.gz");

/// One `java.nio.charset.Charset`: the Unicode encodings are computed, every other charset is the decoder's and
/// encoder's mappings as dumped.
struct JavaCharset {
    lower: String,
    names: Vec<String>,
    codec: Codec,
}

enum Codec {
    Unicode(Unicode),
    Table { data: &'static [u8], table: Box<std::sync::OnceLock<Table>> },
}

#[derive(Clone, Copy)]
enum Unicode {
    Utf8,
    Cesu8,
    /// UTF-16: a byte-order mark picks the order, else big-endian; encodes with a big-endian mark.
    Utf16,
    Utf16Be,
    Utf16Le,
    /// x-UTF-16LE-BOM: as UTF-16, but little-endian without a mark and when encoding.
    Utf16LeBom,
    /// UTF-32: a byte-order mark picks the order, else big-endian; encodes big-endian without a mark.
    Utf32,
    Utf32Be,
    Utf32Le,
    Utf32BeBom,
    Utf32LeBom,
}

struct Table {
    replacement: Vec<u8>,
    /// Byte sequence (`length << 32 | big-endian value`) to code point.
    decode: std::collections::HashMap<u64, u32>,
    /// Per length minus one, ranges of sequences the decoder rejects as a whole.
    errors: [Vec<(u32, u32)>; 4],
    /// Per length minus one, ranges of sequences the decoder waits on: at the end of the input, one U+FFFD.
    incomplete: [Vec<(u32, u32)>; 4],
    max_len: usize,
    encode: std::collections::HashMap<u32, Vec<u8>>,
    /// `encode` for U+0000 to U+00FF, read without hashing: a 10 MiB Latin-1 body took seconds in test builds under
    /// load.
    low: Vec<Option<Vec<u8>>>,
    /// `decode` for a single-byte charset (no longer sequence, none waited on), per byte, read without hashing: a
    /// 10 MiB Latin-1 body logged a few times took minutes in test builds.
    single: Option<Vec<char>>,
    /// GB18030's linear four-byte range for supplementary characters.
    gb18030: bool,
}

/// `Charset.forName`: canonical names and aliases, ASCII case-insensitive.
fn java_charset(name: &str) -> Option<&'static JavaCharset> {
    static CHARSETS: std::sync::OnceLock<std::collections::HashMap<String, JavaCharset>> = std::sync::OnceLock::new();
    static BY_NAME: std::sync::OnceLock<std::collections::HashMap<String, &'static JavaCharset>> = std::sync::OnceLock::new();
    let by_name = BY_NAME.get_or_init(|| {
        let charsets = CHARSETS.get_or_init(|| load_charsets().into_iter().map(|c| (c.lower.clone(), c)).collect());
        charsets.values().flat_map(|c| c.names.iter().map(move |n| (n.to_ascii_lowercase(), c))).collect()
    });
    by_name.get(&name.trim().to_ascii_lowercase()).copied()
}

/// A cursor over the dump.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
    fn varint(&mut self) -> u64 {
        let (mut value, mut shift) = (0u64, 0);
        loop {
            let b = self.u8();
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
    /// One group of sequences as merged ranges.
    fn ranges(&mut self) -> Vec<(u32, u32)> {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut seq = 0u32;
        for _ in 0..self.u32() {
            seq += self.varint() as u32;
            match ranges.last_mut() {
                Some((_, end)) if *end + 1 == seq => *end = seq,
                _ => ranges.push((seq, seq)),
            }
        }
        ranges
    }
    fn string(&mut self) -> String {
        let n = self.u8() as usize;
        String::from_utf8(self.take(n).to_vec()).unwrap()
    }
    /// Skips one table, returning its bytes.
    fn table(&mut self) -> &'a [u8] {
        let start = self.0;
        let n = self.u8() as usize;
        self.take(n);
        for _ in 0..4 {
            for _ in 0..self.u32() {
                self.varint();
                self.varint();
            }
        }
        for _ in 0..8 {
            self.ranges();
        }
        for _ in 0..self.u32() {
            self.varint();
            let n = self.u8() as usize;
            self.take(n);
        }
        &start[..start.len() - self.0.len()]
    }
}

fn load_charsets() -> Vec<JavaCharset> {
    use std::io::Read;
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(JAVA_CHARSETS).read_to_end(&mut raw).expect("java_charsets.bin.gz");
    let raw: &'static [u8] = raw.leak();
    let mut r = Reader(raw);
    assert_eq!(r.take(4), b"JCS1");
    (0..r.u16())
        .map(|_| {
            let name = r.string();
            let mut names = vec![name.clone()];
            for _ in 0..r.u8() {
                names.push(r.string());
            }
            let codec = if r.u8() == 1 {
                Codec::Unicode(match name.as_str() {
                    "UTF-8" => Unicode::Utf8,
                    "CESU-8" => Unicode::Cesu8,
                    "UTF-16" => Unicode::Utf16,
                    "UTF-16BE" => Unicode::Utf16Be,
                    "UTF-16LE" => Unicode::Utf16Le,
                    "x-UTF-16LE-BOM" => Unicode::Utf16LeBom,
                    "UTF-32" => Unicode::Utf32,
                    "UTF-32BE" => Unicode::Utf32Be,
                    "UTF-32LE" => Unicode::Utf32Le,
                    "X-UTF-32BE-BOM" => Unicode::Utf32BeBom,
                    "X-UTF-32LE-BOM" => Unicode::Utf32LeBom,
                    other => panic!("no Unicode codec for {other}"),
                })
            } else {
                Codec::Table { data: r.table(), table: Box::default() }
            };
            JavaCharset { lower: name.to_lowercase(), names, codec }
        })
        .collect()
}

impl Table {
    fn parse(data: &[u8], gb18030: bool) -> Table {
        let mut r = Reader(data);
        let n = r.u8() as usize;
        let replacement = r.take(n).to_vec();
        let mut decode = std::collections::HashMap::new();
        let mut encode = std::collections::HashMap::new();
        let mut max_len = 1;
        for len in 1..=4u64 {
            let (mut seq, mut cp) = (0u64, 0i64);
            for _ in 0..r.u32() {
                seq += r.varint();
                let delta = r.varint();
                cp += ((delta >> 1) as i64) ^ -((delta & 1) as i64);
                decode.insert(len << 32 | seq, cp as u32);
                encode.entry(cp as u32).or_insert_with(|| seq.to_be_bytes()[8 - len as usize..].to_vec());
                max_len = max_len.max(len as usize);
            }
        }
        let errors = [r.ranges(), r.ranges(), r.ranges(), r.ranges()];
        let incomplete = [r.ranges(), r.ranges(), r.ranges(), r.ranges()];
        for (len, ranges) in errors.iter().enumerate() {
            if !ranges.is_empty() {
                max_len = max_len.max(len + 1);
            }
        }
        let mut cp = 0u32;
        for _ in 0..r.u32() {
            cp += r.varint() as u32;
            let n = r.u8() as usize;
            match n {
                0 => encode.remove(&cp),
                _ => encode.insert(cp, r.take(n).to_vec()),
            };
        }
        let low = (0..256).map(|cp| encode.get(&cp).cloned()).collect();
        // a byte the table lacks is malformed or unmappable, one U+FFFD either way
        let single = (max_len == 1 && !gb18030 && incomplete.iter().all(Vec::is_empty))
            .then(|| (0..256u64).map(|b| decode.get(&(1 << 32 | b)).and_then(|cp| char::from_u32(*cp)).unwrap_or('\u{fffd}')).collect());
        Table { replacement, decode, errors, incomplete, max_len, encode, low, single, gb18030 }
    }

    fn decode(&self, bytes: &[u8]) -> String {
        if let Some(single) = &self.single {
            return bytes.iter().map(|b| single[usize::from(*b)]).collect();
        }
        let key = |seq: &[u8]| seq.iter().fold(0u32, |v, b| v << 8 | u32::from(*b));
        let within = |ranges: &[(u32, u32)], seq: &[u8]| {
            let k = key(seq);
            ranges.binary_search_by(|(start, end)| if *end < k { std::cmp::Ordering::Less } else if *start > k { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal }).is_ok()
        };
        let mut out = String::with_capacity(bytes.len());
        let mut i = 0;
        'next: while i < bytes.len() {
            let rest = &bytes[i..];
            // GB18030: a lead and a byte 0x30-0x39 make a four-byte sequence, decoded or rejected whole.
            if let (true, [0x81..=0xfe, 0x30..=0x39, ..]) = (self.gb18030, rest) {
                // A third byte outside 0x81-0xFE ends the malformed sequence before it.
                let seq = &rest[..if rest.get(2).is_some_and(|b| !(0x81..=0xfe).contains(b)) { 3 } else { rest.len().min(4) }];
                let decoded = (seq.len() == 4).then(|| self.decode.get(&(4 << 32 | u64::from(key(seq))))).flatten();
                out.push(decoded.and_then(|cp| char::from_u32(*cp)).or_else(|| gb18030_supplementary(seq)).unwrap_or('\u{fffd}'));
                i += seq.len();
                continue;
            }
            // The decoder waits on an incomplete sequence; at the end of the input it is one malformed one.
            if rest.len() < 4 && within(&self.incomplete[rest.len() - 1], rest) {
                out.push('\u{fffd}');
                break;
            }
            for len in (1..=self.max_len.min(rest.len())).rev() {
                let seq = &rest[..len];
                if let Some(cp) = self.decode.get(&((len as u64) << 32 | u64::from(key(seq)))) {
                    out.push(char::from_u32(*cp).unwrap_or('\u{fffd}'));
                    i += len;
                    continue 'next;
                }
                if within(&self.errors[len - 1], seq) {
                    out.push('\u{fffd}');
                    i += len;
                    continue 'next;
                }
            }
            out.push('\u{fffd}');
            i += 1;
        }
        out
    }

    fn encode(&self, text: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len());
        for c in text.chars() {
            let low = self.low.get(c as usize).map(Option::as_ref);
            match low.unwrap_or_else(|| self.encode.get(&(c as u32))) {
                Some(bytes) => out.extend_from_slice(bytes),
                None if self.gb18030 && c as u32 >= 0x10000 => {
                    let mut linear = c as u32 - 0x10000;
                    let mut b = [0u8; 4];
                    for (i, radix) in [(3, 10), (2, 126), (1, 10)] {
                        b[i] = (linear % radix) as u8;
                        linear /= radix;
                    }
                    b[0] = linear as u8;
                    out.extend_from_slice(&[b[0] + 0x90, b[1] + 0x30, b[2] + 0x81, b[3] + 0x30]);
                }
                None => out.extend_from_slice(&self.replacement),
            }
        }
        out
    }
}

/// GB18030's four-byte sequences from `90 30 81 30`, U+10000 onwards in order.
fn gb18030_supplementary(seq: &[u8]) -> Option<char> {
    let [b1 @ 0x90..=0xfe, b2 @ 0x30..=0x39, b3 @ 0x81..=0xfe, b4 @ 0x30..=0x39] = *seq else { return None };
    let linear = ((u32::from(b1 - 0x90) * 10 + u32::from(b2 - 0x30)) * 126 + u32::from(b3 - 0x81)) * 10 + u32::from(b4 - 0x30);
    char::from_u32(0x10000 + linear).filter(|_| linear <= 0x10ffff - 0x10000)
}

impl JavaCharset {
    fn table(&self) -> Option<&Table> {
        match &self.codec {
            Codec::Table { data, table } => Some(table.get_or_init(|| Table::parse(data, self.lower == "gb18030"))),
            Codec::Unicode(_) => None,
        }
    }

    fn decode(&self, bytes: &[u8]) -> String {
        let Codec::Unicode(unicode) = self.codec else { return self.table().unwrap().decode(bytes) };
        match unicode {
            Unicode::Utf8 => utf8(bytes),
            Unicode::Cesu8 => java_utf8(bytes, true),
            Unicode::Utf16 => match bytes {
                [0xfe, 0xff, rest @ ..] => utf16(rest, false),
                [0xff, 0xfe, rest @ ..] => utf16(rest, true),
                _ => utf16(bytes, false),
            },
            Unicode::Utf16LeBom => match bytes {
                [0xfe, 0xff, rest @ ..] => utf16(rest, false),
                [0xff, 0xfe, rest @ ..] => utf16(rest, true),
                _ => utf16(bytes, true),
            },
            Unicode::Utf16Be => utf16(bytes, false),
            Unicode::Utf16Le => utf16(bytes, true),
            Unicode::Utf32 => match bytes {
                [0, 0, 0xfe, 0xff, rest @ ..] => utf32(rest, false),
                [0xff, 0xfe, 0, 0, rest @ ..] => utf32(rest, true),
                _ => utf32(bytes, false),
            },
            // A fixed order drops a leading byte-order mark in that order only.
            Unicode::Utf32Be | Unicode::Utf32BeBom => utf32(bytes.strip_prefix(&[0, 0, 0xfe, 0xff]).unwrap_or(bytes), false),
            Unicode::Utf32Le | Unicode::Utf32LeBom => utf32(bytes.strip_prefix(&[0xff, 0xfe, 0, 0]).unwrap_or(bytes), true),
        }
    }

    fn encode(&self, text: &str) -> Vec<u8> {
        let Codec::Unicode(unicode) = self.codec else { return self.table().unwrap().encode(text) };
        let units = |be: bool| text.encode_utf16().flat_map(move |u| if be { u.to_be_bytes() } else { u.to_le_bytes() });
        let points = |be: bool| text.chars().flat_map(move |c| if be { (c as u32).to_be_bytes() } else { (c as u32).to_le_bytes() });
        match unicode {
            Unicode::Utf8 => text.as_bytes().to_vec(),
            Unicode::Cesu8 => text.encode_utf16().flat_map(|u| char::from_u32(u32::from(u)).map_or_else(|| surrogate_utf8(u), |c| c.to_string().into_bytes())).collect(),
            Unicode::Utf16 => [0xfe, 0xff].into_iter().chain(units(true)).collect(),
            Unicode::Utf16Be => units(true).collect(),
            Unicode::Utf16Le => units(false).collect(),
            Unicode::Utf16LeBom => [0xff, 0xfe].into_iter().chain(units(false)).collect(),
            Unicode::Utf32 | Unicode::Utf32Be => points(true).collect(),
            Unicode::Utf32Le => points(false).collect(),
            Unicode::Utf32BeBom => [0, 0, 0xfe, 0xff].into_iter().chain(points(true)).collect(),
            Unicode::Utf32LeBom => [0xff, 0xfe, 0, 0].into_iter().chain(points(false)).collect(),
        }
    }
}

/// A surrogate code unit as the three bytes UTF-8 would give it.
fn surrogate_utf8(u: u16) -> Vec<u8> {
    vec![0xe0 | (u >> 12) as u8, 0x80 | ((u >> 6) & 0x3f) as u8, 0x80 | (u & 0x3f) as u8]
}

/// Java's UTF-8 decoder; valid input reads as Rust reads it.
fn utf8(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => java_utf8(bytes, false),
    }
}

/// Java's UTF-8 decoder, or with `cesu` its CESU-8 one (supplementary characters as surrogate pairs of three bytes
/// each, no four-byte sequences). A malformed sequence is its lead and the valid continuation bytes after it, where
/// `ED A0`–`ED BF` start a valid three-byte sequence; UTF-8 rejects the encoded surrogate as a whole.
fn java_utf8(bytes: &[u8], cesu: bool) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let (len, second) = match b {
            0x00..=0x7f => (1, 0x80..=0xbf),
            0xc2..=0xdf => (2, 0x80..=0xbf),
            0xe0 => (3, 0xa0..=0xbf),
            0xe1..=0xef => (3, 0x80..=0xbf),
            0xf0 if !cesu => (4, 0x90..=0xbf),
            0xf1..=0xf3 if !cesu => (4, 0x80..=0xbf),
            0xf4 if !cesu => (4, 0x80..=0x8f),
            _ => (0, 0x80..=0xbf),
        };
        let valid = 1 + (1..len.max(1))
            .take_while(|k| bytes.get(i + k).is_some_and(|c| if *k == 1 { second.contains(c) } else { (0x80..=0xbf).contains(c) }))
            .count();
        if len == 0 || valid < len {
            units.push(0xfffd);
            i += valid;
            continue;
        }
        let cont = |k: usize| u32::from(bytes[i + k] & 0x3f);
        let cp = match len {
            1 => u32::from(b),
            2 => u32::from(b & 0x1f) << 6 | cont(1),
            3 => u32::from(b & 0x0f) << 12 | cont(1) << 6 | cont(2),
            _ => u32::from(b & 0x07) << 18 | cont(1) << 12 | cont(2) << 6 | cont(3),
        };
        match char::from_u32(cp) {
            Some(c) => units.extend_from_slice(c.encode_utf16(&mut [0; 2])),
            None if cesu => units.push(cp as u16),
            None => units.push(0xfffd),
        }
        i += len;
    }
    String::from_utf16_lossy(&units)
}

fn utf32(bytes: &[u8], little_endian: bool) -> String {
    bytes
        .chunks(4)
        .map(|c| match <[u8; 4]>::try_from(c) {
            Ok(b) => char::from_u32(if little_endian { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }).unwrap_or('\u{fffd}'),
            Err(_) => '\u{fffd}',
        })
        .collect()
}

fn is_utf8(charset: &str) -> bool {
    matches!(charset.to_lowercase().as_str(), "utf-8" | "utf8")
}

/// `HttpRequest.getBodyAsString()` over the body `BodyDecoderEncoder.bytesToBody` makes of `bytes`: JSON, XML and
/// other string types decoded with `getCharsetOrDefault()` (UTF-8 for no type, JSON and XML, ISO-8859-1 for other
/// string types), any other type a `BinaryBody`, whose string is its base64.
pub fn body_as_string<'a>(bytes: &'a [u8], content_type: Option<&str>) -> std::borrow::Cow<'a, str> {
    if bytes.is_empty() {
        return std::borrow::Cow::Borrowed("");
    }
    let media = MediaType::parse(content_type);
    match media.charset_or_default() {
        _ if !media.is_json() && !media.is_xml() && !media.is_string() => std::borrow::Cow::Owned(base64::engine::general_purpose::STANDARD.encode(bytes)),
        // `BodyDecoderEncoder` makes a string-typed body a `StringBody`, which keeps a blank value as `""`
        // (`isNotBlank(value) ? value : ""`); a `JsonBody` or `XmlBody` keeps its whitespace.
        charset if !media.is_json() && !media.is_xml() && is_blank_string_body(bytes, charset) => std::borrow::Cow::Borrowed(""),
        Some(charset) if !is_utf8(charset) => std::borrow::Cow::Owned(decode(bytes, Some(charset))),
        _ => String::from_utf8_lossy(bytes),
    }
}

/// `HttpRequest.getBodyAsJsonOrXmlString()`: a `StringBody` (a string type that is neither JSON nor XML, or no
/// type) is encoded back with the header's charset and read as UTF-8, so a control-plane body sent as
/// `text/plain` or a form still reads as the UTF-8 JSON it is; any other body is [`body_as_string`].
pub fn body_as_json_or_xml_string<'a>(bytes: &'a [u8], content_type: Option<&str>) -> std::borrow::Cow<'a, str> {
    let media = MediaType::parse(content_type);
    if bytes.is_empty() || media.is_json() || media.is_xml() || !media.is_string() {
        return body_as_string(bytes, content_type);
    }
    // A `StringBody` keeps a blank value as `""` (`isNotBlank(value) ? value : ""`).
    if is_blank_string_body(bytes, media.charset_or_default()) {
        return std::borrow::Cow::Borrowed("");
    }
    match media.charset_or_default() {
        Some(charset) if !is_utf8(charset) && !charset.eq_ignore_ascii_case("iso-8859-1") => {
            std::borrow::Cow::Owned(String::from_utf8_lossy(&encode(&decode(bytes, Some(charset)), Some(charset))).into_owned())
        }
        // ISO-8859-1 gives back the bytes it read; UTF-8 reads them as they are.
        _ => String::from_utf8_lossy(bytes),
    }
}

/// `StringUtils.isBlank` of the body decoded with `charset`.
fn is_blank_string_body(bytes: &[u8], charset: Option<&str>) -> bool {
    !bytes.iter().any(u8::is_ascii_graphic) && is_blank(&decode(bytes, charset))
}

/// `StringUtils.isBlank`: every character `Character.isWhitespace`.
pub fn is_blank(text: &str) -> bool {
    text.chars().all(java_whitespace)
}

/// `Character.isWhitespace`: Unicode space separators other than the non-breaking ones, and the ASCII controls
/// `\t`–`\r` and `\u001C`–`\u001F`.
fn java_whitespace(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\u{1C}'..='\u{1F}' | ' ' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{205F}' | '\u{3000}')
}

/// Java's UTF-16 decoder: a high surrogate and the unit after it are one malformed sequence unless that is a low
/// surrogate, and so are the bytes left at the end.
fn utf16(bytes: &[u8], little_endian: bool) -> String {
    let unit = |i: usize| if little_endian { u16::from_le_bytes([bytes[i], bytes[i + 1]]) } else { u16::from_be_bytes([bytes[i], bytes[i + 1]]) };
    let mut out = String::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = unit(i);
        match u {
            0xd800..=0xdbff if i + 3 < bytes.len() => {
                let low = unit(i + 2);
                out.push(match low {
                    0xdc00..=0xdfff => char::from_u32(0x10000 + ((u32::from(u) - 0xd800) << 10) + (u32::from(low) - 0xdc00)).unwrap(),
                    _ => '\u{fffd}',
                });
                i += 4;
            }
            0xd800..=0xdbff => {
                out.push('\u{fffd}');
                i = bytes.len();
            }
            _ => {
                out.push(char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'));
                i += 2;
            }
        }
    }
    if i < bytes.len() {
        out.push('\u{fffd}');
    }
    out
}

/// A body's text: decoded with the charset `content_type` names, else as UTF-8.
pub fn text_with_named_charset(bytes: &[u8], content_type: Option<&str>) -> String {
    match MediaType::parse(content_type).charset() {
        Some(charset) => decode(bytes, Some(charset)),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// A received body as upstream models it (`BodyDecoderEncoder.bytesToBody`).
#[derive(Debug, Clone)]
pub enum DecodedBody {
    Json(String),
    Xml(String),
    String(String),
    Binary(Vec<u8>),
}

impl DecodedBody {
    pub fn decode(bytes: &[u8], content_type: Option<&str>) -> Option<DecodedBody> {
        if bytes.is_empty() {
            return None;
        }
        let media = MediaType::parse(content_type);
        let text = || decode(bytes, media.charset_or_default());
        Some(if media.is_json() {
            DecodedBody::Json(text())
        } else if media.is_xml() {
            DecodedBody::Xml(text())
        } else if media.is_string() {
            DecodedBody::String(text())
        } else {
            DecodedBody::Binary(bytes.to_vec())
        })
    }

    /// `BodyDTO.toString(body)` (what templates see as `request.body`): the text, or base64 of binary bodies.
    pub fn template_string(&self) -> String {
        match self {
            DecodedBody::Json(s) | DecodedBody::Xml(s) | DecodedBody::String(s) => s.clone(),
            DecodedBody::Binary(b) => base64::engine::general_purpose::STANDARD.encode(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A Java string's code points; a lone surrogate (UTF-32 and CESU-8 decode one) is U+FFFD in a Rust string.
    fn text(v: &Value) -> String {
        v.as_array().unwrap().iter().map(|cp| char::from_u32(cp.as_u64().unwrap() as u32).unwrap_or('\u{fffd}')).collect()
    }

    /// `getBytes` and `new String` of every charset of the oracle's JVM (`conformance/charsets/CharsetVectors.java`).
    #[test]
    fn charsets_match_the_oracle_jvm() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/charsets/vectors.json");
        let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut failures = Vec::new();
        for v in vectors["encode"].as_array().unwrap() {
            let charset = v["charset"].as_str().unwrap();
            assert_eq!(super::canonical_charset(charset), Some(charset.to_lowercase().as_str()));
            let actual = hex(&super::encode(&text(&v["text"]), Some(charset)));
            if actual != v["bytes"].as_str().unwrap() {
                failures.push(format!("encode {charset} {:?}: {actual} != {}", text(&v["text"]), v["bytes"]));
            }
        }
        for v in vectors["decode"].as_array().unwrap() {
            let charset = v["charset"].as_str().unwrap();
            let b = v["bytes"].as_str().unwrap();
            let bytes: Vec<u8> = (0..b.len()).step_by(2).map(|i| u8::from_str_radix(&b[i..i + 2], 16).unwrap()).collect();
            let actual = super::decode(&bytes, Some(charset));
            if actual != text(&v["text"]) {
                failures.push(format!("decode {charset} {b}: {actual:?} != {:?}", text(&v["text"])));
            }
        }
        assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn charset_names_resolve_as_java_does() {
        assert_eq!(super::canonical_charset("CP1252"), Some("windows-1252"));
        assert_eq!(super::canonical_charset(" latin1 "), Some("iso-8859-1"));
        assert_eq!(super::canonical_charset("x-sjis"), Some("shift_jis"));
        assert_eq!(super::canonical_charset("ISO-2022-JP"), None);
        assert_eq!(super::canonical_charset("nope-1"), None);
    }
}
