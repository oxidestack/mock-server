//! XSD simple types: the built-in datatype hierarchy, facets and value validation, failing on the first error with
//! Xerces' message (`XSSimpleTypeDecl.getActualValue` then `checkFacets`).

use std::cmp::Ordering;

use base64::Engine;

use super::{Schema, TypeId};

pub const XS: &str = "http://www.w3.org/2001/XMLSchema";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhiteSpace {
    Preserve,
    Replace,
    Collapse,
}

/// Xerces' `SPECIAL_PATTERN_*`: the name checks of `NMTOKEN`, `Name` and `NCName`, reported as datatype errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Special {
    NmToken,
    Name,
    NcName,
}

/// The datatype validator (`fDVs[fValidationDV]`) a type's values are read with; its name is the one
/// `cvc-datatype-valid.1.2.1` cites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dv {
    AnySimple,
    String,
    Boolean,
    Decimal,
    Integer,
    Float,
    Double,
    Duration,
    DateTime,
    Time,
    Date,
    GYearMonth,
    GYear,
    GMonthDay,
    GDay,
    GMonth,
    HexBinary,
    Base64Binary,
    AnyUri,
    QName,
    Notation,
}

impl Dv {
    fn name(self) -> &'static str {
        match self {
            Dv::AnySimple => "anySimpleType",
            Dv::String => "string",
            Dv::Boolean => "boolean",
            Dv::Decimal => "decimal",
            Dv::Integer => "integer",
            Dv::Float => "float",
            Dv::Double => "double",
            Dv::Duration => "duration",
            Dv::DateTime => "dateTime",
            Dv::Time => "time",
            Dv::Date => "date",
            Dv::GYearMonth => "gYearMonth",
            Dv::GYear => "gYear",
            Dv::GMonthDay => "gMonthDay",
            Dv::GDay => "gDay",
            Dv::GMonth => "gMonth",
            Dv::HexBinary => "hexBinary",
            Dv::Base64Binary => "base64Binary",
            Dv::AnyUri => "anyURI",
            Dv::QName => "QName",
            Dv::Notation => "NOTATION",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Facets {
    pub white_space: Option<WhiteSpace>,
    /// One level's patterns (alternatives), as written and compiled.
    pub patterns: Vec<(String, regex::Regex)>,
    pub enumeration: Option<Vec<String>>,
    pub length: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub total_digits: Option<usize>,
    pub fraction_digits: Option<usize>,
    pub max_inclusive: Option<String>,
    pub max_exclusive: Option<String>,
    pub min_inclusive: Option<String>,
    pub min_exclusive: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Variety {
    Atomic,
    List(TypeId),
    Union(Vec<TypeId>),
}

#[derive(Debug, Clone)]
pub struct SimpleType {
    /// `fTypeName`: the declared name, `#AnonType_…` for an anonymous type.
    pub name: String,
    pub base: Option<TypeId>,
    pub variety: Variety,
    pub facets: Facets,
    /// Set on the built-ins that define a datatype validator or a special name check.
    pub dv: Option<Dv>,
    pub special: Option<Special>,
}

/// Registers the built-in simple types (and `anyType`), returning their ids by local name.
pub fn builtins(schema: &mut Schema) {
    use Dv::*;
    let add = |schema: &mut Schema, name: &str, base: Option<&str>, dv: Option<Dv>, facets: Facets| {
        let base = base.map(|b| schema.builtin(b));
        let id = schema.push_simple(SimpleType { name: name.into(), base, variety: Variety::Atomic, facets, dv, special: None });
        schema.global_types.insert((XS.into(), name.into()), id);
        id
    };
    let collapse = || Facets { white_space: Some(WhiteSpace::Collapse), ..Facets::default() };
    let range = |min: &str, max: &str| Facets { min_inclusive: Some(min.into()), max_inclusive: Some(max.into()), ..Facets::default() };
    add(schema, "anySimpleType", None, Some(AnySimple), collapse());
    add(schema, "string", Some("anySimpleType"), Some(String), Facets { white_space: Some(WhiteSpace::Preserve), ..Facets::default() });
    add(schema, "normalizedString", Some("string"), None, Facets { white_space: Some(WhiteSpace::Replace), ..Facets::default() });
    add(schema, "token", Some("normalizedString"), None, collapse());
    add(schema, "language", Some("token"), None, Facets { patterns: vec![pattern("([a-zA-Z]{1,8})(-[a-zA-Z0-9]{1,8})*").expect("valid")], ..Facets::default() });
    let nmtoken = add(schema, "NMTOKEN", Some("token"), None, Facets::default());
    schema.simple_mut(nmtoken).special = Some(Special::NmToken);
    let name = add(schema, "Name", Some("token"), None, Facets::default());
    schema.simple_mut(name).special = Some(Special::Name);
    let ncname = add(schema, "NCName", Some("Name"), None, Facets::default());
    schema.simple_mut(ncname).special = Some(Special::NcName);
    for n in ["ID", "IDREF", "ENTITY"] {
        add(schema, n, Some("NCName"), None, Facets::default());
    }
    for (list, item) in [("NMTOKENS", "NMTOKEN"), ("IDREFS", "IDREF"), ("ENTITIES", "ENTITY")] {
        let item = schema.builtin(item);
        let base = schema.builtin("anySimpleType");
        let id = schema.push_simple(SimpleType {
            name: list.into(),
            base: Some(base),
            variety: Variety::List(item),
            facets: Facets { min_length: Some(1), ..Facets::default() },
            dv: None,
            special: None,
        });
        schema.global_types.insert((XS.into(), list.into()), id);
    }
    add(schema, "boolean", Some("anySimpleType"), Some(Boolean), collapse());
    add(schema, "decimal", Some("anySimpleType"), Some(Decimal), collapse());
    add(schema, "integer", Some("decimal"), Some(Integer), Facets { fraction_digits: Some(0), ..Facets::default() });
    add(schema, "nonPositiveInteger", Some("integer"), None, Facets { max_inclusive: Some("0".into()), ..Facets::default() });
    add(schema, "negativeInteger", Some("nonPositiveInteger"), None, Facets { max_inclusive: Some("-1".into()), ..Facets::default() });
    add(schema, "long", Some("integer"), None, range("-9223372036854775808", "9223372036854775807"));
    add(schema, "int", Some("long"), None, range("-2147483648", "2147483647"));
    add(schema, "short", Some("int"), None, range("-32768", "32767"));
    add(schema, "byte", Some("short"), None, range("-128", "127"));
    add(schema, "nonNegativeInteger", Some("integer"), None, Facets { min_inclusive: Some("0".into()), ..Facets::default() });
    add(schema, "unsignedLong", Some("nonNegativeInteger"), None, Facets { max_inclusive: Some("18446744073709551615".into()), ..Facets::default() });
    add(schema, "unsignedInt", Some("unsignedLong"), None, Facets { max_inclusive: Some("4294967295".into()), ..Facets::default() });
    add(schema, "unsignedShort", Some("unsignedInt"), None, Facets { max_inclusive: Some("65535".into()), ..Facets::default() });
    add(schema, "unsignedByte", Some("unsignedShort"), None, Facets { max_inclusive: Some("255".into()), ..Facets::default() });
    add(schema, "positiveInteger", Some("nonNegativeInteger"), None, Facets { min_inclusive: Some("1".into()), ..Facets::default() });
    for (n, dv) in [
        ("float", Float),
        ("double", Double),
        ("duration", Duration),
        ("dateTime", DateTime),
        ("time", Time),
        ("date", Date),
        ("gYearMonth", GYearMonth),
        ("gYear", GYear),
        ("gMonthDay", GMonthDay),
        ("gDay", GDay),
        ("gMonth", GMonth),
        ("hexBinary", HexBinary),
        ("base64Binary", Base64Binary),
        ("anyURI", AnyUri),
        ("QName", QName),
        ("NOTATION", Notation),
    ] {
        add(schema, n, Some("anySimpleType"), Some(dv), collapse());
    }
}

/// An XSD regular expression, implicitly anchored, translated to the `regex` crate's dialect.
pub fn pattern(xsd: &str) -> Result<(String, regex::Regex), String> {
    const NAME_START: &str = r"_:A-Za-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}";
    const NAME_REST: &str = r"\-.0-9\x{B7}\x{300}-\x{36F}\x{203F}-\x{2040}";
    let mut out = String::from("^(?:");
    let mut chars = xsd.chars().peekable();
    let mut depth = 0usize;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(e) = chars.next() else { return Err(format!("invalid pattern {xsd}")) };
                match e {
                    'i' if depth > 0 => out.push_str(NAME_START),
                    'i' => out.push_str(&format!("[{NAME_START}]")),
                    'c' if depth > 0 => out.push_str(&format!("{NAME_START}{NAME_REST}")),
                    'c' => out.push_str(&format!("[{NAME_START}{NAME_REST}]")),
                    'I' => out.push_str(&format!("[^{NAME_START}]")),
                    'C' => out.push_str(&format!("[^{NAME_START}{NAME_REST}]")),
                    'w' if depth > 0 => out.push_str(r"\p{L}\p{M}\p{N}\p{S}"),
                    'w' => out.push_str(r"[\p{L}\p{M}\p{N}\p{S}]"),
                    'W' => out.push_str(r"[\p{P}\p{Z}\p{C}]"),
                    // A block, which the `regex` crate does not name: its ranges.
                    'p' | 'P' if chars.peek() == Some(&'{') => {
                        let name: String = chars.by_ref().skip(1).take_while(|c| *c != '}').collect();
                        match super::regex_syntax::block(&name) {
                            Some(ranges) => {
                                let set: String = ranges.iter().map(|(a, b)| format!("\\x{{{a:X}}}-\\x{{{b:X}}}")).collect();
                                out.push_str(&format!("[{}{set}]", if e == 'P' { "^" } else { "" }));
                            }
                            None => out.push_str(&format!("\\{e}{{{name}}}")),
                        }
                    }
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            // `(?#…)`, a comment.
            '(' if depth == 0 && {
                let mut ahead = chars.clone();
                ahead.next() == Some('?') && ahead.next() == Some('#')
            } => {
                for c in chars.by_ref() {
                    if c == ')' {
                        break;
                    }
                }
            }
            '[' => {
                if depth > 0 && out.ends_with('-') {
                    // Character class subtraction: `[a-z-[aeiou]]`.
                    out.push_str("-[");
                } else {
                    out.push('[');
                }
                depth += 1;
                if chars.peek() == Some(&'^') {
                    out.push(chars.next().expect("peeked"));
                }
            }
            ']' if depth > 0 => {
                depth -= 1;
                out.push(']');
            }
            '.' if depth == 0 => out.push_str(r"[^\n\r]"),
            '$' | '^' if depth == 0 => {
                out.push('\\');
                out.push(c);
            }
            '&' | '~' if depth > 0 => {
                out.push('\\');
                out.push(c);
            }
            other => out.push(other),
        }
    }
    out.push_str(")$");
    regex::Regex::new(&out).map(|r| (xsd.to_string(), r)).map_err(|e| format!("invalid pattern {xsd}: {e}"))
}

pub fn normalize(value: &str, ws: WhiteSpace) -> String {
    match ws {
        WhiteSpace::Preserve => value.to_string(),
        WhiteSpace::Replace => value.chars().map(|c| if matches!(c, '\t' | '\n' | '\r') { ' ' } else { c }).collect(),
        WhiteSpace::Collapse => value.split([' ', '\t', '\n', '\r']).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "),
    }
}

fn is_name_start(c: char) -> bool {
    matches!(c, ':' | '_' | 'A'..='Z' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}'
        | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

pub fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| is_name_start(c) && c != ':') && chars.all(|c| is_name_char(c) && c != ':')
}

fn special_matches(special: Special, s: &str) -> bool {
    match special {
        Special::NmToken => !s.is_empty() && s.chars().all(is_name_char),
        Special::Name => s.chars().next().is_some_and(is_name_start) && s.chars().all(is_name_char),
        Special::NcName => is_ncname(s),
    }
}

/// A decimal in value space: sign, integer digits without leading zeros, fraction digits without trailing zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decimal {
    negative: bool,
    int: String,
    frac: String,
}

impl Decimal {
    fn parse(s: &str, integer: bool) -> Option<Decimal> {
        let (negative, digits) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let (int, frac) = match digits.split_once('.') {
            Some(_) if integer => return None,
            Some((i, f)) => (i, f),
            None => (digits, ""),
        };
        if (int.is_empty() && frac.is_empty()) || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) || (integer && int.is_empty()) {
            return None;
        }
        let int = int.trim_start_matches('0').to_string();
        let frac = frac.trim_end_matches('0').to_string();
        let zero = int.is_empty() && frac.is_empty();
        Some(Decimal { negative: negative && !zero, int, frac })
    }

    fn cmp(&self, other: &Decimal) -> Ordering {
        let magnitude = |a: &Decimal, b: &Decimal| {
            a.int.len().cmp(&b.int.len()).then_with(|| a.int.cmp(&b.int)).then_with(|| {
                let width = a.frac.len().max(b.frac.len());
                format!("{:0<width$}", a.frac).cmp(&format!("{:0<width$}", b.frac))
            })
        };
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => magnitude(self, other),
            (true, true) => magnitude(other, self),
        }
    }

    fn total_digits(&self) -> usize {
        (self.int.len() + self.frac.len()).max(1)
    }

    /// `XDecimal.toString`: the canonical form.
    fn canonical(&self, integer: bool) -> String {
        let int = if self.int.is_empty() { "0" } else { &self.int };
        let sign = if self.negative { "-" } else { "" };
        if integer || self.frac.is_empty() { format!("{sign}{int}") } else { format!("{sign}{int}.{}", self.frac) }
    }
}

fn parse_float(s: &str) -> Option<f64> {
    match s {
        "INF" => return Some(f64::INFINITY),
        "-INF" => return Some(f64::NEG_INFINITY),
        "NaN" => return Some(f64::NAN),
        _ => {}
    }
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits_ok = !(int.is_empty() && frac.is_empty()) && int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit());
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit())
    });
    (digits_ok && exponent_ok).then(|| s.parse::<f64>().ok()).flatten()
}

/// The lexical space of the date, time and duration datatypes.
fn dated(dv: Dv) -> Option<&'static regex::Regex> {
    use std::sync::LazyLock;
    const TZ: &str = r"(Z|[+-]((0\d|1[0-3]):[0-5]\d|14:00))?";
    const YEAR: &str = r"-?(\d{4}|[1-9]\d{4,})";
    const TIME: &str = r"(([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?|24:00:00(\.0+)?)";
    fn compile(body: String) -> regex::Regex {
        regex::Regex::new(&format!("^{body}$")).expect("valid")
    }
    static DURATION: LazyLock<regex::Regex> =
        LazyLock::new(|| compile(r"-?P(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?".into()));
    static DATE_TIME: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"{YEAR}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T{TIME}{TZ}")));
    static TIME_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!("{TIME}{TZ}")));
    static DATE: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"{YEAR}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]){TZ}")));
    static G_YEAR_MONTH: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"{YEAR}-(0[1-9]|1[0-2]){TZ}")));
    static G_YEAR: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!("{YEAR}{TZ}")));
    static G_MONTH_DAY: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"--(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]){TZ}")));
    static G_DAY: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"---(0[1-9]|[12]\d|3[01]){TZ}")));
    static G_MONTH: LazyLock<regex::Regex> = LazyLock::new(|| compile(format!(r"--(0[1-9]|1[0-2]){TZ}")));
    Some(match dv {
        Dv::Duration => &DURATION,
        Dv::DateTime => &DATE_TIME,
        Dv::Time => &TIME_ONLY,
        Dv::Date => &DATE,
        Dv::GYearMonth => &G_YEAR_MONTH,
        Dv::GYear => &G_YEAR,
        Dv::GMonthDay => &G_MONTH_DAY,
        Dv::GDay => &G_DAY,
        Dv::GMonth => &G_MONTH,
        _ => return None,
    })
}

fn lexical_ok(dv: Dv, value: &str) -> bool {
    match dv {
        Dv::AnySimple | Dv::String | Dv::AnyUri | Dv::Notation => true,
        Dv::Boolean => matches!(value, "true" | "false" | "1" | "0"),
        Dv::Decimal => Decimal::parse(value, false).is_some(),
        Dv::Integer => Decimal::parse(value, true).is_some(),
        Dv::Float | Dv::Double => parse_float(value).is_some(),
        Dv::HexBinary => value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit()),
        Dv::Base64Binary => {
            let compact: String = value.chars().filter(|c| *c != ' ').collect();
            base64::engine::general_purpose::STANDARD.decode(compact).is_ok()
        }
        Dv::QName => match value.split_once(':') {
            Some((p, l)) => is_ncname(p) && is_ncname(l),
            None => is_ncname(value),
        },
        Dv::Duration => {
            !matches!(value, "P" | "-P") && !value.ends_with('T') && dated(dv).is_some_and(|r| r.is_match(value))
        }
        _ => dated(dv).is_some_and(|r| r.is_match(value)),
    }
}

/// `getDataLength`: characters, octets, or `-1` where length facets do not apply.
fn data_length(dv: Dv, value: &str) -> Option<usize> {
    match dv {
        Dv::String | Dv::AnyUri | Dv::AnySimple => Some(value.chars().count()),
        Dv::HexBinary => Some(value.len() / 2),
        Dv::Base64Binary => {
            let compact: String = value.chars().filter(|c| *c != ' ').collect();
            base64::engine::general_purpose::STANDARD.decode(compact).ok().map(|b| b.len())
        }
        _ => None,
    }
}

/// `compare`: `None` when the values are incomparable (NaN, or a datatype without an order).
fn compare(dv: Dv, a: &str, b: &str) -> Option<Ordering> {
    match dv {
        Dv::Decimal | Dv::Integer => Some(Decimal::parse(a, false)?.cmp(&Decimal::parse(b, false)?)),
        Dv::Float | Dv::Double => parse_float(a)?.partial_cmp(&parse_float(b)?),
        Dv::DateTime | Dv::Date | Dv::Time | Dv::GYearMonth | Dv::GYear | Dv::GMonthDay | Dv::GDay | Dv::GMonth | Dv::Duration => Some(a.cmp(b)),
        _ => None,
    }
}

/// Equality in value space, for enumerations.
fn equal(dv: Dv, a: &str, b: &str) -> bool {
    match dv {
        Dv::Decimal | Dv::Integer | Dv::Float | Dv::Double => compare(dv, a, b) == Some(Ordering::Equal),
        Dv::Boolean => matches!(a, "true" | "1") == matches!(b, "true" | "1"),
        _ => a == b,
    }
}

/// How an enumeration value prints in `cvc-enumeration-valid` (its actual value's `toString`).
fn enumeration_text(dv: Dv, value: &str) -> String {
    match dv {
        Dv::Decimal | Dv::Integer => Decimal::parse(value, false).map(|d| d.canonical(dv == Dv::Integer)).unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

impl Schema {
    /// The first built-in ancestor's datatype validator and name check.
    pub(super) fn atomic_dv(&self, id: TypeId) -> (Dv, Option<Special>) {
        let mut special = None;
        let mut current = Some(id);
        while let Some(t) = current {
            let st = self.simple(t);
            special = special.or(st.special);
            if let Some(dv) = st.dv {
                return (dv, special);
            }
            current = st.base;
        }
        (Dv::AnySimple, special)
    }

    /// Facets in effect for `id`: the nearest definition of each, every level's patterns.
    pub(super) fn effective(&self, id: TypeId) -> (Facets, Vec<Vec<(String, regex::Regex)>>) {
        let mut out = Facets::default();
        let mut patterns = Vec::new();
        let mut current = Some(id);
        while let Some(t) = current {
            let f = &self.simple(t).facets;
            macro_rules! inherit {
                ($($field:ident),*) => { $( if out.$field.is_none() { out.$field = f.$field.clone(); } )* };
            }
            inherit!(white_space, enumeration, length, min_length, max_length, total_digits, fraction_digits, max_inclusive, max_exclusive, min_inclusive, min_exclusive);
            if !f.patterns.is_empty() {
                patterns.push(f.patterns.clone());
            }
            current = self.simple(t).base;
        }
        (out, patterns)
    }

    pub fn white_space(&self, id: TypeId) -> WhiteSpace {
        match self.simple(id).variety {
            Variety::Atomic => self.effective(id).0.white_space.unwrap_or(WhiteSpace::Collapse),
            _ => WhiteSpace::Collapse,
        }
    }

    /// Validates `raw` against simple type `id`, returning its normalised value or Xerces' first error.
    pub fn validate_simple(&self, id: TypeId, raw: &str, qname_prefix_bound: &dyn Fn(&str) -> bool) -> Result<String, String> {
        let st = self.simple(id);
        let (facets, patterns) = self.effective(id);
        let ws = match st.variety {
            Variety::Atomic => facets.white_space.unwrap_or(WhiteSpace::Collapse),
            _ => WhiteSpace::Collapse,
        };
        let value = normalize(raw, ws);
        // Most derived patterns first (`fPattern` is walked from its end).
        for level in &patterns {
            if !level.iter().any(|(_, r)| r.is_match(&value)) {
                let text = level.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>().join("|");
                return Err(format!("cvc-pattern-valid: Value '{value}' is not facet-valid with respect to pattern '{text}' for type '{}'.", st.name));
            }
        }
        let mut dv = Dv::String;
        let mut length = None;
        match &st.variety {
            Variety::Atomic => {
                let (atomic, special) = self.atomic_dv(id);
                dv = atomic;
                if let Some(special) = special.filter(|s| !special_matches(*s, &value)) {
                    let name = match special {
                        Special::NmToken => "NMTOKEN",
                        Special::Name => "Name",
                        Special::NcName => "NCName",
                    };
                    return Err(format!("cvc-datatype-valid.1.2.1: '{value}' is not a valid value for '{name}'."));
                }
                if !lexical_ok(dv, &value) {
                    return Err(format!("cvc-datatype-valid.1.2.1: '{value}' is not a valid value for '{}'.", dv.name()));
                }
                if dv == Dv::QName && let Some((prefix, _)) = value.split_once(':').filter(|(p, _)| !qname_prefix_bound(p)) {
                    return Err(format!("UndeclaredPrefix: Cannot resolve '{value}' as a QName: the prefix '{prefix}' is not declared."));
                }
                length = data_length(dv, &value);
            }
            Variety::List(item) => {
                for token in value.split(' ').filter(|t| !t.is_empty()) {
                    self.validate_simple(*item, token, qname_prefix_bound)?;
                }
                length = Some(value.split(' ').filter(|t| !t.is_empty()).count());
            }
            Variety::Union(members) => {
                match members.iter().find(|m| self.validate_simple(**m, &value, qname_prefix_bound).is_ok()) {
                    Some(m) => dv = self.atomic_dv(*m).0,
                    None => return Err(format!("cvc-datatype-valid.1.2.3: '{value}' is not a valid value of union type '{}'.", st.name)),
                }
            }
        }
        if let Some(length) = length {
            if let Some(max) = facets.max_length.filter(|m| length > *m) {
                return Err(format!("cvc-maxLength-valid: Value '{value}' with length = '{length}' is not facet-valid with respect to maxLength '{max}' for type '{}'.", st.name));
            }
            if let Some(min) = facets.min_length.filter(|m| length < *m) {
                return Err(format!("cvc-minLength-valid: Value '{value}' with length = '{length}' is not facet-valid with respect to minLength '{min}' for type '{}'.", st.name));
            }
            if let Some(exact) = facets.length.filter(|m| length != *m) {
                return Err(format!("cvc-length-valid: Value '{value}' with length = '{length}' is not facet-valid with respect to length '{exact}' for type '{}'.", st.name));
            }
        }
        if let Some(values) = &facets.enumeration && !values.iter().any(|e| equal(dv, &normalize(e, ws), &value)) {
            let list = values.iter().map(|e| enumeration_text(dv, e)).collect::<Vec<_>>().join(", ");
            return Err(format!("cvc-enumeration-valid: Value '{value}' is not facet-valid with respect to enumeration '[{list}]'. It must be a value from the enumeration."));
        }
        if matches!(dv, Dv::Decimal | Dv::Integer) {
            let decimal = Decimal::parse(&value, false).expect("lexically valid");
            if let Some(limit) = facets.fraction_digits.filter(|f| decimal.frac.len() > *f && dv == Dv::Decimal) {
                return Err(format!(
                    "cvc-fractionDigits-valid: Value '{value}' has {} fraction digits, but the number of fraction digits has been limited to {limit}.",
                    decimal.frac.len()
                ));
            }
            if let Some(limit) = facets.total_digits.filter(|t| decimal.total_digits() > *t) {
                return Err(format!(
                    "cvc-totalDigits-valid: Value '{value}' has {} total digits, but the number of total digits has been limited to {limit}.",
                    decimal.total_digits()
                ));
            }
        }
        let bound = |facet: &Option<String>, name: &str, ok: fn(Ordering) -> bool| -> Result<(), String> {
            match facet {
                Some(limit) if !compare(dv, &value, limit).is_some_and(ok) => {
                    Err(format!("cvc-{name}-valid: Value '{value}' is not facet-valid with respect to {name} '{limit}' for type '{}'.", st.name))
                }
                _ => Ok(()),
            }
        };
        bound(&facets.max_inclusive, "maxInclusive", |o| o != Ordering::Greater)?;
        bound(&facets.max_exclusive, "maxExclusive", |o| o == Ordering::Less)?;
        bound(&facets.min_inclusive, "minInclusive", |o| o != Ordering::Less)?;
        bound(&facets.min_exclusive, "minExclusive", |o| o == Ordering::Greater)?;
        Ok(value)
    }

    /// Whether `id` is (derived from) the built-in type `name`.
    pub fn derives_from(&self, id: TypeId, name: &str) -> bool {
        let target = self.global_types.get(&(XS.to_string(), name.to_string())).copied();
        let mut current = Some(id);
        while let Some(t) = current {
            if Some(t) == target {
                return true;
            }
            current = match &self.types[t] {
                super::Type::Simple(s) => s.base,
                super::Type::Complex(_) => None,
            };
        }
        false
    }
}

/// `XDouble.toString` / `XFloat.toString`: `d.dddEn` from the shortest round-tripping digits.
fn float_canonical(v: f64, single: bool) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "INF".into() } else { "-INF".into() };
    }
    if v == 0.0 {
        return "0.0E1".into();
    }
    let e = if single { format!("{:e}", v as f32) } else { format!("{v:e}") };
    let (mantissa, exponent) = e.split_once('e').expect("exponent form");
    let mantissa = if mantissa.contains('.') { mantissa.to_string() } else { format!("{mantissa}.0") };
    format!("{mantissa}E{exponent}")
}

/// A `dateTime` or `time` with a timezone, normalised to UTC (`Z`); others as written.
fn date_canonical(dv: Dv, value: &str) -> String {
    let (body, offset) = if let Some(b) = value.strip_suffix('Z') {
        (b, Some(0i64))
    } else if value.len() > 6 && matches!(&value[value.len() - 6..value.len() - 5], "+" | "-") && &value[value.len() - 3..value.len() - 2] == ":" {
        let tz = &value[value.len() - 6..];
        let minutes = tz[1..3].parse::<i64>().unwrap_or(0) * 60 + tz[4..6].parse::<i64>().unwrap_or(0);
        (&value[..value.len() - 6], Some(if tz.starts_with('-') { -minutes } else { minutes }))
    } else {
        (value, None)
    };
    let Some(offset) = offset else { return value.to_string() };
    let (date, time) = match dv {
        Dv::DateTime => match body.split_once('T') {
            Some((d, t)) => (Some(d), t),
            None => return value.to_string(),
        },
        Dv::Time => (None, body),
        _ => return value.to_string(),
    };
    let (hms, fraction) = match time.split_once('.') {
        Some((h, f)) => (h, Some(f)),
        None => (time, None),
    };
    let parts: Vec<i64> = hms.split(':').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 3 {
        return value.to_string();
    }
    let mut minutes = parts[0] * 60 + parts[1] - offset;
    let mut day_shift = 0i64;
    while minutes < 0 {
        minutes += 1440;
        day_shift -= 1;
    }
    while minutes >= 1440 {
        minutes -= 1440;
        day_shift += 1;
    }
    let time_text = format!("{:02}:{:02}:{:02}{}", minutes / 60, minutes % 60, parts[2], fraction.map(|f| format!(".{f}")).unwrap_or_default());
    let Some(date) = date else { return format!("{time_text}Z") };
    let (negative, digits) = match date.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, date),
    };
    let ymd: Vec<i64> = digits.split('-').filter_map(|p| p.parse().ok()).collect();
    if ymd.len() != 3 {
        return value.to_string();
    }
    let (mut year, mut month, mut day) = (if negative { -ymd[0] } else { ymd[0] }, ymd[1], ymd[2] + day_shift);
    let days_in = |y: i64, m: i64| match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 {
        month -= 1;
        if month < 1 {
            month = 12;
            year -= 1;
        }
        day = days_in(year, month);
    } else if day > days_in(year, month) {
        day = 1;
        month += 1;
        if month > 12 {
            month = 1;
            year += 1;
        }
    }
    let year_text = if year < 0 { format!("-{:04}", -year) } else { format!("{year:04}") };
    format!("{year_text}-{month:02}-{day:02}T{time_text}Z")
}

/// A duration's value (months and seconds) and `DurationDV`'s printing of it.
fn duration_value(value: &str) -> (String, String) {
    let negative = value.starts_with('-');
    let body = value.trim_start_matches('-').trim_start_matches('P');
    let (date, time) = body.split_once('T').unwrap_or((body, ""));
    let mut fields = [String::from("0"), "0".into(), "0".into(), "0".into(), "0".into(), "0".into()];
    let mut read = |text: &str, units: &[(char, usize)]| {
        let mut number = String::new();
        for c in text.chars() {
            if c.is_ascii_digit() || c == '.' {
                number.push(c);
            } else if let Some((_, i)) = units.iter().find(|(u, _)| *u == c) {
                fields[*i] = std::mem::take(&mut number);
            }
        }
    };
    read(date, &[('Y', 0), ('M', 1), ('D', 2)]);
    read(time, &[('H', 3), ('M', 4), ('S', 5)]);
    let int = |s: &str| s.parse::<i128>().unwrap_or(0);
    let months = int(&fields[0]) * 12 + int(&fields[1]);
    let seconds = Decimal::parse(&fields[5], false).unwrap_or(Decimal { negative: false, int: String::new(), frac: String::new() });
    let whole = (int(&fields[2]) * 86400 + int(&fields[3]) * 3600 + int(&fields[4]) * 60) + int(if seconds.int.is_empty() { "0" } else { &seconds.int });
    let sign = if negative { "-" } else { "" };
    let key = format!("{sign}{months}|{whole}.{}", seconds.frac);
    let secs = seconds.canonical(seconds.frac.is_empty());
    let display = format!("{sign}P{}Y{}M{}DT{}H{}M{secs}S", int(&fields[0]), int(&fields[1]), int(&fields[2]), int(&fields[3]), int(&fields[4]));
    (key, display)
}

impl Schema {
    /// The actual value of a valid normalised `value` of simple type `id`, as an identity-constraint field holds it.
    pub fn ic_value(&self, id: TypeId, value: &str, resolve: &dyn Fn(Option<&str>) -> Option<String>) -> super::identity::Value {
        use super::identity::Value;
        let bound = |p: &str| resolve(Some(p)).is_some();
        match &self.simple(id).variety {
            Variety::List(item) => {
                let items: Vec<Value> = value.split(' ').filter(|t| !t.is_empty()).map(|t| self.ic_value(*item, t, resolve)).collect();
                Value {
                    kind: format!("list({})", items.iter().map(|v| v.kind.as_str()).collect::<Vec<_>>().join(",")),
                    key: items.iter().map(|v| v.key.as_str()).collect::<Vec<_>>().join("\u{0}"),
                    display: items.iter().map(|v| v.display.as_str()).collect::<Vec<_>>().join(" "),
                }
            }
            Variety::Union(members) => match members.iter().find(|m| self.validate_simple(**m, value, &bound).is_ok()) {
                Some(m) => {
                    let normalized = self.validate_simple(*m, value, &bound).unwrap_or_else(|_| value.to_string());
                    self.ic_value(*m, &normalized, resolve)
                }
                None => Value { kind: "anySimpleType".into(), key: value.into(), display: value.into() },
            },
            Variety::Atomic => {
                let dv = self.atomic_dv(id).0;
                let plain = |kind: &str| Value { kind: kind.into(), key: value.into(), display: value.into() };
                match dv {
                    Dv::Decimal | Dv::Integer => match Decimal::parse(value, false) {
                        Some(d) => {
                            let int = if d.int.is_empty() { "0" } else { &d.int };
                            let sign = if d.negative { "-" } else { "" };
                            let display = if dv == Dv::Integer { d.canonical(true) } else { format!("{sign}{int}.{}", if d.frac.is_empty() { "0" } else { &d.frac }) };
                            Value { kind: "decimal".into(), key: format!("{sign}{int}.{}", d.frac), display }
                        }
                        None => plain("decimal"),
                    },
                    Dv::Float | Dv::Double => match parse_float(value) {
                        Some(v) => {
                            let single = dv == Dv::Float;
                            let v = if single { v as f32 as f64 } else { v };
                            let key = if v.is_nan() { "NaN".into() } else if v == 0.0 { "0".into() } else { format!("{v:e}") };
                            Value { kind: dv.name().into(), key, display: float_canonical(v, single) }
                        }
                        None => plain(dv.name()),
                    },
                    Dv::Boolean => {
                        let b = matches!(value, "true" | "1").to_string();
                        Value { kind: "boolean".into(), key: b.clone(), display: b }
                    }
                    Dv::HexBinary => {
                        let upper = value.to_ascii_uppercase();
                        Value { kind: "hexBinary".into(), key: upper.clone(), display: upper }
                    }
                    Dv::Base64Binary => {
                        let compact: String = value.chars().filter(|c| *c != ' ').collect();
                        let engine = base64::engine::general_purpose::STANDARD;
                        let bytes = engine.decode(&compact).unwrap_or_default();
                        Value { kind: "base64Binary".into(), key: bytes.iter().map(|b| format!("{b:02x}")).collect(), display: engine.encode(&bytes) }
                    }
                    Dv::DateTime | Dv::Time => {
                        let canonical = date_canonical(dv, value);
                        Value { kind: dv.name().into(), key: canonical.clone(), display: canonical }
                    }
                    Dv::Duration => {
                        let (key, display) = duration_value(value);
                        Value { kind: "duration".into(), key, display }
                    }
                    Dv::QName => {
                        let (prefix, local) = match value.split_once(':') {
                            Some((p, l)) => (Some(p), l),
                            None => (None, value),
                        };
                        let ns = resolve(prefix).unwrap_or_default();
                        Value { kind: "QName".into(), key: format!("{{{ns}}}{local}"), display: value.into() }
                    }
                    other => plain(other.name()),
                }
            }
        }
    }
}

impl Schema {
    /// The facet checks of a restriction of `base` named `name` with facets `own` (`XSSimpleTypeDecl.applyFacets`),
    /// in Xerces' order: each facet's applicability and value (bounds and enumerations are values of the base),
    /// then the facets given here against each other, then against the base's.
    pub(super) fn check_restriction(&self, name: &str, base: TypeId, own: &Facets, written: &[&str]) -> Result<(), String> {
        let bound = |_: &str| true;
        let st = self.simple(base);
        let dv = match st.variety {
            Variety::Atomic => Some(self.atomic_dv(base).0),
            _ => None,
        };
        let applicable: &[&str] = match (&st.variety, dv) {
            (Variety::List(_), _) => &["length", "minLength", "maxLength", "pattern", "enumeration", "whiteSpace"],
            (Variety::Union(_), _) => &["pattern", "enumeration"],
            (_, Some(Dv::String | Dv::AnyUri | Dv::QName | Dv::Notation | Dv::HexBinary | Dv::Base64Binary)) => {
                &["length", "minLength", "maxLength", "pattern", "enumeration", "whiteSpace"]
            }
            (_, Some(Dv::Boolean)) => &["pattern", "whiteSpace"],
            (_, Some(Dv::Decimal | Dv::Integer)) => {
                &["totalDigits", "fractionDigits", "pattern", "whiteSpace", "enumeration", "maxInclusive", "maxExclusive", "minInclusive", "minExclusive"]
            }
            (_, Some(Dv::AnySimple)) => &[],
            _ => &["pattern", "enumeration", "whiteSpace", "maxInclusive", "maxExclusive", "minInclusive", "minExclusive"],
        };
        // `anySimpleType` has no facets to be consistent with (the schema for schemas restricts it with any).
        if dv == Some(Dv::AnySimple) {
            return Ok(());
        }
        let (inherited, _) = self.effective(base);
        let base_name = if st.name.is_empty() || st.name.starts_with("#AnonType_") { "null" } else { &st.name };
        let cmp = |a: &str, b: &str| dv.and_then(|dv| compare(dv, a.trim(), b.trim()));
        let lexical = |value: &str| -> Result<(), String> {
            match dv.filter(|d| !lexical_ok(*d, value.trim())) {
                Some(dv) => Err(format!("cvc-datatype-valid.1.2.1: '{}' is not a valid value for '{}'.", value.trim(), dv.name())),
                None => Ok(()),
            }
        };
        const ORDER: [&str; 12] =
            ["length", "minLength", "maxLength", "pattern", "whiteSpace", "enumeration", "maxInclusive", "maxExclusive", "minExclusive", "minInclusive", "totalDigits", "fractionDigits"];
        for facet in ORDER.into_iter().filter(|f| written.contains(f)) {
            if !applicable.contains(&facet) {
                return Err(format!("cos-applicable-facets: Facet '{facet}' is not allowed by type {name}."));
            }
            match facet {
                "enumeration" => {
                    for value in own.enumeration.iter().flatten() {
                        if self.validate_simple(base, value, &bound).is_err() {
                            return Err(format!("enumeration-valid-restriction: Enumeration value '{value}' is not in the value space of the base type, {base_name}."));
                        }
                    }
                }
                "maxInclusive" | "minInclusive" => {
                    let value = if facet == "maxInclusive" { &own.max_inclusive } else { &own.min_inclusive };
                    let Some(value) = value else { continue };
                    lexical(value)?;
                    self.validate_simple(base, value, &bound)?;
                }
                "maxExclusive" | "minExclusive" => {
                    let max = facet == "maxExclusive";
                    let (value, same) = if max { (&own.max_exclusive, &inherited.max_exclusive) } else { (&own.min_exclusive, &inherited.min_exclusive) };
                    let Some(value) = value else { continue };
                    lexical(value)?;
                    // Equal to the base's own exclusive bound: not a value of the base, yet allowed.
                    if same.as_deref().is_some_and(|b| cmp(value, b) == Some(Ordering::Equal)) {
                        let (other, worse, key, what) = if max {
                            (&inherited.max_inclusive, Ordering::Greater, "maxExclusive-valid-restriction.2", "<= maxInclusive")
                        } else {
                            (&inherited.min_inclusive, Ordering::Less, "minExclusive-valid-restriction.3", ">= minInclusive")
                        };
                        if let Some(other) = other.as_deref().filter(|o| cmp(value, o) == Some(worse)) {
                            // Xerces passes no type name: MessageFormat leaves `{2}` as it is.
                            return Err(format!("{key}: Error for type '{{2}}'. The {facet} value ='{}' must be {what} of the base type '{}'.", value.trim(), other.trim()));
                        }
                    } else {
                        self.validate_simple(base, value, &bound)?;
                    }
                }
                _ => {}
            }
        }
        // The facets given here, against each other.
        if let (Some(min), Some(max)) = (own.min_length, own.max_length) && min > max {
            return Err(format!("minLength-less-than-equal-to-maxLength: In the definition of {name}, value of minLength = '{min}' must be < value of maxLength = '{max}'."));
        }
        if let (Some(i), Some(e)) = (&own.max_inclusive, &own.max_exclusive) {
            return Err(format!(
                "maxInclusive-maxExclusive: It is an error for both maxInclusive and maxExclusive to be specified for the same datatype. In {name}, maxInclusive = '{}' and maxExclusive = '{}'.",
                i.trim(),
                e.trim()
            ));
        }
        if let (Some(i), Some(e)) = (&own.min_inclusive, &own.min_exclusive) {
            return Err(format!(
                "minInclusive-minExclusive: It is an error for both minInclusive and minExclusive to be specified for the same datatype. In {name}, minInclusive = '{}' and minExclusive = '{}'.",
                i.trim(),
                e.trim()
            ));
        }
        // (lower facet, upper facet, the orderings that break them, the rule, its message)
        type Bounds<'a> = (&'a Option<String>, &'a Option<String>, &'a [Ordering], &'a str, &'a str);
        let pairs: [Bounds; 4] = [
            (&own.min_inclusive, &own.max_inclusive, &[Ordering::Greater], "minInclusive-less-than-equal-to-maxInclusive", "minInclusive value = '{0}' must be <= maxInclusive value = '{1}'"),
            (&own.min_exclusive, &own.max_exclusive, &[Ordering::Greater], "minExclusive-less-than-equal-to-maxExclusive", "minExclusive value = '{0}' must be <= maxExclusive value = '{1}'"),
            (&own.min_exclusive, &own.max_inclusive, &[Ordering::Greater, Ordering::Equal], "minExclusive-less-than-maxInclusive", "minExclusive value = '{0}' must be < maxInclusive value = '{1}'"),
            (&own.min_inclusive, &own.max_exclusive, &[Ordering::Greater, Ordering::Equal], "minInclusive-less-than-maxExclusive", "minInclusive value = '{0}' must be < maxExclusive value = '{1}'"),
        ];
        for (low, high, bad, code, text) in pairs {
            let (Some(low), Some(high)) = (low, high) else { continue };
            if cmp(low, high).is_some_and(|o| bad.contains(&o)) {
                return Err(format!("{code}: In the definition of {name}, {}.", text.replace("{0}", low.trim()).replace("{1}", high.trim())));
            }
        }
        if let (Some(fraction), Some(total)) = (own.fraction_digits, own.total_digits) && fraction > total {
            return Err(format!(
                "fractionDigits-totalDigits: In the definition of {name}, the value '{fraction}' for the facet 'fractionDigits' is invalid, because the value must be <= the value for 'totalDigits' which is '{total}'."
            ));
        }
        // Against the base's.
        if let Some(length) = own.length {
            if let Some(min) = inherited.min_length.filter(|m| length < *m) {
                return Err(format!("length-minLength-maxLength.1.1: For type {name}, it is an error for the value of length '{length}' to be less than the value of minLength '{min}'."));
            }
            if let Some(max) = inherited.max_length.filter(|m| length > *m) {
                return Err(format!("length-minLength-maxLength.2.1: For type {name}, it is an error for the value of length '{length}' to be greater than the value of maxLength '{max}'."));
            }
            if let Some(theirs) = inherited.length.filter(|l| *l != length) {
                return Err(format!("length-valid-restriction: Error for type '{name}'. The value of length = '{length}' must be = the value of that of the base type '{theirs}'."));
            }
        }
        if inherited.length.is_some() || own.length.is_some() {
            if let Some(min) = own.min_length {
                if let Some(theirs) = inherited.length.filter(|l| *l < min) {
                    return Err(format!("length-minLength-maxLength.1.1: For type {name}, it is an error for the value of length '{theirs}' to be less than the value of minLength '{min}'."));
                }
                if let Some(length) = own.length.filter(|l| *l < min) {
                    return Err(format!("length-minLength-maxLength.1.1: For type {name}, it is an error for the value of length '{length}' to be less than the value of minLength '{min}'."));
                }
                match inherited.min_length {
                    None => {
                        return Err(format!(
                            "length-minLength-maxLength.1.2.a: For type {name}, it is an error for the base to not have a minLength facet if the current restriction has the minLength facet and the current restriction or base has the length facet."
                        ));
                    }
                    Some(theirs) if theirs != min => {
                        return Err(format!("length-minLength-maxLength.1.2.b: For type {name}, it is an error for the current minLength '{min}' to not equal the base minLength '{theirs}'."));
                    }
                    _ => {}
                }
            }
            if let Some(max) = own.max_length {
                if let Some(theirs) = inherited.length.filter(|l| *l > max) {
                    return Err(format!("length-minLength-maxLength.2.1: For type {name}, it is an error for the value of length '{theirs}' to be greater than the value of maxLength '{max}'."));
                }
                if let Some(length) = own.length.filter(|l| *l > max) {
                    return Err(format!("length-minLength-maxLength.2.1: For type {name}, it is an error for the value of length '{length}' to be greater than the value of maxLength '{max}'."));
                }
                match inherited.max_length {
                    None => {
                        return Err(format!(
                            "length-minLength-maxLength.2.2.a: For type {name}, it is an error for the base to not have a maxLength facet if the current restriction has the maxLength facet and the current restriction or base has the length facet."
                        ));
                    }
                    Some(theirs) if theirs != max => {
                        return Err(format!("length-minLength-maxLength.2.2.b: For type {name}, it is an error for the current maxLength '{max}' to not equal the base maxLength '{theirs}'."));
                    }
                    _ => {}
                }
            }
        }
        if let Some(min) = own.min_length {
            match (inherited.max_length, inherited.min_length) {
                (Some(max), _) if min > max => {
                    return Err(format!("minLength-less-than-equal-to-maxLength: In the definition of {name}, value of minLength = '{min}' must be < value of maxLength = '{max}'."));
                }
                (Some(_), _) => {}
                (None, Some(theirs)) if min < theirs => {
                    return Err(format!("minLength-valid-restriction: In the definition of {name}, minLength = '{min}' must be >= than that of the base type, '{theirs}'."));
                }
                _ => {}
            }
        }
        if let (Some(max), Some(theirs)) = (own.max_length, inherited.min_length) && max < theirs {
            // Xerces passes no type name: MessageFormat leaves `{2}` as it is.
            return Err(format!("minLength-less-than-equal-to-maxLength: In the definition of {{2}}, value of minLength = '{theirs}' must be < value of maxLength = '{max}'."));
        }
        if let (Some(mine), Some(theirs)) = (own.max_length, inherited.max_length) && mine > theirs {
            return Err(format!("maxLength-valid-restriction: In the definition of {name}, maxLength value = '{mine}' must be <= that of the base type '{theirs}'."));
        }
        if let (Some(mine), Some(theirs)) = (own.total_digits, inherited.total_digits) && mine > theirs {
            return Err(format!(
                "totalDigits-valid-restriction: In the definition of {name}, the value '{mine}' for the facet 'totalDigits' is invalid, because it must be <= the value for 'totalDigits' which was set to '{theirs}' in one of the ancestor types."
            ));
        }
        if let (Some(fraction), Some(total)) = (own.fraction_digits, inherited.total_digits) && fraction > total {
            // The second value is this type's own totalDigits (`-1` when it has none).
            let own_total = own.total_digits.map_or("-1".to_string(), |t| t.to_string());
            return Err(format!(
                "fractionDigits-totalDigits: In the definition of {name}, the value '{fraction}' for the facet 'fractionDigits' is invalid, because the value must be <= the value for 'totalDigits' which is '{own_total}'."
            ));
        }
        if let (Some(mine), Some(theirs)) = (own.fraction_digits, inherited.fraction_digits) && mine > theirs {
            return Err(format!(
                "fractionDigits-valid-restriction: In the definition of {name}, the value '{mine}' for the facet 'fractionDigits' is invalid, because it must be <= the value for 'fractionDigits' which was set to '{theirs}' in one of the ancestor types."
            ));
        }
        if let (Some(mine), Some(theirs)) = (own.white_space, if st.variety_is_atomic() { inherited.white_space } else { Some(WhiteSpace::Collapse) }) {
            let text = |w: WhiteSpace| match w {
                WhiteSpace::Preserve => "preserve",
                WhiteSpace::Replace => "replace",
                WhiteSpace::Collapse => "collapse",
            };
            if theirs == WhiteSpace::Collapse && mine != WhiteSpace::Collapse {
                return Err(format!(
                    "whiteSpace-valid-restriction.1: In the definition of {name}, the value '{}' for the facet 'whitespace' is invalid, because the value for 'whitespace' has been set to 'collapse' in one of the ancestor types.",
                    text(mine)
                ));
            }
            if theirs == WhiteSpace::Replace && mine == WhiteSpace::Preserve {
                return Err(format!(
                    "whiteSpace-valid-restriction.2: In the definition of {name}, the value 'preserve' for the facet 'whitespace' is invalid, because the value for 'whitespace' has been set to 'replace' in one of the ancestor types."
                ));
            }
        }
        Ok(())
    }
}

impl SimpleType {
    fn variety_is_atomic(&self) -> bool {
        matches!(self.variety, Variety::Atomic)
    }
}
