//! `TemplateFunctions.BUILT_IN_FUNCTIONS` and `BUILT_IN_HELPERS`: what every template engine binds besides the
//! request.

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use java_compat::lang::{JError, JList, JObject, JValue};
use java_compat::methods::{as_f64, as_int};
use rand_core::{OsRng, RngCore};

type Invocation = Option<Result<Option<JValue>, JError>>;

fn ok(v: JValue) -> Invocation {
    Some(Ok(Some(v)))
}

fn text(v: &JValue) -> Option<String> {
    match v {
        JValue::Null => None,
        other => Some(other.to_java_string()),
    }
}

/// `DateTimeFormatter.ISO_INSTANT`: fractional seconds in groups of three digits, as needed.
pub fn iso_instant(t: DateTime<Utc>) -> String {
    let nanos = t.timestamp_subsec_nanos();
    let base = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!("{base}{fraction}Z")
}

/// `DateTimeFormatter.RFC_1123_DATE_TIME` at UTC (`Fri, 5 Sep 2026 06:16:06 GMT`: the day is not padded).
pub fn rfc_1123(t: DateTime<Utc>) -> String {
    t.format("%a, %-d %b %Y %H:%M:%S GMT").to_string()
}

fn random_below(max: u32) -> u32 {
    (OsRng.next_u64() % max as u64) as u32
}

fn random_bytes_b64(size: usize) -> String {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A `TemplateFunctions` supplier: renders by calling it (`toString()` and `get()`).
struct Function(fn() -> String);

impl JObject for Function {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.TemplateFunctions".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("get" | "toString", []) => ok(JValue::str((self.0)())),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        (self.0)()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `BUILT_IN_FUNCTIONS`, in declaration order.
pub fn functions() -> Vec<(&'static str, JValue)> {
    let f = |g: fn() -> String| JValue::Object(Arc::new(Function(g)));
    vec![
        ("now", f(|| iso_instant(crate::clock::now()))),
        ("now_epoch", f(|| crate::clock::now().timestamp().to_string())),
        ("now_iso_8601", f(|| iso_instant(crate::clock::now()))),
        ("now_rfc_1123", f(|| rfc_1123(crate::clock::now()))),
        ("uuid", f(|| uuid::Uuid::new_v4().to_string())),
        ("rand_int", f(|| random_below(10).to_string())),
        ("rand_int_10", f(|| random_below(10).to_string())),
        ("rand_int_100", f(|| random_below(100).to_string())),
        ("rand_bytes", f(|| random_bytes_b64(16))),
        ("rand_bytes_16", f(|| random_bytes_b64(16))),
        ("rand_bytes_32", f(|| random_bytes_b64(32))),
        ("rand_bytes_64", f(|| random_bytes_b64(64))),
        ("rand_bytes_128", f(|| random_bytes_b64(128))),
    ]
}

/// A helper object: a simple class name, a `toString()` and its public methods.
struct Helper {
    class: &'static str,
    methods: fn(&str, &[JValue]) -> Invocation,
    to_string: fn() -> String,
}

impl JObject for Helper {
    fn class_name(&self) -> String {
        format!("org.mockserver.templates.engine.helpers.{}", self.class)
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if (name, args.len()) == ("toString", 0) {
            return ok(JValue::str((self.to_string)()));
        }
        (self.methods)(name, args)
    }

    fn to_java_string(&self) -> String {
        (self.to_string)()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn helper(class: &'static str, methods: fn(&str, &[JValue]) -> Invocation, to_string: fn() -> String) -> JValue {
    JValue::Object(Arc::new(Helper { class, methods, to_string }))
}

/// `BUILT_IN_HELPERS`, in declaration order.
pub fn helpers() -> Vec<(&'static str, JValue)> {
    vec![
        ("jwt", helper("JwtTemplateHelper", jwt_methods, || crate::templates::jwt::generate(None))),
        ("strings", helper("StringTemplateHelper", strings, || "StringTemplateHelper".into())),
        ("jsonTransform", helper("JsonTemplateHelper", json_transform, || "JsonTemplateHelper".into())),
        ("dates", helper("DateTemplateHelper", dates_helper, crate::templates::dates::now_iso)),
        ("calc", helper("MathTemplateHelper", calc, || "MathTemplateHelper".into())),
        ("faker", crate::templates::faker::faker()),
        ("crypto", helper("CryptoTemplateHelper", crypto, || "CryptoTemplateHelper".into())),
        ("regex", helper("RegexTemplateHelper", regex, || "RegexTemplateHelper".into())),
        ("scenario", helper("ScenarioTemplateHelper", scenario, || "ScenarioTemplateHelper".into())),
        ("html", helper("HtmlTemplateHelper", html, || "HtmlTemplateHelper".into())),
        ("csv", helper("CsvTemplateHelper", csv, || "CsvTemplateHelper".into())),
        ("xpath", helper("XmlXPathTemplateHelper", xpath, || "XmlXPathTemplateHelper".into())),
        ("yaml", helper("YamlTemplateHelper", yaml, || "YamlTemplateHelper".into())),
    ]
}

/// `ON_DEMAND_HELPERS` as Velocity binds them (Mustache replaces `lists` with its own; a server binds its own
/// `hostname`, from its environment, and its own `systemValue`, from its `templateSystemValueAllowList`).
pub fn on_demand_helpers() -> Vec<(&'static str, JValue)> {
    vec![
        ("lists", crate::templates::lists::lists()),
        ("hostname", hostname(std::env::var("HOSTNAME").ok())),
        ("systemValue", crate::templates::system_value::SystemValue::nothing().velocity()),
    ]
}

/// The `hostname` function: the `HOSTNAME` environment variable when it is set and not blank, otherwise the
/// machine's name (`InetAddress.getLocalHost().getHostName()`), else `localhost`.
pub fn hostname(from_environment: Option<String>) -> JValue {
    let name = from_environment.map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).unwrap_or_else(|| MACHINE_NAME.clone());
    JValue::Object(Arc::new(Value(name)))
}

static MACHINE_NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is writable for its whole length, which is what is passed.
    let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    Some(String::from_utf8_lossy(&buffer[..end]).trim().to_string()).filter(|n| status == 0 && !n.is_empty()).unwrap_or_else(|| "localhost".into())
});

/// A `TemplateFunctions` supplier of a fixed value (`hostname`).
struct Value(String);

impl JObject for Value {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.TemplateFunctions".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("get" | "toString", []) => ok(JValue::str(self.0.as_str())),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        self.0.clone()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn jwt_methods(name: &str, args: &[JValue]) -> Invocation {
    match (name, args) {
        ("generate", []) => ok(JValue::str(crate::templates::jwt::generate(None))),
        ("generate", [JValue::Map(claims)]) => ok(JValue::str(crate::templates::jwt::generate(Some(claims)))),
        ("jwks", []) => ok(JValue::str(crate::templates::jwt::jwks())),
        _ => None,
    }
}

fn strings(name: &str, args: &[JValue]) -> Invocation {
    let arg = |i: usize| args.get(i).and_then(text);
    let s = |v: String| ok(JValue::str(v));
    match (name, args.len()) {
        ("trim", 1) => s(arg(0).map(|v| v.trim_matches(|c: char| c <= ' ').to_string()).unwrap_or_default()),
        ("capitalize", 1) => s(arg(0)
            .filter(|v| !v.is_empty())
            .map(|v| {
                let mut chars = v.chars();
                let first = chars.next().expect("not empty");
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
            .unwrap_or_default()),
        ("uppercase", 1) => s(arg(0).map(|v| v.to_uppercase()).unwrap_or_default()),
        ("lowercase", 1) => s(arg(0).map(|v| v.to_lowercase()).unwrap_or_default()),
        ("urlEncode", 1) => s(arg(0).map(|v| form_urlencoded::byte_serialize(v.as_bytes()).collect()).unwrap_or_default()),
        ("urlDecode", 1) => s(arg(0).map(|v| form_urlencoded::parse(format!("x={v}").as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()).unwrap_or_default()),
        ("base64Encode", 1) => s(arg(0).map(|v| base64::engine::general_purpose::STANDARD.encode(v)).unwrap_or_default()),
        ("base64Decode", 1) => match arg(0) {
            None => s(String::new()),
            Some(v) => match base64::engine::general_purpose::STANDARD.decode(v.as_bytes()) {
                Ok(bytes) => s(String::from_utf8_lossy(&bytes).into_owned()),
                Err(e) => Some(Err(JError::new("java.lang.IllegalArgumentException", e.to_string()))),
            },
        },
        ("substringBefore", 2) => match (arg(0), arg(1)) {
            (Some(v), Some(sep)) => s(v.find(&sep).map(|i| v[..i].to_string()).unwrap_or(v)),
            (v, _) => s(v.unwrap_or_default()),
        },
        ("substringAfter", 2) => match (arg(0), arg(1)) {
            (Some(v), Some(sep)) => s(v.find(&sep).map(|i| v[i + sep.len()..].to_string()).unwrap_or_default()),
            _ => s(String::new()),
        },
        ("length", 1) => ok(JValue::Int(arg(0).map(|v| v.encode_utf16().count() as i32).unwrap_or(0))),
        ("contains", 2) => ok(JValue::Bool(matches!((arg(0), arg(1)), (Some(v), Some(x)) if v.contains(&x)))),
        ("replace", 3) => match (arg(0), arg(1)) {
            (Some(v), Some(target)) => s(v.replace(&target, &arg(2).unwrap_or_default())),
            (v, _) => s(v.unwrap_or_default()),
        },
        _ => None,
    }
}

/// Jackson's compact writer (`writeValueAsString`).
fn compact(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn json_transform(name: &str, args: &[JValue]) -> Invocation {
    let arg = |i: usize| args.get(i).and_then(text).unwrap_or_else(|| "null".into());
    let parse = |s: &str| crate::json::parse_lenient(s.as_bytes()).ok().map(|v| crate::model::big_decimal_tree(&v));
    let s = |v: String| ok(JValue::str(v));
    match (name, args.len()) {
        ("merge", 2) => {
            let (a, b) = (arg(0), arg(1));
            match (parse(&a), parse(&b)) {
                (Some(serde_json::Value::Object(mut x)), Some(serde_json::Value::Object(y))) => {
                    for (k, v) in y {
                        x.insert(k, v);
                    }
                    s(compact(&serde_json::Value::Object(x)))
                }
                _ => s(a),
            }
        }
        ("sort", 2) => {
            let (a, field) = (arg(0), arg(1));
            match parse(&a) {
                Some(serde_json::Value::Array(mut items)) => {
                    let key = |n: &serde_json::Value| match n.get(&field) {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(serde_json::Value::Null) => "null".into(),
                        Some(f) if f.is_object() || f.is_array() => String::new(),
                        Some(f) => f.to_string(),
                        None => String::new(),
                    };
                    items.sort_by(|x, y| key(x).encode_utf16().cmp(key(y).encode_utf16()));
                    s(compact(&serde_json::Value::Array(items)))
                }
                _ => s(a),
            }
        }
        ("arrayAdd", 2) => {
            let a = arg(0);
            match (parse(&a), parse(&arg(1))) {
                (Some(serde_json::Value::Array(mut items)), Some(e)) => {
                    items.push(e);
                    s(compact(&serde_json::Value::Array(items)))
                }
                _ => s(a),
            }
        }
        ("remove", 2) => {
            let a = arg(0);
            match parse(&a) {
                Some(serde_json::Value::Object(mut o)) => {
                    o.shift_remove(&arg(1));
                    s(compact(&serde_json::Value::Object(o)))
                }
                _ => s(a),
            }
        }
        ("prettyPrint", 1) => {
            let a = arg(0);
            s(parse(&a).map(|v| crate::json::pretty(&v)).unwrap_or(a))
        }
        ("field", 2) => s(match parse(&arg(0)).and_then(|v| v.get(arg(1)).cloned()) {
            Some(serde_json::Value::String(t)) => t,
            Some(other) => compact(&other),
            None => String::new(),
        }),
        ("size", 1) => ok(JValue::Int(match parse(&arg(0)) {
            Some(serde_json::Value::Array(a)) => a.len() as i32,
            _ => 0,
        })),
        _ => None,
    }
}

fn long_arg(v: Option<&JValue>) -> Option<i64> {
    v.and_then(as_int).or_else(|| v.and_then(as_f64).map(|d| d as i64))
}

/// `DateTemplateHelper`: the methods on any date and zone (`dates.rs`), then the ones on now.
pub fn dates_helper(name: &str, args: &[JValue]) -> Invocation {
    crate::templates::dates::helper(name, args).or_else(|| dates(name, args))
}

fn dates(name: &str, args: &[JValue]) -> Invocation {
    let now = crate::clock::now();
    let n = long_arg(args.first());
    let iso = |t: DateTime<Utc>| ok(JValue::str(iso_instant(t)));
    match (name, args.len()) {
        ("plusSeconds", 1) => iso(now + Duration::seconds(n?)),
        ("plusMinutes", 1) => iso(now + Duration::minutes(n?)),
        ("plusHours", 1) => iso(now + Duration::hours(n?)),
        ("plusDays", 1) => iso(now + Duration::days(n?)),
        ("minusSeconds", 1) => iso(now - Duration::seconds(n?)),
        ("minusMinutes", 1) => iso(now - Duration::minutes(n?)),
        ("minusHours", 1) => iso(now - Duration::hours(n?)),
        ("minusDays", 1) => iso(now - Duration::days(n?)),
        ("epochSeconds", 0) => ok(JValue::Long(now.timestamp())),
        ("epochMillis", 0) => ok(JValue::Long(now.timestamp_millis())),
        ("epochSecondsPlus", 1) => ok(JValue::str((now + Duration::seconds(n?)).timestamp().to_string())),
        ("epochSecondsMinus", 1) => ok(JValue::str((now - Duration::seconds(n?)).timestamp().to_string())),
        _ => None,
    }
}

fn random_f64() -> f64 {
    (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

fn calc(name: &str, args: &[JValue]) -> Invocation {
    let d = |i: usize| args.get(i).and_then(as_f64);
    let i = |i: usize| args.get(i).and_then(as_int);
    let is_int = |i: usize| matches!(args.get(i), Some(JValue::Int(_) | JValue::Long(_)));
    match (name, args.len()) {
        ("randomInt", 2) => {
            let (min, max) = (i(0)?, i(1)?);
            if min > max {
                return Some(Err(JError::new("java.lang.IllegalArgumentException", "bound must be greater than origin")));
            }
            let range = (max - min + 1) as u64;
            ok(JValue::Int((min + (OsRng.next_u64() % range) as i64) as i32))
        }
        ("randomDouble", 0) => ok(JValue::Double(random_f64())),
        ("randomDouble", 2) => {
            let (min, max) = (d(0)?, d(1)?);
            ok(JValue::Double(min + random_f64() * (max - min)))
        }
        ("abs", 1) if is_int(0) => ok(JValue::Int((i(0)? as i32).wrapping_abs())),
        ("abs", 1) => ok(JValue::Double(d(0)?.abs())),
        ("min", 2) => ok(JValue::Int(i(0)?.min(i(1)?) as i32)),
        ("max", 2) => ok(JValue::Int(i(0)?.max(i(1)?) as i32)),
        ("round", 2) => {
            let (value, scale) = (d(0)?, i(1)?);
            let text = java_compat::double_to_string(value);
            ok(JValue::Double(crate::templates::java_time::round_half_up(&text, scale).parse().unwrap_or(value)))
        }
        ("format", 2) => {
            let pattern = args.get(1).and_then(text)?;
            Some(crate::templates::java_time::decimal_format(d(0)?, &pattern).map(|s| Some(JValue::str(s))))
        }
        ("ceil", 1) => ok(JValue::Double(d(0)?.ceil())),
        ("floor", 1) => ok(JValue::Double(d(0)?.floor())),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn crypto(name: &str, args: &[JValue]) -> Invocation {
    use ring::digest;
    let arg = |i: usize| args.get(i).and_then(text);
    let digest = |alg: &'static digest::Algorithm| ok(JValue::str(arg(0).map(|v| hex(digest::digest(alg, v.as_bytes()).as_ref())).unwrap_or_default()));
    match (name, args.len()) {
        ("md5", 1) => ok(JValue::str(arg(0).map(|v| hex(&crate::templates::md5::digest(v.as_bytes()))).unwrap_or_default())),
        ("sha1", 1) => digest(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        ("sha256", 1) => digest(&digest::SHA256),
        ("sha512", 1) => digest(&digest::SHA512),
        ("hmacSha256", 2) => match (arg(0), arg(1)) {
            (Some(key), Some(data)) => {
                let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
                ok(JValue::str(hex(ring::hmac::sign(&key, data.as_bytes()).as_ref())))
            }
            _ => ok(JValue::str("")),
        },
        _ => None,
    }
}

/// `Pattern.compile(pattern)`, or the `PatternSyntaxException` it throws.
fn java_pattern(pattern: &str) -> Result<std::sync::Arc<crate::matcher::java_pattern::JavaRegex>, JError> {
    crate::matcher::java_pattern::compile(pattern).map_err(|e| JError::new("java.util.regex.PatternSyntaxException", e.to_string()))
}

fn regex(name: &str, args: &[JValue]) -> Invocation {
    let arg = |i: usize| args.get(i).and_then(text);
    match (name, args.len()) {
        ("matches", 2) => match (arg(0), arg(1)) {
            (Some(input), Some(pattern)) => Some(java_pattern(&pattern).and_then(|re| {
                let found = re.find_or_throw(&input).map_err(|e| JError::new(e.class, e.message))?;
                Ok(Some(JValue::Bool(found)))
            })),
            _ => ok(JValue::Bool(false)),
        },
        ("replaceAll", 3) => match (arg(0), arg(1)) {
            (Some(input), Some(pattern)) => Some(java_pattern(&pattern).and_then(|compiled| {
                let replacement = arg(2).unwrap_or_default();
                let mut out = String::new();
                let mut last = 0;
                let found = compiled.find_all(&input).map_err(|e| JError::new(e.class, e.message))?;
                // A match may start or end between a supplementary character's surrogates; `slice` writes the lone
                // halves the result then holds.
                let slice = crate::matcher::java_pattern::slice;
                for caps in found {
                    let m = caps.get(0).expect("group 0");
                    out.push_str(&slice(&input, last, m.start()));
                    out.push_str(&caps.expand(&replacement)?);
                    last = m.end();
                }
                out.push_str(&slice(&input, last, input.len()));
                Ok(Some(JValue::str(out)))
            })),
            (input, _) => ok(JValue::str(input.unwrap_or_default())),
        },
        ("group", 3) => match (arg(0), arg(1), args.get(2).and_then(as_int)) {
            (Some(input), Some(pattern), Some(group)) if group >= 0 => Some(java_pattern(&pattern).and_then(|compiled| {
                let found = compiled.captures_or_throw(&input).map_err(|e| JError::new(e.class, e.message))?;
                Ok(Some(JValue::str(found.and_then(|c| c.get(group as usize).map(|m| m.as_str().to_string())).unwrap_or_default())))
            })),
            _ => ok(JValue::str("")),
        },
        _ => None,
    }
}

fn scenario(name: &str, args: &[JValue]) -> Invocation {
    let arg = |i: usize| args.get(i).and_then(text);
    match (name, args.len()) {
        ("get", 1) => ok(JValue::str(arg(0).map(|n| crate::templates::scenario_state(&n)).unwrap_or_default())),
        ("set", 2) => {
            if let (Some(n), Some(s)) = (arg(0), arg(1)) {
                crate::templates::set_scenario_state(&n, &s);
            }
            ok(JValue::str(""))
        }
        ("matches", 2) => ok(JValue::Bool(matches!((arg(0), arg(1)), (Some(n), Some(s)) if crate::templates::scenario_state(&n) == s))),
        _ => None,
    }
}

fn html(name: &str, args: &[JValue]) -> Invocation {
    let arg = args.first().and_then(text);
    match (name, args.len()) {
        ("escape", 1) => ok(JValue::str(arg.map(|v| java_compat::escape_html4(&v)).unwrap_or_default())),
        ("unescape", 1) => ok(JValue::str(arg.map(|v| java_compat::unescape_html4(&v)).unwrap_or_default())),
        _ => None,
    }
}

fn csv(name: &str, args: &[JValue]) -> Invocation {
    match (name, args) {
        ("parse", [v]) => {
            let rows = crate::templates::csv_parse(v.as_str().unwrap_or(""));
            ok(JValue::List(JList::array_list(rows.into_iter().map(JValue::string_list).collect())))
        }
        ("row", [JValue::Null]) => ok(JValue::str("")),
        ("row", [fields]) => {
            let items = fields.iterate()?;
            let line = items
                .iter()
                .map(|f| {
                    let field = if f.is_null() { String::new() } else { f.to_java_string() };
                    if field.contains([',', '"', '\n', '\r']) { format!("\"{}\"", field.replace('"', "\"\"")) } else { field }
                })
                .collect::<Vec<_>>()
                .join(",");
            ok(JValue::str(line))
        }
        _ => None,
    }
}

pub fn xpath(name: &str, args: &[JValue]) -> Invocation {
    match (name, args) {
        ("formatXml", [xml]) => Some(crate::templates::format_xml::format_xml(text(xml).as_deref()).map(|x| Some(JValue::str(x)))),
        ("evaluate", [xml, expr]) => match (text(xml), text(expr)) {
            (Some(xml), Some(expr)) => ok(JValue::str(crate::templates::extract::xpath_string(&xml, &expr).unwrap_or_default())),
            _ => ok(JValue::str("")),
        },
        _ => None,
    }
}

fn yaml(name: &str, args: &[JValue]) -> Invocation {
    let arg = |i: usize| args.get(i).and_then(text);
    match (name, args.len()) {
        ("toJson", 1) => ok(JValue::str(match arg(0).filter(|y| !y.is_empty()) {
            None => String::new(),
            Some(y) => crate::templates::yaml_to_json(&y).map(|v| compact(&v)).unwrap_or(y),
        })),
        ("parse", 2) => ok(JValue::str(match (arg(0).filter(|y| !y.is_empty()), arg(1)) {
            (Some(y), Some(field)) => match crate::templates::yaml_to_json(&y).ok().and_then(|v| v.get(&field).cloned()) {
                Some(serde_json::Value::String(s)) => s,
                Some(v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => compact(&v),
                Some(serde_json::Value::Null) => "null".into(),
                Some(v) => v.to_string(),
                None => String::new(),
            },
            _ => String::new(),
        })),
        _ => None,
    }
}
