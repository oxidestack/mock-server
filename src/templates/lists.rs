//! The `lists` helper (`ListTemplateHelper`, and `MustacheListTemplateHelper` for Mustache): WireMock's
//! `pickRandom`, `array`, `arrayJoin` and `range`, each list at most [`MAX_SIZE`] values. Unseeded it picks with a
//! thread-local generator; with a non-zero `templateFakerSeed` each engine has its own `new Random(seed)`
//! ([`Lists`]), so picks repeat across runs.

use std::sync::{Arc, LazyLock, OnceLock};

use datafaker::java::Random;
use java_compat::lang::{JError, JList, JObject, JValue};
use jmustache::{Fragment, Lambda, LambdaFn, MustacheError};

type Invocation = Option<Result<Option<JValue>, JError>>;

/// `ListTemplateHelper.MAX_SIZE`.
const MAX_SIZE: usize = 10_000;
/// `ListTemplateHelper.MIN_JOIN_LIMIT`.
const MIN_JOIN_LIMIT: u64 = 64 * 1024;

fn illegal(message: String) -> JError {
    JError::new("java.lang.IllegalArgumentException", message)
}

/// A `ListTemplateHelper`: `None` picks with a thread-local generator, `Some` with a seeded `java.util.Random`.
#[derive(Clone)]
pub struct ListHelper {
    random: Option<Arc<Random>>,
    mustache: bool,
}

impl ListHelper {
    fn next_int(&self, bound: usize) -> usize {
        match &self.random {
            Some(random) => random.next_int_bounded(bound as i32).map(|i| i as usize).unwrap_or(0),
            None => {
                use rand_core::{OsRng, RngCore};
                (OsRng.next_u64() % bound as u64) as usize
            }
        }
    }

    pub fn pick_random(&self, values: &[JValue]) -> Result<JValue, JError> {
        let items = items("pickRandom", values)?;
        if items.is_empty() {
            return Err(illegal("lists.pickRandom: there is nothing to pick from; pass at least one value".into()));
        }
        Ok(items[self.next_int(items.len())].clone())
    }

    fn array(&self, values: &[JValue]) -> Result<JValue, JError> {
        Ok(JValue::List(JList::array_list(items("array", values)?)))
    }

    fn array_join(&self, separator: &JValue, values: &[JValue]) -> Result<String, JError> {
        let joiner = if separator.is_null() { String::new() } else { separator.to_java_string() };
        let texts: Vec<String> = items("arrayJoin", values)?.iter().map(JValue::to_java_string).collect();
        let utf16 = |s: &str| s.encode_utf16().count() as u64;
        let values_length: u64 = texts.iter().map(|t| utf16(t)).sum();
        let joined_length = values_length + utf16(&joiner) * texts.len().saturating_sub(1) as u64;
        let limit = MIN_JOIN_LIMIT.max(4 * values_length);
        if joined_length > limit {
            return Err(illegal(format!("lists.arrayJoin: the joined text would be {joined_length} characters, over the limit of {limit}")));
        }
        Ok(texts.join(&joiner))
    }
}

/// `range(from, to)`: both included, counting down when `to` is smaller.
fn range(from: i32, to: i32) -> Result<JValue, JError> {
    let size = (to as i64 - from as i64).unsigned_abs() + 1;
    if size > MAX_SIZE as u64 {
        return Err(illegal(format!("lists.range: a range has at most {MAX_SIZE} values, but {from} to {to} has {size}")));
    }
    let step = if from <= to { 1 } else { -1 };
    Ok(JValue::List(JList::array_list((0..size as i32).map(|i| JValue::Int(from + i * step)).collect())))
}

/// `integer(name, value)`: a whole `Number`, or text holding one.
fn integer(name: &str, value: &JValue) -> Result<i32, JError> {
    if let Some(number) = java_compat::methods::as_f64(value).filter(|_| is_number(value)) {
        if number != number.round_ties_even() || number > i32::MAX as f64 || number < i32::MIN as f64 {
            return Err(illegal(format!("lists.range: {name} must be a whole number, but was {}", value.to_java_string())));
        }
        return Ok(number as i32);
    }
    let text = if value.is_null() { String::new() } else { value.to_java_string().trim_matches(|c: char| c <= ' ').to_string() };
    java_parse_int(&text).ok_or_else(|| illegal(format!("lists.range: {name} must be a whole number, but was \"{text}\"")))
}

fn is_number(value: &JValue) -> bool {
    matches!(value, JValue::Byte(_) | JValue::Short(_) | JValue::Int(_) | JValue::Long(_) | JValue::Float(_) | JValue::Double(_) | JValue::BigInteger(_) | JValue::BigDecimal(_))
}

/// `Integer.parseInt`: an optional sign, then ASCII digits.
fn java_parse_int(text: &str) -> Option<i32> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `items(helper, values)`: the values, or the elements of the single list, array or map (its values) passed instead.
fn items(helper: &str, values: &[JValue]) -> Result<Vec<JValue>, JError> {
    let items = match values {
        [JValue::List(list)] => list.items(),
        [JValue::Map(map)] => map.entries().into_iter().map(|(_, v)| v).collect(),
        [JValue::Array(array)] => array.items(),
        _ => values.to_vec(),
    };
    if items.len() > MAX_SIZE {
        return Err(illegal(format!("lists.{helper}: a list has at most {MAX_SIZE} values, but this one has {}", items.len())));
    }
    Ok(items)
}

impl JObject for ListHelper {
    fn class_name(&self) -> String {
        if self.mustache { "org.mockserver.templates.engine.mustache.MustacheListTemplateHelper".into() } else { "org.mockserver.templates.engine.helpers.ListTemplateHelper".into() }
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        let done = |r: Result<JValue, JError>| Some(r.map(Some));
        match (name, args) {
            ("toString", []) => done(Ok(JValue::str("ListTemplateHelper"))),
            // Mustache cannot pass arguments: `pickRandom` and `arrayJoin` are sections, `range` a map of maps.
            ("pickRandom", []) if self.mustache => done(Ok(Lambda::object(PICK_RANDOM_CLASS, Arc::new(MustacheList { helper: self.clone_ref(), join: false })))),
            ("arrayJoin", []) if self.mustache => done(Ok(Lambda::object(ARRAY_JOIN_CLASS, Arc::new(MustacheList { helper: self.clone_ref(), join: true })))),
            ("range", []) if self.mustache => done(Ok(JValue::Object(Arc::new(Bound { from: None })))),
            ("pickRandom", values) => done(self.pick_random(values)),
            ("array", values) => done(self.array(values)),
            ("arrayJoin", [separator, values @ ..]) => done(self.array_join(separator, values).map(JValue::str)),
            ("range", [from, to]) => done(integer("from", from).and_then(|from| integer("to", to).and_then(|to| range(from, to)))),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        "ListTemplateHelper".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl ListHelper {
    /// The same helper (its generator is shared state, as the Java object's field is).
    fn clone_ref(&self) -> Arc<ListHelper> {
        Arc::new(self.clone())
    }
}

const PICK_RANDOM_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheListTemplateHelper$$Lambda/0x00007f3c8c0e3a10";
const ARRAY_JOIN_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheListTemplateHelper$$Lambda/0x00007f3c8c0e3c38";

/// The `pickRandom` and `arrayJoin` sections: the body's values separated by `|`.
struct MustacheList {
    helper: Arc<ListHelper>,
    join: bool,
}

/// `values(body)`: the parts between `|`, each trimmed, empty ones left out.
fn values(body: &str) -> Result<Vec<JValue>, JError> {
    let mut values = Vec::new();
    for part in body.split('|') {
        let value = part.trim_matches(|c: char| c <= ' ');
        if !value.is_empty() {
            values.push(JValue::str(value));
            if values.len() > MAX_SIZE {
                return Err(illegal(format!("lists: a list has at most {MAX_SIZE} values")));
            }
        }
    }
    Ok(values)
}

impl LambdaFn for MustacheList {
    fn execute(&self, frag: &Fragment, out: &mut String) -> Result<(), MustacheError> {
        let body = frag.execute()?;
        let written = if self.join {
            let Some(end) = body.find('|') else {
                return Err(MustacheError::Java(illegal(
                    "lists.arrayJoin: write the separator first, then the values, all separated by |, such as {{#lists.arrayJoin}}, |red|green{{/lists.arrayJoin}}".into(),
                )));
            };
            self.helper.array_join(&JValue::str(&body[..end]), &values(&body[end + 1..]).map_err(MustacheError::Java)?)
        } else {
            values(&body).and_then(|v| self.helper.pick_random(&v)).map(|v| v.to_java_string())
        };
        out.push_str(&written.map_err(MustacheError::Java)?);
        Ok(())
    }
}

/// `IntegerKeyedMap`: each name read from it is a whole number, `from` then `to` (`lists.range.1.5`).
struct Bound {
    from: Option<i32>,
}

impl JObject for Bound {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.mustache.MustacheListTemplateHelper$IntegerKeyedMap".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if !args.is_empty() || matches!(name, "getClass" | "hashCode" | "toString" | "equals") {
            return None;
        }
        let bound = if self.from.is_none() { "from" } else { "to" };
        let Some(n) = java_parse_int(name.trim_matches(|c: char| c <= ' ')) else {
            return Some(Err(illegal(format!("lists.range: {bound} must be a whole number, but was \"{name}\"; write the range as lists.range.1.5"))));
        };
        Some(match self.from {
            None => Ok(Some(JValue::Object(Arc::new(Bound { from: Some(n) })))),
            Some(from) => range(from, n).map(Some),
        })
    }

    fn to_java_string(&self) -> String {
        "{}".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The shared, unseeded helpers.
static VELOCITY: LazyLock<JValue> = LazyLock::new(|| JValue::Object(Arc::new(ListHelper { random: None, mustache: false })));
static MUSTACHE: LazyLock<JValue> = LazyLock::new(|| JValue::Object(Arc::new(ListHelper { random: None, mustache: true })));

pub fn lists() -> JValue {
    VELOCITY.clone()
}

pub fn mustache_lists() -> JValue {
    MUSTACHE.clone()
}

/// The per-engine seeded `lists` helpers of a server (`TemplateFunctions.resolveLists(templateFakerSeed)`).
#[derive(Default)]
pub struct Lists {
    velocity: OnceLock<Option<JValue>>,
    mustache: OnceLock<Option<JValue>>,
}

impl Lists {
    /// The engine's seeded helper, `None` when `templateFakerSeed` is 0 (the shared unseeded one applies).
    pub fn seeded(&self, config: &crate::Config, engine: super::Engine) -> Option<JValue> {
        let (cell, mustache) = match engine {
            super::Engine::Velocity => (&self.velocity, false),
            super::Engine::Mustache => (&self.mustache, true),
            super::Engine::JavaScript => return None,
        };
        cell.get_or_init(|| {
            let seed = config.int_property("templateFakerSeed", 0);
            (seed != 0).then(|| JValue::Object(Arc::new(ListHelper { random: Some(Arc::new(Random::new(seed))), mustache })))
        })
        .clone()
    }
}
