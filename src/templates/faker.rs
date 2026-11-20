//! The `faker` helper: a Datafaker 2.7.0 `Faker` (datafaker-rs). Templates reach its public methods and those of the
//! providers it returns through datafaker-rs's method tables (`faker.name().firstName()`, `faker.name.firstName`,
//! `$faker.number().numberBetween(1, 10)`). The shared faker is unseeded, as `TemplateFunctions.FAKER`; with a
//! non-zero `templateFakerSeed` each template engine gets its own `new Faker(new Random(seed))` ([`Fakers`]), so a
//! fresh server's renders repeat the oracle's.
//!
//! A call is resolved as Velocity resolves it by reflection, not by Datafaker's own coercion: each method table is
//! described to velocity-rs as a typed class ([`class_def`]), whose `MethodMap` chooses the overload (an ambiguous
//! call is not found, so the reference renders as written) and whose invocation converts and packs the arguments.
//! Under 8.0.0's `SecureUberspector` there is no conversion handler, so no string becomes a number, boolean, enum
//! constant or `char` and nothing becomes a `String` (`$faker.planet().symbol('EARTH')`, `$faker.numerify(12)`
//! render as written); an unsandboxed engine (`velocityDisallowClassLoading=false`) renders in the JVM foreign
//! runtime, not here. A `null` argument binds to any reference parameter and the method's body does what the Java
//! one does with it (`$faker.dune().quote(null)`: a `NullPointerException`); a body datafaker-rs has not taught
//! about `null`, or an argument it has no value for (a `Date`, an enum constant), is not found. A template's lists,
//! maps and Java arrays reach the `List`, `Set`, `Map`, array and `Object...` parameters
//! (`$faker.options().option(['a','b'])` picks the list itself, `nextElement(['a','b'])` one of its items): each
//! value Datafaker only passes along, compares or hashes travels as a [`Foreigns`] entry and comes back as itself.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use datafaker::dispatch::{Method, Target, P};
use java_compat::lang::{JError, JList, JMap, JObject, JValue, MapKind};
use java_compat::reflect::{ClassDef, JMethod, JType};
use velocity::uberspect::CallError;

type Invocation = Option<Result<Option<JValue>, JError>>;

fn ok(v: JValue) -> Invocation {
    Some(Ok(Some(v)))
}

/// A Datafaker object a template holds: the faker, one of its providers, or its `RandomService`.
struct Fake {
    faker: Arc<datafaker::Faker>,
    target: Target,
    family: Arc<Family>,
}

/// A root `TemplateFaker` and the locale fakers `locale(tag)` made from it, which share its cache and seed.
struct Family {
    root: Arc<datafaker::Faker>,
    /// `null` when unseeded; else each locale faker gets its own `new Random(seed)`.
    seed: Option<i64>,
    /// Keyed only by [`SUPPORTED_LOCALES`] entries.
    locales: Mutex<HashMap<&'static str, Arc<datafaker::Faker>>>,
}

impl Family {
    fn root(seed: Option<i64>) -> JValue {
        let faker = match seed {
            Some(seed) => datafaker::Faker::with_seed(seed),
            None => datafaker::Faker::new(),
        };
        let root = Arc::new(faker.subclass("TemplateFaker"));
        let family = Arc::new(Family { root: root.clone(), seed, locales: Mutex::default() });
        JValue::Object(Arc::new(Fake { faker: root, target: Target::Faker, family }))
    }

    /// `TemplateFaker.locale(tag)`: the faker of the supported locale `tag` reduces to, else the root faker.
    fn locale(self: &Arc<Family>, tag: Option<&str>) -> JValue {
        let faker = match tag.and_then(supported_tag) {
            None => self.root.clone(),
            Some(supported) => self
                .locales
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(supported)
                .or_insert_with(|| {
                    let (language, country) = supported.split_once('-').unwrap_or((supported, ""));
                    let random = match self.seed {
                        Some(seed) => datafaker::RandomService::with_seed(seed),
                        None => datafaker::RandomService::default(),
                    };
                    Arc::new(datafaker::Faker::with_locale_and_random(datafaker::Locale::new(language, country), random).subclass("TemplateFaker"))
                })
                .clone(),
        };
        JValue::Object(Arc::new(Fake { faker, target: Target::Faker, family: self.clone() }))
    }
}

/// `TemplateFaker.SHIPPED_LOCALES`: the locales Datafaker 2.x ships a `<tag>.yml` for (all of them in datafaker-rs),
/// in the order of the `TreeSet` that holds them.
const SUPPORTED_LOCALES: [&str; 77] = [
    "ar", "be", "bg", "by", "ca", "ca-CAT", "cs", "cs-CZ", "da-DK", "de", "de-AT", "de-CH", "el-GR", "en", "en-AU", "en-BORK", "en-CA", "en-GB", "en-IE",
    "en-IN", "en-MD", "en-MS", "en-NEP", "en-NG", "en-NZ", "en-PAK", "en-PH", "en-PK", "en-SG", "en-UG", "en-US", "en-ZA", "es", "es-AR", "es-MX", "es-PY",
    "et", "fa", "fi-FI", "fr", "fr-CA", "fr-CH", "he", "hr", "hu", "hy", "id", "id-ID", "it", "ja", "ka", "ko", "lv", "mk", "nb-NO", "nl", "nl-BE", "no-NO",
    "pl", "pt", "pt-BR", "ro-MD", "ru", "ru-MD", "sk", "sq", "sv", "sv-SE", "ta", "ta-IN", "th", "tr", "uk", "uz", "vi", "zh-CN", "zh-TW",
];

/// `supportedTag(tag)`: by string parsing only, the language and region when Datafaker has data for that pair,
/// else the language, else `None`. Scripts, variants and extensions are ignored.
fn supported_tag(tag: &str) -> Option<&'static str> {
    let normalised = tag.trim_matches(|c: char| c <= ' ').replace('_', "-");
    let subtags: Vec<&str> = normalised.splitn(3, '-').collect();
    let language = subtags[0].to_lowercase();
    let length = |s: &str| s.encode_utf16().count();
    if !(2..=3).contains(&length(&language)) {
        return None;
    }
    if let Some(region) = subtags.get(1).filter(|r| (2..=4).contains(&length(r))) {
        let found = SUPPORTED_LOCALES.iter().find(|s| {
            s.len() == language.len() + 1 + region.len() && s.starts_with(&format!("{language}-")) && s[language.len() + 1..].eq_ignore_ascii_case(region)
        });
        if let Some(found) = found {
            return Some(found);
        }
    }
    SUPPORTED_LOCALES.iter().find(|s| **s == language).copied()
}

/// `TemplateFaker.LocaleLookup`, for Mustache, which cannot pass an argument: each name read from it is a locale.
struct LocaleLookup(Arc<Family>);

impl JObject for LocaleLookup {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.helpers.TemplateFaker$LocaleLookup".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("get", [key]) => ok(self.0.locale(Some(&key.to_java_string()))),
            ("containsKey", [key]) => ok(JValue::Bool(matches!(key, JValue::Str(_)))),
            ("toString", []) => ok(JValue::str("{}")),
            ("isEmpty", []) => ok(JValue::Bool(true)),
            ("size", []) => ok(JValue::Int(0)),
            (_, []) if !matches!(name, "getClass" | "hashCode" | "equals") => ok(self.0.locale(Some(name))),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        "{}".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Fake {
    fn value(&self, target: Target) -> JValue {
        JValue::Object(Arc::new(Fake { faker: self.faker.clone(), target, family: self.family.clone() }))
    }

    /// The faker's or a provider's public method `name`, chosen and its arguments converted as Velocity does.
    fn call(&self, name: &str, args: &[JValue]) -> Invocation {
        let def = class_def(self.target);
        let method = velocity::uberspect::class_methods(&def).find_cached(name, args).ok().flatten()?;
        let this = self.value(self.target);
        match velocity::uberspect::invoke(&method, &this, args) {
            Ok(value) => Some(Ok(value)),
            Err(CallError::Threw(e)) if e.class == NOT_TAKEN => None,
            Err(CallError::Threw(e) | CallError::IllegalArgument(e)) => Some(Err(e)),
        }
    }

    /// Runs `method`'s body with the arguments Velocity converted and packed for its parameters.
    fn run(&self, method: &'static Method, args: &[JValue]) -> Result<Option<JValue>, JError> {
        let mut foreigns = Foreigns::default();
        let mut values = Vec::with_capacity(args.len());
        for (i, arg) in args.iter().enumerate() {
            let vararg = method.varargs && i == method.params.len() - 1;
            values.push(datafaker_argument(method, method.params[i], vararg, arg, &mut foreigns)?);
        }
        match (method.invoke)(&self.faker, &values) {
            Ok(value) => Ok(Some(self.convert(value, &foreigns))),
            Err(e) => Err(java_error(&e)),
        }
    }

    fn convert(&self, value: datafaker::JValue, foreigns: &Foreigns) -> JValue {
        use datafaker::JValue as D;
        match value {
            D::Null => JValue::Null,
            D::Str(s) => JValue::str(s),
            D::Int(i) => JValue::Int(i),
            D::Long(l) => JValue::Long(l),
            D::Double(d) => JValue::Double(d),
            D::Float(f) => JValue::Float(f),
            D::Bool(b) => JValue::Bool(b),
            D::Char(c) => JValue::Char(char::from_u32(c as u32).unwrap_or('\u{FFFD}')),
            D::List(items) => JValue::List(JList::array_list(items.into_iter().map(|v| self.convert(v, foreigns)).collect())),
            D::Map(entries) => JValue::Map(JMap::from_entries(
                MapKind::Linked,
                entries.into_iter().map(|(k, v)| (self.convert(k, foreigns), self.convert(v, foreigns))),
            )),
            D::Foreign { id, .. } => foreigns.0[id].clone(),
            D::Enum(e) => JValue::str(e),
            D::Provider(kind) => self.value(Target::Provider(kind)),
            D::Faker => self.value(Target::Faker),
            D::RandomService => self.value(Target::RandomService),
        }
    }
}

/// The class of the error [`datafaker_argument`] raises for an argument the body has no value for: the call is not
/// found, as before Velocity chose it.
const NOT_TAKEN: &str = "mock_server.templates.faker.NotTaken";

fn not_taken() -> JError {
    JError::without_message(NOT_TAKEN)
}

/// The template values a call hands Datafaker as [`datafaker::JValue::Foreign`]s, by id. Values that are `equals`
/// share one id, so Datafaker's `distinct` and `HashSet` see Java's equality, and a result comes back as the first
/// of them the template passed.
#[derive(Default)]
struct Foreigns(Vec<JValue>);

impl Foreigns {
    fn add(&mut self, v: &JValue) -> datafaker::JValue {
        let id = match self.0.iter().position(|w| java_compat::lang::java_equals(w, v)) {
            Some(id) => id,
            None => {
                self.0.push(v.clone());
                self.0.len() - 1
            }
        };
        let class = java_compat::reflect::class_of(v).map_or_else(String::new, |c| c.name());
        datafaker::JValue::Foreign { id, hash: java_compat::lang::java_hash_code(v), class }
    }

    /// An element Datafaker may read as a `String` (`slug`'s words): a string as itself, `null` as null, anything
    /// else as a foreign value its checkcast refuses.
    fn element(&mut self, v: &JValue) -> datafaker::JValue {
        match v {
            JValue::Null => datafaker::JValue::Null,
            JValue::Str(s) => datafaker::JValue::Str(s.to_string()),
            other => self.add(other),
        }
    }

    /// An element of an `Object[]`, a primitive array or `Object...`: passed along as itself.
    fn item(&mut self, v: &JValue) -> datafaker::JValue {
        if v.is_null() { datafaker::JValue::Null } else { self.add(v) }
    }
}

/// A non-null argument of a `List`, `Set`, `Map` or array parameter (`P::Opaque(name)`), `None` for one of another
/// kind or a parameter datafaker-rs has no value for.
fn opaque(name: &str, arg: &JValue, foreigns: &mut Foreigns) -> Option<datafaker::JValue> {
    use datafaker::JValue as D;
    Some(match (name, arg) {
        ("List", JValue::List(list)) => D::List(list.items().iter().map(|v| foreigns.element(v)).collect()),
        ("Set", _) => foreigns.add(arg),
        ("String[]", JValue::Array(array)) => D::List(array.items().iter().map(|v| foreigns.element(v)).collect()),
        ("Object[]" | "char[]" | "int[]" | "long[]" | "float[]" | "double[]" | "short[]" | "boolean[]" | "byte[]", JValue::Array(array)) => {
            D::List(array.items().iter().map(|v| foreigns.item(v)).collect())
        }
        // `templatify`'s `Map<Character, String[]>`: `Character` keys and `String[]` values are Datafaker's to read.
        ("Map", JValue::Map(map)) => D::Map(
            map.entries()
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        JValue::Char(c) => D::Char(c.encode_utf16(&mut [0; 2])[0]),
                        other => foreigns.item(other),
                    };
                    let value = match v {
                        JValue::Array(a) if a.component == JType::string() => D::List(a.items().iter().map(|s| foreigns.element(s)).collect()),
                        other => foreigns.item(other),
                    };
                    (key, value)
                })
                .collect(),
        ),
        _ => return None,
    })
}

/// An argument Velocity passes to parameter type `p` (the component type for a varargs array) as a datafaker-rs value.
fn datafaker_argument(method: &Method, p: P, vararg: bool, arg: &JValue, foreigns: &mut Foreigns) -> Result<datafaker::JValue, JError> {
    use datafaker::JValue as D;
    if arg.is_null() {
        return if method.nulls { Ok(D::Null) } else { Err(not_taken()) };
    }
    if vararg {
        let JValue::Array(array) = arg else { return Err(not_taken()) };
        let mut items = Vec::new();
        for item in array.items() {
            if item.is_null() {
                if !method.null_items {
                    return Err(not_taken());
                }
                items.push(D::Null);
                continue;
            }
            items.push(if p == P::Object { foreigns.add(&item) } else { scalar(p, &item).ok_or_else(not_taken)? });
        }
        return Ok(D::List(items));
    }
    match p {
        P::Opaque(name) => opaque(name, arg, foreigns),
        _ => scalar(p, arg),
    }
    .ok_or_else(not_taken)
}

/// A non-null value of parameter type `p`, `None` for one datafaker-rs has no value for.
fn scalar(p: P, v: &JValue) -> Option<datafaker::JValue> {
    use datafaker::JValue as D;
    Some(match (p, v) {
        // No template value is a Datafaker enum constant (results come back as their names).
        (P::Opaque(_) | P::Date | P::Enum(..), _) => return None,
        (_, JValue::Str(s)) => D::Str(s.to_string()),
        (_, JValue::Bool(b)) => D::Bool(*b),
        (_, JValue::Char(c)) => D::Char(c.encode_utf16(&mut [0; 2])[0]),
        (_, JValue::Byte(n)) => D::Int(*n as i32),
        (_, JValue::Short(n)) => D::Int(*n as i32),
        (_, JValue::Int(n)) => D::Int(*n),
        (_, JValue::Long(n)) => D::Long(*n),
        (_, JValue::Float(f)) => D::Float(*f),
        (_, JValue::Double(d)) => D::Double(*d),
        _ => return None,
    })
}

/// A parameter type as Velocity's `MethodMap` sees it. Datafaker's classes keep their shaded names; the other
/// opaque ones (`Range`, `Gender`, …) only need to be unrelated to `String` and to each other.
fn jtype(p: P) -> JType {
    match p {
        P::Byte => JType::Byte,
        P::Short => JType::Short,
        P::Int => JType::Int,
        P::Long => JType::Long,
        P::Float => JType::Float,
        P::Double => JType::Double,
        P::Boolean => JType::Boolean,
        P::Char => JType::Char,
        P::String => JType::string(),
        P::CharSequence => JType::class("java.lang.CharSequence"),
        P::Object => JType::object(),
        P::Date => JType::class("java.util.Date"),
        P::Enum(name, _) => enum_type(name),
        P::Opaque(name) => match name.strip_suffix("[]") {
            Some(component) => JType::array(jtype(match component {
                "char" => P::Char,
                "int" => P::Int,
                "long" => P::Long,
                "float" => P::Float,
                "double" => P::Double,
                "short" => P::Short,
                "boolean" => P::Boolean,
                "byte" => P::Byte,
                "String" => P::String,
                _ => P::Object,
            })),
            None => JType::class(match name {
                "List" => "java.util.List",
                "Map" => "java.util.Map",
                "Set" => "java.util.Set",
                "Class" => "java.lang.Class",
                "Date" => "java.util.Date",
                "Instant" => "java.time.Instant",
                "LocalDate" => "java.time.LocalDate",
                "LocalTime" => "java.time.LocalTime",
                "Period" => "java.time.Period",
                "Supplier" => "java.util.function.Supplier",
                "RandomGenerator" => "java.util.random.RandomGenerator",
                other => return JType::class(&format!("shaded_package.net.datafaker.{other}")),
            }),
        },
    }
}

/// An enum parameter's class, by its shaded binary name.
fn enum_type(name: &str) -> JType {
    JType::class(&match name {
        "TimeUnit" => "java.util.concurrent.TimeUnit".to_string(),
        "ChronoUnit" => "java.time.temporal.ChronoUnit".to_string(),
        "AviationCodeType" => "shaded_package.net.datafaker.providers.base.AviationCodeType".to_string(),
        other => {
            let outer = match other {
                "PlanetName" => "Planet",
                "Category" => "FinancialTerms",
                "CompassPoint" => "Compass",
                "CreditCardType" => "Finance",
                "Browser" => "Http",
                _ => "Internet",
            };
            format!("shaded_package.net.datafaker.providers.base.{outer}${other}")
        }
    })
}

/// The typed class Velocity resolves a call on the faker, a provider or `RandomService` against: the public methods
/// of its datafaker-rs table, each running its body through [`Fake::run`].
fn class_def(target: Target) -> Arc<ClassDef> {
    static DEFS: LazyLock<Mutex<HashMap<String, Arc<ClassDef>>>> = LazyLock::new(Mutex::default);
    let name = class_name(target);
    let mut defs = DEFS.lock().unwrap_or_else(|e| e.into_inner());
    defs.entry(name.clone())
        .or_insert_with(|| {
            let mut def = ClassDef::new(&name);
            def.methods = target.methods().iter().map(|m| java_method(&name, m)).collect();
            Arc::new(def)
        })
        .clone()
}

fn java_method(class: &str, m: &'static Method) -> JMethod {
    let mut params: Vec<JType> = m.params.iter().map(|p| jtype(*p)).collect();
    if m.varargs && let Some(last) = params.pop() {
        params.push(JType::array(last));
    }
    JMethod {
        name: m.name.into(),
        params,
        returns: (m.returns != "void").then(JType::object),
        declaring_class: class.into(),
        is_static: false,
        varargs: m.varargs,
        invoke: Arc::new(move |target: &JValue, args: &[JValue]| match target {
            JValue::Object(o) => match o.as_any().downcast_ref::<Fake>() {
                Some(fake) => fake.run(m, args),
                None => Err(not_taken()),
            },
            _ => Err(not_taken()),
        }),
    }
}

/// The Java exception a Datafaker body threw. A helpful `NullPointerException` text names Datafaker's classes as the
/// jar MockServer shades them (`"shaded_package.net.datafaker.service.Range.from()"`).
fn java_error(e: &datafaker::Error) -> JError {
    let class = java_exception_class(e.simple_class());
    if !e.has_message() {
        return JError::without_message(&class);
    }
    let message = if e.simple_class() == "NullPointerException" { e.message().replace("\"net.datafaker.", "\"shaded_package.net.datafaker.") } else { e.message().to_string() };
    JError::new(&class, message)
}

fn java_exception_class(simple: &str) -> String {
    match simple {
        "IllegalArgumentException" | "RuntimeException" | "IllegalStateException" | "NumberFormatException" | "StringIndexOutOfBoundsException"
        | "IndexOutOfBoundsException" | "UnsupportedOperationException" | "NullPointerException" | "ArithmeticException"
        | "ArrayIndexOutOfBoundsException" | "ClassCastException" | "NegativeArraySizeException" => format!("java.lang.{simple}"),
        "NoSuchElementException" => "java.util.NoSuchElementException".into(),
        "DateTimeException" => "java.time.DateTimeException".into(),
        "DateTimeParseException" => "java.time.format.DateTimeParseException".into(),
        "UnsupportedTemporalTypeException" => "java.time.temporal.UnsupportedTemporalTypeException".into(),
        other => format!("net.datafaker.{other}"),
    }
}

fn class_name(target: Target) -> String {
    match target {
        // MockServer's own `Faker` subclass; its jar shades Datafaker under `shaded_package.`.
        Target::Faker => "org.mockserver.templates.engine.helpers.TemplateFaker".into(),
        Target::RandomService => "shaded_package.net.datafaker.service.RandomService".into(),
        Target::Provider(kind) => format!("shaded_package.{}", kind.class_name()),
    }
}

impl JObject for Fake {
    fn class_name(&self) -> String {
        class_name(self.target)
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if (name, args.len()) == ("toString", 0) {
            return ok(JValue::str(self.to_java_string()));
        }
        // `TemplateFaker.locale(String)` and, for Mustache, `locale()`
        match (self.target, name, args) {
            (Target::Faker, "locale", [JValue::Str(tag)]) => return ok(self.family.locale(Some(tag))),
            (Target::Faker, "locale", [JValue::Null]) => return ok(self.family.locale(None)),
            (Target::Faker, "locale", []) => return ok(JValue::Object(Arc::new(LocaleLookup(self.family.clone())))),
            // `Object.equals`: the same faker (a locale faker is cached), provider or random service
            (_, "equals", [other]) => {
                let same = matches!(other, JValue::Object(o) if o.as_any().downcast_ref::<Fake>().is_some_and(|f| Arc::ptr_eq(&f.faker, &self.faker) && f.target == self.target));
                return ok(JValue::Bool(same));
            }
            _ => {}
        }
        self.call(name, args)
    }

    fn to_java_string(&self) -> String {
        self.target.value().to_java_string(&self.faker)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `TemplateFunctions.FAKER`: one unseeded faker for every render.
static SHARED: LazyLock<JValue> = LazyLock::new(|| Family::root(None));

pub fn faker() -> JValue {
    SHARED.clone()
}

/// The per-engine seeded fakers of a server (`TemplateFunctions.resolveFaker(templateFakerSeed)`, held by each
/// `VelocityTemplateEngine` and `MustacheTemplateEngine`), created at an engine's first render.
#[derive(Default)]
pub struct Fakers {
    velocity: OnceLock<Option<JValue>>,
    mustache: OnceLock<Option<JValue>>,
}

impl Fakers {
    /// The engine's seeded faker, `None` when `templateFakerSeed` is 0 (the shared unseeded one applies).
    pub fn seeded(&self, config: &crate::Config, engine: super::Engine) -> Option<JValue> {
        let cell = match engine {
            super::Engine::Velocity => &self.velocity,
            super::Engine::Mustache => &self.mustache,
            super::Engine::JavaScript => return None,
        };
        cell.get_or_init(|| {
            let seed = config.int_property("templateFakerSeed", 0);
            (seed != 0).then(|| Family::root(Some(seed)))
        })
        .clone()
    }
}
