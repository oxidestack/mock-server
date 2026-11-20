//! The `systemValue` helper (`SystemValueTemplateHelper`, WireMock's `systemValue`): `env(name)` and
//! `property(name)` read an environment variable or a system property, but only a name on the startup-only
//! `templateSystemValueAllowList` (exact names, or prefixes ending in `*`). Any other name, and every name with the
//! default empty list, reads `""`, as an allowed name that is not set does. MockServer's own settings
//! (`mockserver.*`, `MOCKSERVER_*`, any case) and the JSSE store passwords are never read. A refused name is logged
//! at WARN once per server; the refusals a render met are logged when it ends ([`logged`]).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use java_compat::lang::{JError, JMap, JObject, JValue, MapKind};
use jmustache::{Lambda, MustacheError};

use crate::recorded::{Level, LogEntry};
use crate::state::State;

type Invocation = Option<Result<Option<JValue>, JError>>;

const DENIED_PREFIXES: [&str; 2] = ["mockserver.", "MOCKSERVER_"];
const DENIED_NAMES: [&str; 2] = ["javax.net.ssl.keyStorePassword", "javax.net.ssl.trustStorePassword"];
/// Longer names are refused without being remembered.
const MAX_NAME_LENGTH: usize = 256;
/// Distinct refused names logged per server.
const MAX_REFUSED_NAMES_LOGGED: usize = 1000;

/// `regionMatches(true, 0, prefix, 0, prefix.length())`: `name` starts with `prefix`, ignoring case.
fn starts_with_ignoring_case(name: &str, prefix: &str) -> bool {
    let (name, prefix): (Vec<u16>, Vec<u16>) = (name.encode_utf16().collect(), prefix.encode_utf16().collect());
    name.len() >= prefix.len() && String::from_utf16_lossy(&name[..prefix.len()]).to_lowercase() == String::from_utf16_lossy(&prefix).to_lowercase()
}

fn is_reserved(name: &str) -> bool {
    DENIED_PREFIXES.iter().any(|p| starts_with_ignoring_case(name, p)) || DENIED_NAMES.iter().any(|d| d.to_lowercase() == name.to_lowercase())
}

/// `prefixCoversReserved`: a prefix that names, or is the start of, a reserved name or prefix.
fn prefix_covers_reserved(prefix: &str) -> bool {
    is_reserved(prefix) || DENIED_PREFIXES.iter().chain(DENIED_NAMES.iter()).any(|r| starts_with_ignoring_case(r, prefix))
}

/// A parsed `templateSystemValueAllowList`.
pub struct AllowList {
    exact: Vec<String>,
    prefixes: Vec<String>,
    ignored: Vec<String>,
    reserved: Vec<String>,
}

impl AllowList {
    fn parse(text: &str) -> AllowList {
        let mut list = AllowList { exact: Vec::new(), prefixes: Vec::new(), ignored: Vec::new(), reserved: Vec::new() };
        for entry in text.split(',') {
            let name = entry.trim_matches(|c: char| c <= ' ');
            if name.is_empty() {
                continue;
            }
            match name.find('*') {
                None => {
                    if !list.exact.iter().any(|e| e == name) {
                        list.exact.push(name.to_string());
                    }
                    if is_reserved(name) {
                        list.reserved.push(name.to_string());
                    }
                }
                Some(star) if star == name.len() - 1 && star > 0 => {
                    let prefix = &name[..star];
                    list.prefixes.push(prefix.to_string());
                    if prefix_covers_reserved(prefix) {
                        list.reserved.push(name.to_string());
                    }
                }
                Some(_) => list.ignored.push(name.to_string()),
            }
        }
        list
    }

    /// Parsed once per text.
    fn of(text: &str) -> Arc<AllowList> {
        static CACHE: LazyLock<parking_lot::Mutex<HashMap<String, Arc<AllowList>>>> = LazyLock::new(Default::default);
        let mut cache = CACHE.lock();
        if cache.len() > 64 {
            cache.clear();
        }
        cache.entry(text.to_string()).or_insert_with(|| Arc::new(AllowList::parse(text))).clone()
    }

    fn allows(&self, name: &str) -> bool {
        self.exact.iter().any(|e| e == name) || self.prefixes.iter().any(|p| name.starts_with(p.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.prefixes.is_empty()
    }
}

fn allow_list(state: &State) -> Arc<AllowList> {
    AllowList::of(&state.config.startup_property("templateSystemValueAllowList").unwrap_or_default())
}

/// `logAllowList`: once at startup, what templates can read and the entries that were ignored or name reserved
/// settings; nothing for an empty list.
pub fn log_allow_list(state: &State) {
    let list = allow_list(state);
    if !list.ignored.is_empty() {
        crate::log::warn_event(state, LogEntry::at(Level::Warn, "templateSystemValueAllowList entries {} were ignored: an entry must be an exact name or a prefix followed by a single * at the end, and a bare * is not allowed because it would let templates read every environment variable and system property").args([list.ignored.join(", ")]));
    }
    if !list.reserved.is_empty() {
        crate::log::warn_event(state, LogEntry::at(Level::Warn, "templateSystemValueAllowList entries {} name or cover MockServer's own settings (mockserver.* and MOCKSERVER_*) or the javax.net.ssl store passwords, which systemValue never reads whatever the list says").args([list.reserved.join(", ")]));
    }
    if !list.is_empty() {
        crate::log::warn_event(state, LogEntry::at(Level::Warn, "templates can read the environment variables and system properties named {} and those starting with {} through systemValue, so anyone who can create expectations, call them or read the log can read their values").args([list.exact.join(", "), list.prefixes.join(", ")]));
    }
}

/// A name a render was refused: its kind (`environment variable`, `system property`), the name, and whether it is
/// reserved rather than off the list.
struct Refusal {
    kind: &'static str,
    name: String,
    reserved: bool,
}

thread_local! {
    /// The refusals of the render in progress on this thread, while [`logged`] runs it.
    static REFUSALS: RefCell<Option<Vec<Refusal>>> = const { RefCell::new(None) };
}

/// Runs `render`, then logs the names it was refused that this server has not logged before.
pub fn logged<T>(state: &State, render: impl FnOnce() -> T) -> T {
    let outer = REFUSALS.with(|r| r.borrow_mut().replace(Vec::new()));
    let out = render();
    let refusals = REFUSALS.with(|r| std::mem::replace(&mut *r.borrow_mut(), outer)).unwrap_or_default();
    for Refusal { kind, name, reserved } in refusals {
        let first = {
            let mut logged = state.template_system_values_refused.lock();
            name.encode_utf16().count() <= MAX_NAME_LENGTH && logged.len() < MAX_REFUSED_NAMES_LOGGED && logged.insert(name.clone())
        };
        if !first {
            continue;
        }
        let format = if reserved {
            "template systemValue refused to read {} {} because names starting with mockserver. or MOCKSERVER_, and the javax.net.ssl store passwords, are never readable by templates, so it returned an empty value"
        } else {
            "template systemValue refused to read {} {} because it is not on templateSystemValueAllowList, so it returned an empty value; add the name, or a prefix ending in *, to templateSystemValueAllowList when the server starts if templates should read it, remembering that anyone who can create expectations can then read its value"
        };
        crate::log::warn_event(state, LogEntry::at(Level::Warn, format).args([kind.to_string(), name]));
    }
    out
}

/// The names a server has logged a refusal for (`AllowList.refusedNamesLogged` of its logger).
pub type Refused = parking_lot::Mutex<HashSet<String>>;

/// One engine's `SystemValueTemplateHelper`: the allowed values it can read, taken when the render starts.
pub struct SystemValue {
    allow: Arc<AllowList>,
    env: HashMap<String, String>,
    properties: HashMap<String, String>,
}

impl SystemValue {
    pub fn new(state: &State) -> SystemValue {
        let allow = allow_list(state);
        let pick = |values: Vec<(String, String)>| -> HashMap<String, String> {
            if allow.is_empty() { HashMap::new() } else { values.into_iter().filter(|(k, _)| allow.allows(k) && !is_reserved(k)).collect() }
        };
        let env = pick(state.config.env_vars());
        let properties = pick(state.config.all_system_property_values());
        SystemValue { allow, env, properties }
    }

    /// `ON_DEMAND_HELPERS`' `new SystemValueTemplateHelper("", null)`: reads nothing and logs nothing, for a render
    /// no server's configuration reaches.
    pub fn nothing() -> SystemValue {
        SystemValue { allow: AllowList::of(""), env: HashMap::new(), properties: HashMap::new() }
    }

    fn read(&self, kind: &'static str, name: Option<&str>) -> String {
        let Some(name) = name.filter(|n| !n.is_empty()) else { return String::new() };
        let reserved = is_reserved(name);
        if !reserved && self.allow.allows(name) {
            let values = if kind == "environment variable" { &self.env } else { &self.properties };
            return values.get(name).cloned().unwrap_or_default();
        }
        REFUSALS.with(|r| {
            if let Some(list) = r.borrow_mut().as_mut() {
                list.push(Refusal { kind, name: name.to_string(), reserved });
            }
        });
        String::new()
    }

    pub fn env(&self, name: Option<&str>) -> String {
        self.read("environment variable", name)
    }

    pub fn property(&self, name: Option<&str>) -> String {
        self.read("system property", name)
    }

    /// The helper as Velocity sees it.
    pub fn velocity(self) -> JValue {
        JValue::Object(Arc::new(self))
    }

    /// `systemValueMustacheHelper`: `env` and `property` sections whose trimmed body is the name.
    pub fn mustache(self) -> JValue {
        let helper = Arc::new(self);
        let map = JMap::new(MapKind::Hash);
        let env = helper.clone();
        map.put_str("env", Lambda::with_class(LAMBDA_CLASS, move |name| Ok::<_, MustacheError>(env.env(Some(name.trim_matches(|c: char| c <= ' '))))));
        map.put_str("property", Lambda::with_class(LAMBDA_CLASS, move |name| Ok::<_, MustacheError>(helper.property(Some(name.trim_matches(|c: char| c <= ' '))))));
        JValue::Map(map)
    }
}

const LAMBDA_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheTemplateEngine$$Lambda/0x00007f3c8c0e4088";

impl JObject for SystemValue {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.helpers.SystemValueTemplateHelper".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        let text = |v: &JValue| match v {
            JValue::Null => Some(None),
            JValue::Str(s) => Some(Some(s.to_string())),
            _ => None,
        };
        match (name, args) {
            ("env", [n]) => Some(Ok(Some(JValue::str(self.env(text(n)?.as_deref()))))),
            ("property", [n]) => Some(Ok(Some(JValue::str(self.property(text(n)?.as_deref()))))),
            ("toString", []) => Some(Ok(Some(JValue::str("SystemValueTemplateHelper")))),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        "SystemValueTemplateHelper".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
