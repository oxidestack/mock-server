//! Rewrites accepted input JSON into the form MockServer echoes back (201 bodies, `retrieve`), as observed on
//! the oracle: fixed key orders, map-form multi-values, shorthand bodies, filled-in defaults.

use base64::Engine;
use serde_json::{Map, Value};

use crate::model;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Keys of `httpRequest` in the order `HttpRequestDTOSerializer` writes them (it writes nothing else).
const REQUEST_ORDER: &[&str] = &[
    "not", "method", "path", "pathParameters", "queryStringParameters", "headers", "cookies", "keepAlive", "secure",
    "respondBeforeBody", "clientCertificateChain", "clientCertificate", "jwt", "clientIp", "socketAddress", "protocol",
    "localAddress", "remoteAddress", "body", "originalBody",
];
/// Keys of `httpResponse` in the order `HttpResponseDTOSerializer` writes them (it writes nothing else).
const RESPONSE_ORDER: &[&str] = &[
    "statusCode", "statusCodeRange", "reasonPhrase", "headers", "trailers", "cookies", "body", "generateFromSchema",
    "delay", "connectionOptions", "recoverAfter", "primary",
];

/// The canonical form of one expectation; `id` must already be assigned.
pub fn expectation(input: &Map<String, Value>, id: &str) -> Value {
    let mut out = Map::new();
    for (key, value) in input {
        let value = match key.as_str() {
            "httpRequest" => shown_definition(request_definition(value)),
            "httpResponse" => response(value),
            "times" => times(value),
            "timeToLive" => time_to_live(value),
            "httpForward" => http_forward(value),
            "httpOverrideForwardedRequest" => override_forwarded(value),
            "httpForwardWithFallback" => forward_with_fallback(value),
            "httpForwardValidateAction" => forward_validate(value),
            "httpResponseTemplate" | "httpForwardTemplate" => template(value),
            "httpResponseClassCallback" | "httpForwardClassCallback" | "httpResponseObjectCallback" | "httpForwardObjectCallback" | "httpError" => {
                pojo(value)
            }
            // `HttpChaosProfileDTO`: non-null properties, alphabetical, probabilities as doubles.
            "chaos" => <crate::chaos::HttpChaosProfile as crate::chaos::HostProfile>::from_json(value)
                .map(|p| crate::chaos::HostProfile::to_json(&p))
                .unwrap_or_else(|_| sorted(value)),
            "httpResponses" => value.as_array().map(|rs| Value::Array(rs.iter().map(response).collect())).unwrap_or_else(|| value.clone()),
            "httpSseResponse" => sse_response(value),
            // `HttpLlmResponseDTO`: its fields in declaration order, every nested object's alphabetical.
            "httpLlmResponse" => {
                const ORDER: &[&str] = &["delay", "provider", "model", "completion", "embedding", "rerank", "moderation", "contentFilter", "conversationPredicates", "chaos", "primary"];
                let sorted = sorted(value);
                let mut out = Map::new();
                for key in ORDER {
                    match sorted.get(*key) {
                        Some(Value::Bool(false)) if *key == "primary" => {}
                        // `Completion` under the mapper's `NON_EMPTY`: empty strings and lists are left out.
                        Some(v) if *key == "completion" => {
                            out.insert((*key).into(), non_empty_bean(v));
                        }
                        Some(v) => {
                            out.insert((*key).into(), v.clone());
                        }
                        None => {}
                    }
                }
                Value::Object(out)
            }
            // `CaptureRuleDTO`s: always a list, each with its properties in alphabetical order.
            "capture" => {
                let rules = match value {
                    Value::Array(items) => items.clone(),
                    other => vec![other.clone()],
                };
                Value::Array(rules.into_iter().map(|mut r| {
                    if let Some(o) = r.as_object_mut() {
                        o.sort_keys();
                    }
                    r
                }).collect())
            }
            // `AfterActionDTO` / `ExpectationStepDTO`: properties alphabetical, each target in its own form.
            "rateLimit" => sorted(value),
            // `HttpWebSocketResponseDTO`: alphabetical, the subscription filter as a `GraphQLBodyDTO`.
            "httpWebSocketResponse" => {
                let mut ws = sorted(value);
                // an empty `messages` list is not written
                if let Some(o) = ws.as_object_mut().filter(|o| o.get("messages").and_then(Value::as_array).is_some_and(Vec::is_empty)) {
                    o.shift_remove("messages");
                }
                // `WebSocketMessageMatcherDTO`: frame type `ANY` unless given, `TEXT` whenever a text matcher is
                // (`withTextMatcher` sets it); an empty `responses` list is not written.
                if let Some(Value::Array(matchers)) = ws.get_mut("matchers") {
                    for m in matchers.iter_mut().filter_map(Value::as_object_mut) {
                        let frame = if m.get("textMatcher").is_some_and(|t| !t.is_null()) {
                            Value::from("TEXT")
                        } else {
                            m.get("frameType").filter(|f| !f.is_null()).cloned().unwrap_or_else(|| Value::from("ANY"))
                        };
                        m.insert("frameType".into(), frame);
                        if m.get("responses").and_then(Value::as_array).is_some_and(Vec::is_empty) {
                            m.shift_remove("responses");
                        }
                        m.sort_keys();
                    }
                }
                if let Some(filter) = value.get("graphqlSubscriptionFilter").filter(|f| f.is_object()) {
                    ws["graphqlSubscriptionFilter"] = graphql_body(filter);
                }
                ws
            }
            // `CrossProtocolScenario`s, alphabetical; an empty list is not written.
            "crossProtocolScenarios" => match value {
                Value::Array(items) if items.is_empty() => continue,
                other => sorted(other),
            },
            "beforeActions" | "afterActions" | "steps" => value.as_array().map(|items| Value::Array(items.iter().map(side_action).collect())).unwrap_or_else(|| value.clone()),
            // `Expectation.withNamespace`: trimmed, and a blank one is the global namespace (left out).
            "namespace" => match value.as_str().map(str::trim) {
                Some(ns) if !ns.is_empty() => Value::String(ns.to_string()),
                _ => continue,
            },
            // `Expectation.withMetadata`: an empty map is no metadata.
            "metadata" if value.as_object().is_some_and(serde_json::Map::is_empty) => continue,
            "dnsResponse" => dns_response(value),
            // `BinaryResponseDTO`: an empty `binaryData` is not serialised (`NON_EMPTY`), as an absent one
            "binaryResponse" => {
                let mut binary = value.clone();
                if let Some(o) = binary.as_object_mut()
                    && o.get("binaryData").and_then(Value::as_str) == Some("")
                {
                    o.shift_remove("binaryData");
                }
                binary
            }
            // `GrpcStreamResponseDTO`: alphabetical, its messages' too.
            // `GrpcStreamResponseDTO`: alphabetical, but its `Headers` print as any `keyToMultiValue`.
            "grpcStreamResponse" => with_headers(sorted(value), value),
            // `GrpcBidiResponseDTO`: no serializer of its own, so alphabetical like any DTO, its messages and rules
            // too; `primary` only when true, the delay in its own form.
            "grpcBidiResponse" => {
                let mut bidi = with_headers(sorted(value), value);
                if let Some(o) = bidi.as_object_mut() {
                    if o.get("primary").and_then(Value::as_bool) != Some(true) {
                        o.shift_remove("primary");
                    }
                    if let Some(d) = value.get("delay").filter(|d| d.is_object()).map(delay) {
                        o.insert("delay".into(), d);
                    }
                }
                bidi
            }
            _ => value.clone(),
        };
        out.insert(key.clone(), value);
    }
    out.insert("id".into(), Value::String(id.to_string()));
    out.entry("priority").or_insert(Value::from(0));
    out.entry("timeToLive").or_insert_with(unlimited);
    out.entry("times").or_insert_with(unlimited);
    // ExpectationDTO's properties serialise alphabetically.
    out.sort_keys();
    Value::Object(out)
}

/// `DnsResponseDTO`: alphabetical, record lists and their records without nulls, empty lists left out
/// (`NON_EMPTY`), `primary` only when true, the delay in its own form.
fn dns_response(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (k, value) in o {
        let value = match (k.as_str(), value) {
            (_, Value::Null) => continue,
            ("primary", p) if p.as_bool() != Some(true) => continue,
            ("delay", d) => delay(d),
            ("answerRecords" | "authorityRecords" | "additionalRecords", Value::Array(records)) if records.is_empty() => continue,
            // `NON_EMPTY`: a record's empty text (a TXT record's empty value) is left out too
            ("answerRecords" | "authorityRecords" | "additionalRecords", Value::Array(records)) => Value::Array(
                records
                    .iter()
                    .map(|r| match sorted(r) {
                        Value::Object(mut o) => {
                            o.retain(|_, v| v.as_str() != Some(""));
                            Value::Object(o)
                        }
                        other => other,
                    })
                    .collect(),
            ),
            (_, other) => sorted(other),
        };
        out.insert(k.clone(), value);
    }
    out.sort_keys();
    Value::Object(out)
}

/// `DnsRequestDefinitionDTO`: alphabetical, without nulls (`not` as given).
fn dns_request(input: &Map<String, Value>) -> Value {
    let mut out: Map<String, Value> = input
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.sort_keys();
    Value::Object(out)
}

/// A binary request definition (`httpRequest` with `binaryData`, empty or not).
pub fn is_binary_request(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("binaryData"))
}

/// A request definition (in canonical form) as the oracle prints it: `BinaryRequestDefinitionDTO` leaves an empty
/// `binaryData` out (`NON_EMPTY`), so an empty binary definition prints `{ }`. Matching reads the definition with the
/// key, which is what tells it apart from an HTTP one.
pub fn shown_definition(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut()
        && o.get("binaryData").and_then(Value::as_str) == Some("")
    {
        o.shift_remove("binaryData");
    }
    v
}

pub fn is_dns_request(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("dnsName"))
}

/// `GraphQLBodyDTOSerializer`.
fn graphql_body(v: &Value) -> Value {
    let mut out = Map::new();
    for flag in ["not", "optional"] {
        if v.get(flag).and_then(Value::as_bool) == Some(true) {
            out.insert(flag.into(), true.into());
        }
    }
    out.insert("type".into(), "GRAPHQL".into());
    out.insert("query".into(), v.get("query").cloned().unwrap_or(Value::Null));
    for key in ["operationName", "variablesSchema", "schema", "selectionSetMatchType", "fields"] {
        if let Some(value) = v.get(key).filter(|x| !x.is_null()) {
            out.insert(key.into(), value.clone());
        }
    }
    Value::Object(out)
}

/// A GraphQL request body's properties as `BodyDTODeserializer` reads them: a nested `graphQL` object's values
/// win over the top-level ones; schemas given as JSON become pretty-printed text.
fn graphql_fields(o: &Map<String, Value>) -> Map<String, Value> {
    const MATCH_TYPES: &[&str] = &["NORMALISED_STRING", "AST_EXACT", "AST_SUBSET"];
    let java_string = |v: &Value| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
    let mut out = Map::new();
    for flag in ["not", "optional"] {
        if self::flag(o, flag) {
            out.insert(flag.into(), true.into());
        }
    }
    // Top level: text fields only when strings, schemas as text or JSON.
    for (key, value) in o {
        let k = key.to_ascii_lowercase();
        let v = match (k.as_str(), value) {
            ("query" | "operationname", Value::String(_)) => value.clone(),
            ("variablesschema", Value::String(_)) | ("schema", Value::String(_)) => value.clone(),
            ("variablesschema", Value::Object(_)) => Value::String(crate::json::pretty(value)),
            ("schema", v) if !v.is_null() => Value::String(crate::json::pretty(value)),
            ("selectionsetmatchtype", Value::String(s)) if MATCH_TYPES.contains(&s.as_str()) => value.clone(),
            _ => continue,
        };
        let name = match k.as_str() {
            "query" => "query",
            "operationname" => "operationName",
            "variablesschema" => "variablesSchema",
            "schema" => "schema",
            _ => "selectionSetMatchType",
        };
        out.insert(name.into(), v);
    }
    // `graphQL: {…}`: `String.valueOf` for the texts, the variables schema always written as JSON.
    if let Some(Value::Object(g)) = field(o, "graphQL") {
        if let Some(q) = g.get("query") {
            out.insert("query".into(), java_string(q).into());
        }
        if let Some(n) = g.get("operationName") {
            out.insert("operationName".into(), java_string(n).into());
        }
        if let Some(s) = g.get("variablesSchema") {
            out.insert("variablesSchema".into(), crate::json::pretty(s).into());
        }
        if let Some(Value::String(m)) = g.get("selectionSetMatchType").filter(|m| m.as_str().is_some_and(|m| MATCH_TYPES.contains(&m))) {
            out.insert("selectionSetMatchType".into(), m.clone().into());
        }
        match g.get("schema") {
            Some(Value::String(s)) => {
                out.insert("schema".into(), s.clone().into());
            }
            Some(s) if !s.is_null() => {
                out.insert("schema".into(), crate::json::pretty(s).into());
            }
            _ => {}
        }
    }
    out
}

fn side_action(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (key, value) in o.iter().filter(|(_, v)| !v.is_null()) {
        let value = match key.as_str() {
            "httpRequest" => request_definition(value),
            "httpResponse" => response(value),
            "httpForward" => http_forward(value),
            "httpOverrideForwardedRequest" => override_forwarded(value),
            "httpRequestTemplate" => template(value),
            "httpClassCallback" | "httpObjectCallback" | "httpError" => pojo(value),
            _ => sorted(value),
        };
        out.insert(key.clone(), value);
    }
    out.sort_keys();
    Value::Object(out)
}

/// An expectation as log lines print it (`Expectation.toString`): the echoed form, with an LLM action's properties
/// sorted.
pub fn logged_expectation_ending(canonical: &Value, end_date: Option<i64>) -> Value {
    let mut shown = logged_expectation(canonical);
    // The log prints the `Expectation` object, whose time to live carries the `endDate` the DTO echo leaves out.
    if let (Some(end), Some(Value::Object(ttl))) = (end_date, shown.get_mut("timeToLive")) {
        ttl.insert("endDate".into(), end.into());
    }
    shown
}

/// An expectation as the entries about matching print it: [`logged_expectation_ending`] without its `metadata`
/// (`Expectation.cloneWithoutMetadata`, so a matched request never serialises it).
pub fn logged_matched_expectation(canonical: &Value, end_date: Option<i64>) -> Value {
    let mut shown = logged_expectation_ending(canonical, end_date);
    if let Value::Object(o) = &mut shown {
        o.shift_remove("metadata");
    }
    shown
}

pub fn logged_expectation(canonical: &Value) -> Value {
    let mut shown = canonical.clone();
    // The log's mapper writes map values `NON_EMPTY`: nulls, empty strings, empty lists and maps (once their own
    // values were left out) are not written, and a metadata left empty is not either; list items stay. The echo keeps
    // them all (`MetadataJson`).
    if let Value::Object(o) = &mut shown
        && let Some(metadata) = o.get_mut("metadata")
    {
        fn strip(v: &mut Value) {
            match v {
                Value::Object(o) => {
                    o.values_mut().for_each(strip);
                    o.retain(|_, v| match v {
                        Value::Null => false,
                        Value::String(s) => !s.is_empty(),
                        Value::Array(items) => !items.is_empty(),
                        Value::Object(inner) => !inner.is_empty(),
                        _ => true,
                    });
                }
                Value::Array(items) => items.iter_mut().for_each(strip),
                _ => {}
            }
        }
        strip(metadata);
        if metadata.as_object().is_some_and(serde_json::Map::is_empty) {
            o.shift_remove("metadata");
        }
    }
    // `DnsRequestDefinition` and `BinaryRequestDefinition` print as model objects, which have no `not`.
    if let Some(Value::Object(r)) = shown.get_mut("httpRequest").filter(|r| is_dns_request(r) || is_binary_request(r)) {
        r.shift_remove("not");
    }
    if let Some(llm) = shown.get("httpLlmResponse").map(sorted) {
        shown["httpLlmResponse"] = llm;
    }
    // `WasmBody` serialises as a model object, whose `value` is the module name.
    if let Some(Value::Object(body)) = shown.pointer_mut("/httpRequest/body") && body.get("type").and_then(Value::as_str) == Some("WASM") {
        let module = body.get("moduleName").cloned().unwrap_or(Value::Null);
        body.insert("value".into(), module);
    }
    // `HttpRequestSerializer` leaves out a body whose value is blank (a regex, JSON path or XPath body
    // read without its value).
    if let Some(Value::Object(r)) = shown.get_mut("httpRequest") {
        let blank = r.get("body").and_then(Value::as_object).is_some_and(|b| {
            ["regex", "jsonPath", "xpath"].iter().any(|k| b.get(*k).and_then(Value::as_str).is_some_and(|v| v.trim().is_empty()))
        });
        if blank {
            r.shift_remove("body");
        }
    }
    model_bodies(&mut shown);
    shown
}

/// Every `body` in a printed expectation as the model's body serializers write it, not the DTO echo's:
/// `XmlBodySerializer` and `StringBodySerializer` write no `rawBytes`, and `XmlBodySerializer` and
/// `BinaryBodySerializer` put `contentType` before `type`.
fn model_bodies(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (key, value) in o.iter_mut() {
                match value {
                    Value::Object(body) if key == "body" => *body = model_body(body),
                    _ if key == "body" => {}
                    _ => model_bodies(value),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(model_bodies),
        _ => {}
    }
}

fn model_body(body: &Map<String, Value>) -> Map<String, Value> {
    let leading: &[&str] = match body.get("type").and_then(Value::as_str) {
        Some("XML" | "BINARY") => &["not", "optional", "contentType", "type"],
        Some("STRING") => &[],
        // `AllOfBodySerializer`: each component through its own serializer.
        Some("ALL_OF") => {
            let mut out = body.clone();
            if let Some(Value::Array(parts)) = out.get_mut("bodyAllOf") {
                for part in parts.iter_mut() {
                    if let Value::Object(p) = part {
                        *p = model_body(p);
                    }
                }
            }
            return out;
        }
        _ => return body.clone(),
    };
    let mut out = Map::new();
    for key in leading {
        if let Some(v) = body.get(*key) {
            out.insert((*key).into(), v.clone());
        }
    }
    for (k, v) in body.iter().filter(|(k, _)| k.as_str() != "rawBytes") {
        if !out.contains_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Every object's properties in alphabetical order, nulls left out (a model object Jackson writes sorted).
/// `sorted` with a `headers` member put back in `KeysToMultiValuesSerializer`'s form (descending keys).
fn with_headers(mut out: Value, input: &Value) -> Value {
    if let (Some(o), Some(headers)) = (out.as_object_mut(), input.get("headers").filter(|h| h.is_object() || h.is_array())) {
        o.insert("headers".into(), multi_map(headers));
    }
    out
}

pub fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut out: Map<String, Value> = o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), sorted(v))).collect();
            out.sort_keys();
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// `HttpSseResponseDTO`: properties (and each event's) in alphabetical order, headers as a `keyToMultiValue`.
fn sse_response(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (k, value) in o {
        let value = match k.as_str() {
            _ if value.is_null() => continue,
            "headers" => match non_empty(multi_map(value)) {
                Some(h) => h,
                None => continue,
            },
            "delay" => delay(value),
            "events" => Value::Array(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| {
                        let mut e = e.as_object().cloned().unwrap_or_default();
                        e.retain(|_, v| !v.is_null());
                        if let Some(d) = e.get("delay").map(delay) {
                            e.insert("delay".into(), d);
                        }
                        e.sort_keys();
                        Value::Object(e)
                    })
                    .collect(),
            ),
            _ => value.clone(),
        };
        out.insert(k.clone(), value);
    }
    out.sort_keys();
    Value::Object(out)
}

/// Nested requests and responses of `httpOverrideForwardedRequest` (both shapes) in their canonical form.
fn override_forwarded(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (k, v) in o {
        let (key, v) = match k.as_str() {
            // The legacy `{httpRequest, httpResponse}` shape is echoed in the new form.
            "requestOverride" | "httpRequest" => ("requestOverride", request_definition(v)),
            "responseOverride" | "httpResponse" => ("responseOverride", response(v)),
            "requestModifier" | "responseModifier" => (k.as_str(), modifier(v)),
            "responseTemplate" => ("responseTemplate", template(v)),
            "delay" => ("delay", delay(v)),
            // `primary` only when true, as on any action.
            "primary" if v.as_bool() != Some(true) => continue,
            other => (other, v.clone()),
        };
        out.insert(key.to_string(), v);
    }
    out.sort_keys();
    Value::Object(out)
}

/// `requestModifier` / `responseModifier`: keys alphabetical at each level, maps in map form.
fn modifier(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (k, v) in o {
        let v = match (k.as_str(), v) {
            // `PathModifierDTO`: empty strings are left out (`NON_EMPTY`).
            ("path", Value::Object(p)) => {
                let mut p = p.clone();
                p.retain(|_, v| v.as_str() != Some("") && !v.is_null());
                p.sort_keys();
                Value::Object(p)
            }
            // `jsonMergePatch` is an arbitrary RFC 7386 document supplied verbatim by the caller, not a DTO field —
            // its key order is caller data, not ours to alphabetise (unlike `headers`/`cookies`/`queryStringParameters`
            // below, which really are `PATCH`-style op maps). `jsonPatch` is an array so it never reaches this match
            // (arms below only fire on `Value::Object`) and already passes through `_ => v.clone()` untouched.
            ("jsonMergePatch", _) => v.clone(),
            // `HttpResponseModifierCondition`: a fixed-shape DTO, alphabetical like any other.
            ("condition", Value::Object(c)) => {
                let mut c = c.clone();
                c.sort_keys();
                Value::Object(c)
            }
            // `modifiers`: a chain of nested `responseModifier`s, each canonicalised the same way as this one.
            ("modifiers", Value::Array(items)) => Value::Array(items.iter().map(modifier).collect()),
            (_, Value::Object(ops)) => {
                let mut ops_out = Map::new();
                for (op, value) in ops {
                    let value = if op == "remove" { value.clone() } else if k == "cookies" { single_map(value) } else { multi_map(value) };
                    ops_out.insert(op.clone(), value);
                }
                ops_out.sort_keys();
                Value::Object(ops_out)
            }
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    out.sort_keys();
    Value::Object(out)
}

/// `HttpForwardWithFallbackDTO`: alphabetical, the forward and the fallback response in their own forms, an empty
/// `fallbackOnStatusCodes` left out.
fn forward_with_fallback(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut o = o.clone();
    o.retain(|k, v| !(k == "fallbackOnStatusCodes" && v.as_array().is_some_and(Vec::is_empty)));
    let mut out = match pojo(&Value::Object(o)) {
        Value::Object(out) => out,
        other => return other,
    };
    if let Some(f) = out.get("httpForward").map(http_forward) {
        out.insert("httpForward".into(), f);
    }
    if let Some(r) = out.get("fallbackResponse").map(response) {
        out.insert("fallbackResponse".into(), r);
    }
    Value::Object(out)
}

/// `HttpForwardValidateActionDTO` built from the model: port 80, scheme HTTP, both validations on and STRICT unless
/// given.
fn forward_validate(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut o = o.clone();
    o.entry("port").or_insert(Value::from(80));
    o.entry("scheme").or_insert(Value::String("HTTP".into()));
    o.entry("validateRequest").or_insert(Value::Bool(true));
    o.entry("validateResponse").or_insert(Value::Bool(true));
    o.entry("validationMode").or_insert(Value::String("STRICT".into()));
    pojo(&Value::Object(o))
}

/// `HttpForward` defaults: port 80, scheme HTTP; properties alphabetical like any DTO.
fn http_forward(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut o = o.clone();
    // `NON_EMPTY`: an empty host is left out.
    if o.get("host").and_then(Value::as_str) == Some("") {
        o.shift_remove("host");
    }
    o.entry("port").or_insert(Value::from(80));
    o.entry("scheme").or_insert(Value::String("HTTP".into()));
    pojo(&Value::Object(o))
}

/// A DTO without a custom serializer: properties alphabetical (`SORT_PROPERTIES_ALPHABETICALLY`), `primary`
/// only when true, delays in their own canonical form.
fn pojo(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    for (k, v) in o {
        let v = match k.as_str() {
            "delay" | "chunkDelay" | "closeSocketDelay" => delay(v),
            "primary" if v.as_bool() != Some(true) => continue,
            _ if v.is_null() => continue,
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    out.sort_keys();
    Value::Object(out)
}

/// `HttpTemplateDTO`: alphabetical, with the nested response and modifier canonicalised.
fn template(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut o = o.clone();
    // `NON_EMPTY`: an empty template is left out.
    if o.get("template").and_then(Value::as_str) == Some("") {
        o.shift_remove("template");
    }
    // `withParameters`: empty parameters are none.
    if o.get("parameters").is_some_and(|p| p.is_null() || p.as_object().is_some_and(|p| p.is_empty())) {
        o.shift_remove("parameters");
    }
    if let Some(r) = o.get("responseOverride").map(response) {
        o.insert("responseOverride".into(), r);
    }
    if let Some(m) = o.get("responseModifier").map(modifier) {
        o.insert("responseModifier".into(), m);
    }
    pojo(&Value::Object(o))
}

/// `DelayDTO`: `value` is a primitive (0 when absent); a template survives only with its `templateType`
/// (`DelayDTO.buildObject`); the distribution's properties are alphabetical.
pub fn delay(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    if let Some(Value::Object(d)) = o.get("distribution") {
        let mut d: Map<String, Value> = d.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect();
        d.sort_keys();
        out.insert("distribution".into(), Value::Object(d));
    }
    if let (Some(t), Some(kind)) = (o.get("template").filter(|t| t.is_string()), o.get("templateType").filter(|t| t.is_string())) {
        out.insert("template".into(), t.clone());
        out.insert("templateType".into(), kind.clone());
    }
    if let Some(unit) = o.get("timeUnit").filter(|u| u.is_string()) {
        out.insert("timeUnit".into(), unit.clone());
    }
    out.insert("value".into(), o.get("value").filter(|v| v.is_number()).cloned().unwrap_or(Value::from(0)));
    Value::Object(out)
}

/// `SocketAddress` defaults: port 80, scheme HTTP.
fn socket_address(v: &Value) -> Value {
    let Some(o) = v.as_object() else { return v.clone() };
    let mut out = Map::new();
    if let Some(host) = o.get("host").filter(|h| !h.is_null()) {
        out.insert("host".into(), host.clone());
    }
    out.insert("port".into(), o.get("port").filter(|p| !p.is_null()).cloned().unwrap_or(Value::from(80)));
    out.insert("scheme".into(), o.get("scheme").filter(|s| !s.is_null()).cloned().unwrap_or(Value::String("HTTP".into())));
    Value::Object(out)
}

fn unlimited() -> Value {
    serde_json::json!({"unlimited": true})
}

fn times(v: &Value) -> Value {
    match v.get("remainingTimes") {
        Some(n) if !v.get("unlimited").and_then(Value::as_bool).unwrap_or(false) => serde_json::json!({"remainingTimes": n}),
        _ => unlimited(),
    }
}

fn time_to_live(v: &Value) -> Value {
    // Without a time unit the TTL is unlimited.
    if v.get("unlimited").and_then(Value::as_bool).unwrap_or(false) || v.get("timeToLive").is_none() || v.get("timeUnit").is_none_or(Value::is_null) {
        return unlimited();
    }
    let mut out = Map::new();
    if let Some(unit) = v.get("timeUnit") {
        out.insert("timeUnit".into(), unit.clone());
    }
    out.insert("timeToLive".into(), v["timeToLive"].clone());
    Value::Object(out)
}

fn ordered(input: &Map<String, Value>, order: &[&str], mut map: impl FnMut(&str, &Value) -> Option<Value>) -> Value {
    let mut out = Map::new();
    for key in order {
        if let Some(v) = input.get(*key) && let Some(v) = map(key, v) {
            out.insert((*key).to_string(), v);
        }
    }
    Value::Object(out)
}

/// A multimap echo, or `None` when it holds no entries (the serializers skip empty collections).
fn non_empty(v: Value) -> Option<Value> {
    match &v {
        Value::Object(o) if o.keys().all(|k| k == "keyMatchStyle") => None,
        Value::Array(a) if a.is_empty() => None,
        _ => Some(v),
    }
}

/// A request matcher (`httpRequest` in expectations, filters in verify/retrieve/clear).
pub fn request_definition(v: &Value) -> Value {
    let Some(input) = v.as_object() else { return v.clone() };
    // `RequestDefinitionDTODeserializer`: `anyOf`, then `if`, before the other kinds.
    if is_conditional_request(v) {
        return conditional_request(input);
    }
    if input.contains_key("specUrlOrPayload") {
        return openapi_definition(input);
    }
    if input.contains_key("dnsName") {
        return dns_request(input);
    }
    // `BinaryRequestDefinitionDTO`: alphabetical (`binaryData`, then `not`), without nulls.
    if input.contains_key("binaryData") {
        return dns_request(input);
    }
    if !is_http_request(input) {
        return v.clone();
    }
    // `HttpRequest.withSocketAddress` makes the request secure when the address scheme is HTTPS.
    let https = input.get("socketAddress").and_then(|s| s.get("scheme")).and_then(Value::as_str) == Some("HTTPS");
    let mut input = input.clone();
    if https {
        input.insert("secure".into(), Value::Bool(true));
    }
    ordered(&input, REQUEST_ORDER, |key, value| match key {
        _ if value.is_null() => None,
        "not" => value.as_bool().filter(|b| *b).map(Value::Bool),
        "clientIp" => model::NString::from_json(value).map(|s| s.to_json()),
        "method" | "path" => model::NString::from_json(value).filter(|s| s.value.as_deref().is_some_and(|v| !v.trim().is_empty())).map(|s| s.to_json()),
        "pathParameters" | "queryStringParameters" | "headers" => non_empty(multi_map(value)),
        "cookies" => non_empty(single_map(value)),
        "socketAddress" => Some(socket_address(value)),
        "clientCertificateChain" => Some(certificate_chain(value)),
        "body" => request_body(value),
        _ => Some(value.clone()),
    })
}

/// `X509CertificateSerializer` on each entry: its four names in a fixed order, blank ones left out.
fn certificate_chain(v: &Value) -> Value {
    let Some(entries) = v.as_array() else { return v.clone() };
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                let Some(o) = entry.as_object() else { return entry.clone() };
                let mut out = Map::new();
                for key in ["serialNumber", "issuerDistinguishedName", "subjectDistinguishedName", "signatureAlgorithmName"] {
                    if let Some(value) = o.get(key).and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                        out.insert(key.into(), value.into());
                    }
                }
                Value::Object(out)
            })
            .collect(),
    )
}

/// `OpenAPIDefinitionDTOSerializer`: `not` (only when true), a non-blank `operationId`, the spec (a JSON payload as
/// an object, anything else as a string) and a non-blank `contextPathPrefix`.
fn openapi_definition(input: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    if input.get("not").and_then(Value::as_bool) == Some(true) {
        out.insert("not".into(), Value::Bool(true));
    }
    let non_blank = |k: &str| input.get(k).and_then(Value::as_str).filter(|s| !s.trim().is_empty()).map(|s| Value::String(s.to_string()));
    if let Some(id) = non_blank("operationId") {
        out.insert("operationId".into(), id);
    }
    if let Some(spec) = input.get("specUrlOrPayload").and_then(crate::openapi::spec_text).filter(|s| !s.trim().is_empty()) {
        let value = if spec.trim().starts_with('{') {
            crate::json::parse_lenient(spec.as_bytes()).unwrap_or(Value::String(spec))
        } else {
            Value::String(spec)
        };
        out.insert("specUrlOrPayload".into(), value);
    }
    if let Some(prefix) = non_blank("contextPathPrefix") {
        out.insert("contextPathPrefix".into(), prefix);
    }
    Value::Object(out)
}

/// A compound request definition: a conditional (`if`, with optional `then` and `else`) or an `anyOf` (logical OR
/// of branches). Neither is an `HttpRequest`.
pub fn is_conditional_request(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("if") || o.contains_key("anyOf"))
}

/// An `anyOf` request definition (`RequestDefinitionDTODeserializer` reads one before a conditional).
pub fn is_any_of_request(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("anyOf"))
}

/// `ConditionalRequestDefinitionSerializer`: `not` (only when true), then each branch present, in canonical form.
/// `AnyOfRequestDefinitionSerializer`: `not` (only when true), then `anyOf`, its non-null branches in canonical form.
fn conditional_request(input: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    if input.get("not").and_then(Value::as_bool) == Some(true) {
        out.insert("not".into(), Value::Bool(true));
    }
    if input.contains_key("anyOf") {
        let branches = input.get("anyOf").and_then(Value::as_array).map(|a| a.iter().filter(|b| !b.is_null()).map(request_definition).collect()).unwrap_or_default();
        out.insert("anyOf".into(), Value::Array(branches));
        return Value::Object(out);
    }
    for key in ["if", "then", "else"] {
        if let Some(branch) = input.get(key).filter(|b| !b.is_null()) {
            out.insert(key.into(), request_definition(branch));
        }
    }
    Value::Object(out)
}

fn is_http_request(input: &Map<String, Value>) -> bool {
    !["specUrlOrPayload", "binaryData", "dnsName", "if", "anyOf"].iter().any(|k| input.contains_key(*k))
}

pub fn response(v: &Value) -> Value {
    let Some(input) = v.as_object() else { return v.clone() };
    ordered(input, RESPONSE_ORDER, |key, value| match key {
        _ if value.is_null() => None,
        "headers" | "trailers" => non_empty(multi_map(value)),
        "cookies" => non_empty(single_map(value)),
        "body" => response_body(value),
        "delay" => Some(delay(value)),
        "connectionOptions" => Some(pojo(value)),
        // `HttpResponseDTOSerializer` writes `primary` last, and only when true.
        "primary" => (value.as_bool() == Some(true)).then(|| Value::Bool(true)),
        // `RecoverAfterDTO`: alphabetical, the failure response in its own form.
        "recoverAfter" => Some(match pojo(value) {
            Value::Object(mut r) => {
                if let Some(failure) = r.get("failResponse").map(response) {
                    r.insert("failResponse".into(), failure);
                }
                Value::Object(r)
            }
            other => other,
        }),
        _ => Some(value.clone()),
    })
}

/// A blank JSON body echoes `null`.
fn blank_bodies(v: Value) -> Value {
    match v {
        Value::Object(o) if o.get("type").and_then(Value::as_str) == Some("JSON") && o.get("json").and_then(Value::as_str).is_some_and(|s| s.trim().is_empty()) => {
            Value::Null
        }
        other => other,
    }
}

fn request_body(v: &Value) -> Option<Value> {
    Some(blank_bodies(body(v)))
}

/// `BodyWithContentTypeDTODeserializer` builds only binary, JSON, string, XML and file bodies; any other type
/// becomes `{ }`, and `HttpResponseDTOSerializer` skips empty string, JSON and XML bodies.
fn response_body(v: &Value) -> Option<Value> {
    match response_body_built(v) {
        // A blank JSON body is dropped from the echo too (`JsonBody` of "" builds no body).
        Value::Null => None,
        built if is_empty_text_body(&built) => None,
        other => Some(other),
    }
}

/// An empty string or XML body as [`response_body_built`] leaves it (a binary one is kept).
fn is_empty_text_body(built: &Value) -> bool {
    match built {
        Value::String(s) => s.is_empty(),
        Value::Object(o) => ["string", "xml"].iter().any(|k| o.get(*k).and_then(Value::as_str) == Some("")) && o.get("type").and_then(Value::as_str) != Some("BINARY"),
        _ => false,
    }
}

/// The body the event log prints for a response whose echo leaves an empty body out: `""` for an empty string or
/// XML body, `null` for a blank JSON one (`returning response` prints the model, whose body the DTO echo skips).
pub fn empty_response_body(response: &Value) -> Option<Value> {
    let body = response.get("body").filter(|b| !b.is_null())?;
    match response_body_built(body) {
        Value::Null => Some(Value::Null),
        built if is_empty_text_body(&built) => Some(Value::String(String::new())),
        _ => None,
    }
}

/// `response` with `body` put back in its place (before `delay` and the other later fields), unless it has one.
pub fn with_response_body(response: &Value, body: &Value) -> Value {
    let Some(o) = response.as_object().filter(|o| !o.contains_key("body")) else { return response.clone() };
    let after = &RESPONSE_ORDER[RESPONSE_ORDER.iter().position(|k| *k == "body").unwrap_or(0) + 1..];
    let mut out = Map::new();
    for (k, v) in o {
        if after.contains(&k.as_str()) && !out.contains_key("body") {
            out.insert("body".into(), body.clone());
        }
        out.insert(k.clone(), v.clone());
    }
    out.entry("body").or_insert_with(|| body.clone());
    Value::Object(out)
}

/// A response body in its echoed form, empty ones included.
fn response_body_built(v: &Value) -> Value {
    let typed = match v {
        Value::Object(o) => match response_body_type(o) {
            // No type: the whole object is a JSON body.
            None => return json_body(model::jackson_echo_tree(v)),
            Some((kind, payload)) => {
                const BUILT: &[(&str, &str)] = &[("BINARY", "base64Bytes"), ("JSON", "json"), ("STRING", "string"), ("XML", "xml"), ("FILE", "filePath")];
                let Some((_, payload_key)) = BUILT.iter().find(|(t, _)| *t == kind) else {
                    // `JsonBody.json("{ }")`, given the body's `optional` (`result.withOptional(optional)`).
                    let mut empty = Map::new();
                    empty.insert("type".into(), "JSON".into());
                    empty.insert("json".into(), Value::Object(Map::new()));
                    if let Some(optional) = o.iter().rfind(|(k, _)| k.eq_ignore_ascii_case("optional")) {
                        empty.insert(optional.0.clone(), optional.1.clone());
                    }
                    return blank_bodies(body(&Value::Object(empty)));
                };
                // Rebuilt from what the deserializer reads (a string body keeps `subString`, below); the payload is
                // the last payload field, whatever its name. `not` is `Boolean.parseBoolean` of the value's text, put
                // back by `HttpResponseDTO.buildObject` (`Not.not(body.buildObject(), body.getNot())`, upstream master).
                let mut typed = Map::new();
                typed.insert("type".into(), kind.into());
                if kind != "BINARY" && let Some(p) = payload {
                    typed.insert((*payload_key).into(), p.clone());
                }
                for (k, value) in o {
                    if k.eq_ignore_ascii_case("not") {
                        let text = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
                        typed.insert("not".into(), Value::Bool(text.eq_ignore_ascii_case("true")));
                        continue;
                    }
                    // Master reads a string body's `subString` too (`Boolean.parseBoolean`), and the DTO prints it
                    // when true (harvested from BodyWithContentTypeDTODeserializerTest).
                    if kind == "STRING" && k.eq_ignore_ascii_case("subString") {
                        let text = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
                        if text.eq_ignore_ascii_case("true") {
                            typed.insert("subString".into(), Value::Bool(true));
                        }
                        continue;
                    }
                    let keep = ["optional", "contentType", "charset", "rawBytes"].iter().any(|m| k.eq_ignore_ascii_case(m))
                        || (kind == "BINARY" && k.eq_ignore_ascii_case("base64Bytes"))
                        || (kind == "FILE" && (k.eq_ignore_ascii_case("templateType") || k.eq_ignore_ascii_case("templatedFilePath")));
                    if keep {
                        typed.insert(k.clone(), value.clone());
                    }
                }
                Value::Object(typed)
            }
        },
        other => other.clone(),
    };
    // A scalar JSON value given as a string keeps its text ([`body`]: `"json": "\"done\"  \r\t "` echoes
    // as `"done"  \r\t `).
    blank_bodies(body(&typed))
}

/// `BodyWithContentTypeDTODeserializer`'s body type and payload value, read in key order: a valid `type` value or a
/// typed payload key (`base64Bytes`, `json`, `string`, `xml`, `filePath`), whichever comes last; the payload is the
/// last of the payload keys it reads. `None` when nothing names a type.
pub fn response_body_type(o: &Map<String, Value>) -> Option<(&'static str, Option<&Value>)> {
    const PAYLOADS: &[&str] = &["string", "regex", "json", "jsonSchema", "jsonPath", "xml", "xmlSchema", "xpath", "base64Bytes", "filePath"];
    const TYPED: &[(&str, &str)] = &[("base64Bytes", "BINARY"), ("json", "JSON"), ("string", "STRING"), ("xml", "XML"), ("filePath", "FILE")];
    let mut kind: Option<&'static str> = None;
    let mut payload = None;
    for (key, value) in o {
        if key.eq_ignore_ascii_case("type") {
            // `Body.Type.valueOf(String.valueOf(value))`: exact names only.
            let name = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
            if let Some(t) = model::BODY_TYPES.iter().chain(&["LOG_EVENT"]).find(|t| **t == name) {
                kind = Some(t);
            }
        }
        if PAYLOADS.iter().any(|p| key.eq_ignore_ascii_case(p)) && kind != Some("PARAMETERS") {
            if let Some((_, t)) = TYPED.iter().find(|(p, _)| key.eq_ignore_ascii_case(p)) {
                kind = Some(t);
            }
            payload = Some(value);
        }
    }
    kind.map(|k| (k, payload))
}

/// Whether an expectation (input form) holds a JSON body whose text is not JSON at all. `JsonBodyDTOSerializer`
/// reads the text with `readTree` before writing it (upstream master), so `ExpectationSerializer` throws for such an
/// expectation: it is stored, but each JSON rendering of it fails.
pub fn unwritable_json_body(expectation: &Map<String, Value>) -> bool {
    let unreadable = |payload: Option<&Value>| match payload {
        Some(Value::String(s)) if !s.trim().is_empty() => !scalar_json_text(s) && !matches!(json_payload(&Value::String(s.clone())), Value::Object(_) | Value::Array(_)),
        _ => false,
    };
    let request = expectation.get("httpRequest").and_then(|r| r.get("body")).and_then(Value::as_object);
    let response = expectation.get("httpResponse").and_then(|r| r.get("body")).and_then(Value::as_object);
    request.is_some_and(|o| body_type(o).as_deref() == Some("JSON") && unreadable(field(o, "json")))
        || response.is_some_and(|o| matches!(response_body_type(o), Some(("JSON", payload)) if unreadable(payload)))
}

/// `keyToMultiValue` in its echoed form (`KeysToMultiValuesSerializer`).
pub fn multi_map(v: &Value) -> Value {
    if !(v.is_object() || v.is_array()) {
        return v.clone();
    }
    let (entries, style) = model::multi_values_with_style(v);
    model::multi_values_json(&entries, style.as_deref())
}

/// `keyToValue` (cookies) in its echoed form (`CookiesSerializer`).
pub fn single_map(v: &Value) -> Value {
    if !(v.is_object() || v.is_array()) {
        return v.clone();
    }
    model::key_values_json(&model::key_values(v))
}

/// Payload key → body `type`, for bodies given without a `type` (`BodyDTODeserializer`).
const INFERRED_TYPES: &[(&str, &str)] = &[
    ("string", "STRING"),
    ("regex", "REGEX"),
    ("fuzzy", "FUZZY"),
    ("json", "JSON"),
    ("jsonSchema", "JSON_SCHEMA"),
    ("jsonPath", "JSON_PATH"),
    ("xml", "XML"),
    ("xmlSchema", "XML_SCHEMA"),
    ("xpath", "XPATH"),
    ("parameters", "PARAMETERS"),
    ("base64Bytes", "BINARY"),
];
const BODY_MODIFIERS: &[&str] = &[
    "not", "optional", "contentType", "charset", "subString", "matchType", "matchNumbersAsStrings", "namespacePrefixes", "threshold", "ignoreCase",
    // `BodyDateTimeField`: read on every body, used by JSON_PATH and XPATH ones
    "dateTime",
];

/// The body `type` of an object body, explicit or inferred; `None` means a raw JSON body.
pub fn body_type(o: &Map<String, Value>) -> Option<String> {
    if let Some(t) = o.iter().find(|(k, _)| k.eq_ignore_ascii_case("type")).and_then(|(_, v)| v.as_str()) {
        let t = t.to_ascii_uppercase();
        // `Body.Type.valueOf` failing is ignored (logged at debug): the payload keys decide the type.
        if model::BODY_TYPES.contains(&t.as_str()) {
            return Some(t);
        }
    }
    // `BodyDTODeserializer`: a `bodyAllOf` array makes the body `ALL_OF` whatever else it holds.
    if field(o, "bodyAllOf").is_some_and(Value::is_array) {
        return Some("ALL_OF".into());
    }
    let payload = INFERRED_TYPES.iter().find(|(key, _)| o.keys().any(|k| k.eq_ignore_ascii_case(key)))?;
    let all_known = o
        .keys()
        .all(|k| k.eq_ignore_ascii_case(payload.0) || k.eq_ignore_ascii_case("type") || BODY_MODIFIERS.iter().any(|m| k.eq_ignore_ascii_case(m)));
    all_known.then(|| payload.1.to_string())
}

/// Case-insensitive field lookup, as the body deserialiser does.
pub fn field<'a>(o: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    o.get(name).or_else(|| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

/// A `FILE` body's `templatedFilePath` (9.2.0): `Boolean.parseBoolean(String.valueOf(value))` when the key is
/// there (`"TRUE"` is true, `1` or `"yes"` false), `None` when it is not.
pub fn templated_file_path(o: &Map<String, Value>) -> Option<bool> {
    field(o, "templatedFilePath").map(|v| match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    })
}

fn flag(o: &Map<String, Value>, name: &str) -> bool {
    field(o, name).and_then(Value::as_bool).unwrap_or(false)
}

/// Parses a JSON payload given as a string; leaves it a string when it is not JSON. An object or array is read as
/// leniently as MockServer's mapper does (single quotes, unquoted names, comments…).
pub fn json_payload(v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| {
            let structured = s.trim_start().starts_with(['{', '[']);
            structured.then(|| crate::json::parse_lenient(s.as_bytes()).ok()).flatten().unwrap_or_else(|| v.clone())
        }),
        other => other.clone(),
    }
}

/// A `StringBody`'s `rawBytes`: the text in the content type's charset, else
/// `DEFAULT_TEXT_HTTP_CHARACTER_SET` (ISO-8859-1, unmappable characters as `?`).
fn model_bytes(text: &str, content_type: Option<&str>) -> Vec<u8> {
    let has_charset = content_type.is_some_and(|ct| ct.split(';').any(|p| p.trim().to_ascii_lowercase().starts_with("charset=")));
    if has_charset { encode(text, content_type) } else { encode(text, Some("text/plain; charset=iso-8859-1")) }
}

/// Encodes `text` in the charset named by a `Content-Type` value (`media_type::encode`: UTF-8 when none or an
/// unknown one is named).
pub fn encode(text: &str, content_type: Option<&str>) -> Vec<u8> {
    crate::media_type::encode(text, crate::media_type::MediaType::parse(content_type).charset())
}

thread_local! {
    /// Set while building the form `ExpectationSerializer(logger, serialiseDefaultValues = true)` writes.
    static DEFAULT_VALUES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn default_values() -> bool {
    DEFAULT_VALUES.with(|d| d.get())
}

/// One expectation as the code formats embed it (`serialiseDefaultValues = true`): string and JSON bodies are
/// never shortened to their value, and a string body keeps the bytes it was given.
pub fn expectation_with_default_values(input: &Map<String, Value>, id: &str) -> Value {
    DEFAULT_VALUES.with(|d| d.set(true));
    let out = expectation(input, id);
    DEFAULT_VALUES.with(|d| d.set(false));
    out
}

/// A JSON body as `JsonBodyDTOSerializer` writes it: the value, or `{type, json}` with default values.
fn json_body(json: Value) -> Value {
    if default_values() {
        let mut o = Map::new();
        o.insert("type".into(), "JSON".into());
        o.insert("json".into(), json);
        Value::Object(o)
    } else {
        json
    }
}

/// Whether a JSON body's text reads (as leniently as Jackson's `readTree`) as a value node, which
/// `JsonBodyDTOSerializer` writes back as that very text (`writeRawValue`).
fn scalar_json_text(s: &str) -> bool {
    crate::json::parse_lenient(s.as_bytes()).is_ok_and(|v| !v.is_object() && !v.is_array())
}

/// A `bodyAllOf` component as `BodyDTODeserializer` reads it: written out by an `ObjectMapper` whose inclusion is
/// `NON_EMPTY` and read back, so every object drops its entries that are null, `""`, `[]` or (recursively) empty
/// objects (a null payload field reads as an absent one).
fn all_of_child(v: &Value) -> Value {
    fn empty(v: &Value) -> bool {
        match v {
            Value::Null => true,
            Value::String(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.values().all(empty),
            _ => false,
        }
    }
    match v {
        Value::Object(o) => Value::Object(o.iter().filter(|(_, v)| !empty(v)).map(|(k, v)| (k.clone(), all_of_child(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(all_of_child).collect()),
        other => other.clone(),
    }
}

pub fn body(v: &Value) -> Value {
    let o = match v {
        Value::Object(o) => o,
        Value::String(s) => {
            let mut o = Map::new();
            o.insert("type".into(), "STRING".into());
            o.insert("string".into(), s.clone().into());
            return body(&Value::Object(o));
        }
        Value::Array(_) => return json_body(model::jackson_echo_tree(v)),
        other => return other.clone(),
    };
    // Upstream reads JSON arrays as `Object[]`, so a `fields` key always means multipart (`BodyDTODeserializer`).
    if ["fields", "filenames", "partContentTypes"].iter().any(|f| o.keys().any(|k| k.eq_ignore_ascii_case(f))) {
        let mut out = Map::new();
        if flag(o, "not") {
            out.insert("not".into(), Value::Bool(true));
        }
        out.insert("type".into(), "MULTIPART".into());
        for key in ["fields", "filenames", "partContentTypes"] {
            if let Some(m) = field(o, key).filter(|m| m.is_object()).map(multi_map).and_then(non_empty) {
                out.insert(key.into(), m);
            }
        }
        return Value::Object(out);
    }
    if field(o, "graphQL").is_some_and(Value::is_object) || body_type(o).as_deref() == Some("GRAPHQL") {
        return graphql_body(&Value::Object(graphql_fields(o)));
    }
    let Some(kind) = body_type(o) else { return json_body(model::jackson_echo_tree(v)) };
    let not = flag(o, "not");
    let optional = flag(o, "optional");
    // `MediaType.parse(contentType).toString()`: a blank one is none; else a `charset` field names the type's
    // default content type with that charset (JSON and string bodies).
    let charset = field(o, "charset").and_then(Value::as_str).and_then(crate::media_type::canonical_charset);
    let content_type = match field(o, "contentType") {
        Some(Value::String(ct)) => Some(crate::media_type::normalise(ct)).filter(|ct| !ct.is_empty()).map(Value::String),
        Some(other) => Some(other.clone()),
        None => None,
    }
    .or_else(|| match (kind.as_str(), &charset) {
        ("JSON", Some(c)) => Some(format!("application/json; charset={c}").into()),
        ("STRING", Some(c)) => Some(format!("text/plain; charset={c}").into()),
        ("XML", Some(c)) => Some(format!("application/xml; charset={c}").into()),
        _ => None,
    });
    let mut out = Map::new();
    // The body serialisers write `not`, then `optional`, before everything else.
    let put_not = |out: &mut Map<String, Value>| {
        if not {
            out.insert("not".into(), Value::Bool(true));
        }
        if optional {
            out.insert("optional".into(), Value::Bool(true));
        }
    };
    match kind.as_str() {
        "STRING" => {
            // `StringBody` stores a blank value as "" but keeps the bytes it was given.
            let original = field(o, "string").map(|s| s.as_str().map(str::to_string).unwrap_or_else(|| s.to_string())).unwrap_or_default();
            let string = if original.trim().is_empty() { String::new() } else { original.clone() };
            let sub = flag(o, "subString");
            if !not && !optional && !sub && content_type.is_none() && !default_values() {
                return Value::String(string);
            }
            put_not(&mut out);
            out.insert("type".into(), "STRING".into());
            out.insert("string".into(), string.into());
            let raw = field(o, "rawBytes").and_then(Value::as_str).map(str::to_string);
            out.insert("rawBytes".into(), raw.unwrap_or_else(|| B64.encode(model_bytes(&original, content_type.as_ref().and_then(Value::as_str)))).into());
            if sub {
                out.insert("subString".into(), Value::Bool(true));
            }
            if let Some(ct) = content_type {
                out.insert("contentType".into(), ct);
            }
        }
        "JSON" => {
            // Given as a string, the JSON keeps each number's own text (a `BigDecimal` read); given as a value,
            // Jackson has already read it into doubles.
            // `JsonBodyDTOSerializer` writes a scalar given as a string as the text it was given (`writeRawValue`),
            // white space included: a number holding that text, which the matcher reads again.
            let json = match field(o, "json") {
                Some(Value::String(s)) if scalar_json_text(s) => model::number(s),
                Some(Value::String(_)) => model::big_decimal_tree(&json_payload(field(o, "json").unwrap_or(&Value::Null))),
                other => model::jackson_echo_tree(&json_payload(other.unwrap_or(&Value::Null))),
            };
            let strict = field(o, "matchType").and_then(Value::as_str) == Some("STRICT");
            // Only `JsonBody.DEFAULT_JSON_CONTENT_TYPE` (`application/json; charset=utf-8`) goes unwritten; a plain
            // `application/json` is written.
            let content_type = content_type.filter(|ct| ct.as_str() != Some("application/json; charset=utf-8"));
            let numbers_as_strings = flag(o, "matchNumbersAsStrings");
            // `JsonBodyDTOSerializer` writes the bare JSON value, scalars included (`writeRawValue`); a string that
            // is not JSON at all stays in the typed form.
            let parsed = match field(o, "json") {
                Some(Value::String(s)) => serde_json::from_str::<Value>(s).is_ok() || !json.is_string(),
                _ => true,
            };
            if !not && !optional && !strict && !numbers_as_strings && content_type.is_none() && parsed {
                return json_body(json);
            }
            put_not(&mut out);
            if let Some(ct) = content_type {
                out.insert("contentType".into(), ct);
            }
            out.insert("type".into(), "JSON".into());
            out.insert("json".into(), json);
            if strict {
                out.insert("matchType".into(), "STRICT".into());
            }
            if numbers_as_strings {
                out.insert("matchNumbersAsStrings".into(), Value::Bool(true));
            }
        }
        "XML" => {
            put_not(&mut out);
            out.insert("type".into(), "XML".into());
            let xml = field(o, "xml").cloned().unwrap_or(Value::String(String::new()));
            let text = xml.as_str().unwrap_or_default().to_string();
            out.insert("xml".into(), xml);
            out.insert("rawBytes".into(), B64.encode(encode(&text, content_type.as_ref().and_then(Value::as_str))).into());
            if let Some(ct) = content_type {
                out.insert("contentType".into(), ct);
            }
        }
        // `BinaryBodyDTOSerializer`: the bytes are the last `rawBytes`/`base64Bytes` string that decodes (none: empty).
        "BINARY" => {
            put_not(&mut out);
            out.insert("type".into(), "BINARY".into());
            let bytes = o
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("rawBytes") || k.eq_ignore_ascii_case("base64Bytes"))
                .filter_map(|(_, v)| v.as_str().and_then(crate::import::base64_decode))
                .next_back()
                .unwrap_or_default();
            out.insert("base64Bytes".into(), B64.encode(bytes).into());
            if let Some(ct) = content_type {
                out.insert("contentType".into(), ct);
            }
        }
        "JSON_SCHEMA" => {
            put_not(&mut out);
            out.insert("type".into(), "JSON_SCHEMA".into());
            // The schema is kept as the text of the `Map` it was read into: floats print as `Double`s (`1.0E-4`), not
            // re-read as `BigDecimal`s the way a JSON body is (oracle: `user_schema_reports`, "multipleof-num").
            out.insert("jsonSchema".into(), model::jackson_tree(&json_payload(field(o, "jsonSchema").unwrap_or(&Value::Null))));
            if let Some(styles) = field(o, "parameterStyles").filter(|s| s.as_object().is_some_and(|m| !m.is_empty())) {
                out.insert("parameterStyles".into(), styles.clone());
            }
        }
        // `AllOfBodyDTOSerializer`: each component in its own form.
        "ALL_OF" => {
            put_not(&mut out);
            out.insert("type".into(), "ALL_OF".into());
            let parts = field(o, "bodyAllOf").and_then(Value::as_array).map(|b| b.iter().map(|c| body(&all_of_child(c))).collect()).unwrap_or_default();
            out.insert("bodyAllOf".into(), Value::Array(parts));
        }
        "FUZZY" => {
            put_not(&mut out);
            out.insert("type".into(), "FUZZY".into());
            out.insert("fuzzy".into(), field(o, "fuzzy").cloned().unwrap_or(Value::String(String::new())));
            let threshold = field(o, "threshold").and_then(Value::as_f64).unwrap_or(0.8);
            out.insert("threshold".into(), model::number(&java_compat::double_to_string(threshold)));
            if flag(o, "ignoreCase") {
                out.insert("ignoreCase".into(), Value::Bool(true));
            }
        }
        "FILE" => {
            // `FileBodyDTO`: alphabetical, the template type only when given.
            if let Some(ct) = content_type {
                out.insert("contentType".into(), ct);
            }
            out.insert("filePath".into(), field(o, "filePath").cloned().unwrap_or(Value::Null));
            put_not(&mut out);
            if let Some(t) = field(o, "templateType").filter(|t| t.is_string()) {
                out.insert("templateType".into(), t.clone());
            }
            if let Some(templated) = templated_file_path(o) {
                out.insert("templatedFilePath".into(), Value::Bool(templated));
            }
            out.insert("type".into(), "FILE".into());
        }
        "PARAMETERS" => {
            put_not(&mut out);
            out.insert("type".into(), "PARAMETERS".into());
            // `ParameterBodyDTOSerializer` leaves out an empty parameter map.
            let parameters = multi_map(field(o, "parameters").unwrap_or(&Value::Null));
            let empty = match &parameters {
                Value::Null => true,
                Value::Object(m) => m.is_empty(),
                Value::Array(a) => a.is_empty(),
                _ => false,
            };
            if !empty {
                out.insert("parameters".into(), parameters);
            }
        }
        // `WasmBodyDTO` has no serializer of its own: Jackson writes its properties alphabetically.
        "WASM" => {
            // null and "" are left out (the oracle echoes neither)
            if let Some(name) = field(o, "moduleName").filter(|v| !v.is_null() && v.as_str() != Some("")) {
                out.insert("moduleName".into(), name.clone());
            }
            put_not(&mut out);
            out.insert("type".into(), "WASM".into());
        }
        other => {
            put_not(&mut out);
            out.insert("type".into(), other.into());
            let payload = INFERRED_TYPES.iter().find(|(_, t)| *t == other).map(|(k, _)| *k);
            // `BodyDTODeserializer` builds these from its value, "" when none was read.
            if let Some(p) = payload.filter(|p| ["regex", "jsonPath", "xpath"].contains(p) && field(o, p).is_none()) {
                out.insert(p.into(), Value::String(String::new()));
            }
            for (k, v) in o {
                if k.eq_ignore_ascii_case("type") || k.eq_ignore_ascii_case("not") || k.eq_ignore_ascii_case("optional") {
                    continue;
                }
                let key = match payload {
                    Some(p) if k.eq_ignore_ascii_case(p) => p.to_string(),
                    _ => k.clone(),
                };
                out.insert(key, v.clone());
            }
            // `JsonPathBodyDTOSerializer` / `XPathBodyDTOSerializer`: the date-time comparison last, as a value is
            // written
            if matches!(other, "JSON_PATH" | "XPATH") {
                let date_time = o.keys().filter(|k| k.eq_ignore_ascii_case("dateTime")).cloned().collect::<Vec<_>>();
                for k in &date_time {
                    out.shift_remove(k);
                }
                if let Some(written) = field(o, "dateTime").and_then(model::NString::from_json).filter(|s| s.date_time.is_some()) {
                    out.insert("dateTime".into(), written.to_json());
                }
            }
        }
    }
    Value::Object(out)
}

/// `JsonInclude.Include.NON_EMPTY` on a bean tree: empty strings and lists are dropped (empty beans stay).
fn non_empty_bean(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(_, x)| !matches!(x, Value::String(s) if s.is_empty()) && !matches!(x, Value::Array(a) if a.is_empty()))
                .map(|(k, x)| (k.clone(), non_empty_bean(x)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(non_empty_bean).collect()),
        other => other.clone(),
    }
}
