//! Ports of upstream's dashboard model tests (`org.mockserver.dashboard`): the log-entry serializers
//! (`DashboardLogEntryDTOSerializerTest`, `DashboardLogEntryDTOGroupSerializerTest`), the description processor
//! (`DescriptionProcessorTest`) and the frame built from them (`DashboardWebSocketHandlerTest`'s frame cases and
//! `DashboardWebSocketFrameContractTest`). The Java tests build `LogEntry` objects the server never produces by
//! itself (arbitrary types, formats and argument lists), so they drive `mock_server::dashboard`'s model directly;
//! the live behaviour is in `dashboard_websocket.rs`. Expected JSON is what the Java assertions spell out, compared
//! as compact text so key order counts.

use mock_server::dashboard::{
    ActiveExpectation, DashArg, DashEntry, Described, Description, DescriptionProcessor, FrameBudget, MAX_BODY_CHARACTERS, MAX_UPDATE_CHARACTERS,
    MESSAGE_OVERHEAD_CHARACTERS, build_frame, build_frame_with, build_frame_within, entry_value, frame_text, group_value,
};
use serde_json::{Value, json};

const EPOCH: i64 = 1_593_582_678_216;

fn full_timestamp() -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_millis_opt(EPOCH).unwrap().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// `StringUtils.substringAfter(timestamp, "-")`
fn short_timestamp() -> String {
    full_timestamp().split_once('-').unwrap().1.to_string()
}

fn style(color: &str, pre_wrap: bool) -> Value {
    if pre_wrap {
        json!({"style.whiteSpace": "pre-wrap", "paddingBottom": "4px", "whiteSpace": "nowrap", "overflow": "auto", "color": color, "paddingTop": "4px"})
    } else {
        json!({"paddingBottom": "4px", "whiteSpace": "nowrap", "overflow": "auto", "color": color, "paddingTop": "4px"})
    }
}

fn text(s: &str) -> DashArg {
    DashArg::Text(s.to_string())
}

/// `new LogEntry().setLogLevel(WARN).setEpochTime(epochTime).setType(kind).setMessageFormat(format).setArguments(…)`
/// as a dashboard entry.
fn entry(id: &str, kind: &str, format: &str, arguments: Vec<DashArg>) -> DashEntry {
    let mut e = DashEntry::new(id, None, Some(&full_timestamp()), Some(kind));
    e.message_format = Some(format.to_string());
    if !arguments.is_empty() {
        e.arguments = Some(arguments);
    }
    e
}

/// `getDescription(logEntry)` of the serializer tests: a `LogMessageDescription` built by hand, which the processor
/// never saw, so it pads against a maximum of zero.
fn described(e: &DashEntry, processor: &std::rc::Rc<DescriptionProcessor>) -> Description {
    let first = short_timestamp();
    let second = e.kind.clone().unwrap();
    let length = first.chars().count() + second.chars().count();
    Description::Log { first, second, length, processor: processor.clone() }
}

fn with_description(mut e: DashEntry) -> DashEntry {
    let processor = DescriptionProcessor::new();
    e.description = Some(described(&e, &processor));
    e
}

fn msg(id: &str, i: usize, value: &str) -> Value {
    json!({"key": format!("{id}_{i}msg"), "value": value})
}

fn quoted(id: &str, i: usize, value: &str) -> Value {
    json!({"key": format!("{id}_{i}arg"), "multiline": false, "argument": true, "value": format!("\"{value}\"")})
}

fn lines(id: &str, i: usize, value: &[&str]) -> Value {
    json!({"key": format!("{id}_{i}arg"), "multiline": true, "argument": true, "value": value})
}

fn because(id: &str, i: usize, value: &[&str]) -> Value {
    json!({"key": format!("{id}_{i}arg"), "because": true, "argument": true, "value": value})
}

fn object(id: &str, i: usize, value: Value) -> Value {
    json!({"key": format!("{id}_{i}arg"), "json": true, "argument": true, "value": value})
}

/// The serializer's `{key, value: {timestamp, description, style, messageParts}}` for a TEMPLATE_GENERATED entry
/// described `TEMPLATE_GENERATED ` (one trailing space).
fn template_generated(id: &str, parts: Vec<Value>) -> Value {
    json!({
        "key": format!("{id}_log"),
        "value": {
            "timestamp": full_timestamp(),
            "description": format!("{} TEMPLATE_GENERATED ", short_timestamp()),
            "style": style("rgb(241, 186, 27)", false),
            "messageParts": parts,
        }
    })
}

fn assert_same(actual: &Value, expected: &Value) {
    assert_eq!(actual.to_string(), expected.to_string());
}

const FORMAT_TWO: &str = "some random{}formatted string{}";

#[test]
fn serialise_event_with_single_line_string_argument() {
    let e = with_description(entry("id1", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("one"), text("two")]));
    let actual = entry_value(&e);
    let expected = template_generated("id1", vec![msg("id1", 0, "some random"), quoted("id1", 0, "one"), msg("id1", 1, "formatted string"), quoted("id1", 1, "two")]);
    assert_same(&actual, &expected);
    // and the printer writes it as the Java test spells it
    let pretty = mock_server::json::pretty(&actual);
    assert!(pretty.starts_with("{\n  \"key\" : \"id1_log\",\n  \"value\" : {\n    \"timestamp\" : "), "{pretty}");
    assert!(pretty.contains("      \"multiline\" : false,\n      \"argument\" : true,\n      \"value\" : \"\\\"one\\\"\"\n"), "{pretty}");
}

#[test]
fn serialise_event_with_multi_line_string_argument_as_first() {
    let e = with_description(entry("id2", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("line one\nline two\nline three"), text("two")]));
    let expected = template_generated(
        "id2",
        vec![msg("id2", 0, "some random"), lines("id2", 0, &["line one", "line two", "line three"]), msg("id2", 1, "formatted string"), quoted("id2", 1, "two")],
    );
    assert_same(&entry_value(&e), &expected);
}

#[test]
fn serialise_event_with_multi_line_string_argument_as_all() {
    let e = with_description(entry(
        "id3",
        "TEMPLATE_GENERATED",
        FORMAT_TWO,
        vec![text("line one_one\nline one_two\nline one_three"), text("line two_one\nline two_two\nline two_three")],
    ));
    let expected = template_generated(
        "id3",
        vec![
            msg("id3", 0, "some random"),
            lines("id3", 0, &["line one_one", "line one_two", "line one_three"]),
            msg("id3", 1, "formatted string"),
            lines("id3", 1, &["line two_one", "line two_two", "line two_three"]),
        ],
    );
    assert_same(&entry_value(&e), &expected);
}

#[test]
fn serialise_event_with_because_argument_as_first() {
    let mut e = entry("id4", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("line one\nline two\nline three"), text("two")]);
    e.because = Some("line one\nline two\nline three".into());
    let expected = template_generated(
        "id4",
        vec![msg("id4", 0, "some random"), because("id4", 0, &["line one", "line two", "line three"]), msg("id4", 1, "formatted string"), quoted("id4", 1, "two")],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_because_argument_as_last() {
    let mut e = entry("id5", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("one"), text("line one\nline two\nline three")]);
    e.because = Some("line one\nline two\nline three".into());
    let expected = template_generated(
        "id5",
        vec![msg("id5", 0, "some random"), quoted("id5", 0, "one"), msg("id5", 1, "formatted string"), because("id5", 1, &["line one", "line two", "line three"])],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_because_argument_not_matching() {
    let mut e = entry("id6", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("one"), text("line one\nline two\nline three")]);
    e.because = Some("other line one\nother line two\nother line three".into());
    let expected = template_generated(
        "id6",
        vec![msg("id6", 0, "some random"), quoted("id6", 0, "one"), msg("id6", 1, "formatted string"), lines("id6", 1, &["line one", "line two", "line three"])],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_object_argument_as_first() {
    let e = entry("id7", "TEMPLATE_GENERATED", FORMAT_TWO, vec![DashArg::Json(json!({"path": "somePath"})), text("two")]);
    let expected = template_generated(
        "id7",
        vec![msg("id7", 0, "some random"), object("id7", 0, json!({"path": "somePath"})), msg("id7", 1, "formatted string"), quoted("id7", 1, "two")],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_object_argument_as_all() {
    let e = entry("id8", "TEMPLATE_GENERATED", FORMAT_TWO, vec![DashArg::Json(json!({"path": "somePath"})), DashArg::Json(json!({"path": "otherPath"}))]);
    let expected = template_generated(
        "id8",
        vec![
            msg("id8", 0, "some random"),
            object("id8", 0, json!({"path": "somePath"})),
            msg("id8", 1, "formatted string"),
            object("id8", 1, json!({"path": "otherPath"})),
        ],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_too_many_arguments() {
    // the third argument has no `{}` to follow and is dropped
    let e = entry("id9", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("one"), text("two"), text("three")]);
    let expected = template_generated("id9", vec![msg("id9", 0, "some random"), quoted("id9", 0, "one"), msg("id9", 1, "formatted string"), quoted("id9", 1, "two")]);
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_too_few_arguments() {
    // a third part of the message with no argument is shown on its own
    let e = entry("id10", "TEMPLATE_GENERATED", "some random{}formatted string{}and more{}", vec![text("one"), text("two")]);
    let expected = template_generated(
        "id10",
        vec![
            msg("id10", 0, "some random"),
            quoted("id10", 0, "one"),
            msg("id10", 1, "formatted string"),
            quoted("id10", 1, "two"),
            msg("id10", 2, "and more"),
        ],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_multi_line_string() {
    let e = entry("id11", "TEMPLATE_GENERATED", "some\n random{}formatted\n string{}", vec![text("one"), text("two")]);
    let expected = template_generated("id11", vec![msg("id11", 0, "some\n random"), quoted("id11", 0, "one"), msg("id11", 1, "formatted\n string"), quoted("id11", 1, "two")]);
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_event_with_throwable() {
    let mut e = entry("id12", "TEMPLATE_GENERATED", "some message", vec![]);
    e.throwable = Some(vec!["java.lang.RuntimeException: TEST EXCEPTION".into(), "\tat some.Class.method(Class.java:1)".into()]);
    let expected = template_generated(
        "id12",
        vec![
            msg("id12", 0, "some message"),
            json!({"key": "id12_throwable_msg", "value": "exception:"}),
            json!({"key": "id12_throwable_value", "multiline": true, "argument": true, "value": ["java.lang.RuntimeException: TEST EXCEPTION", "\tat some.Class.method(Class.java:1)"]}),
        ],
    );
    assert_same(&entry_value(&with_description(e)), &expected);
}

#[test]
fn serialise_timestamp_when_set() {
    let e = with_description(entry("id13", "TEMPLATE_GENERATED", "some message", vec![]));
    assert_eq!(entry_value(&e)["value"]["timestamp"], json!(full_timestamp()));
}

#[test]
fn omit_timestamp_when_null() {
    let mut e = DashEntry::new("someId", Some("someCorrelationId"), None, Some("TEMPLATE_GENERATED"));
    e.message_format = Some("some message".into());
    assert!(entry_value(&e)["value"].get("timestamp").is_none());
}

#[test]
fn serialise_binary_forward() {
    // arguments: a multi-line hex string, a socket address (not a string, so shown as JSON), a list of hex lines
    let response_lines = ["596f7520626974652075702062656361757365206f6620796f7572206c6f7765", "72206a61772e0a4920616d20636f756e74696e67206d792063616c6f72696573"];
    let request_lines = ["54686520747269636b20746f2067657474696e67206b69647320746f20656174", "20616e797468696e6720697320746f207075742063617463687570206f6e2069"];
    let mut e = entry(
        "id14",
        "FORWARDED_REQUEST",
        "returning binary response:{}from:{}for forwarded binary request:{}",
        vec![text(&response_lines.join("\n")), DashArg::Json(json!("0.0.0.0:1234")), DashArg::Json(json!(request_lines))],
    );
    e.description = Some(described(&e, &DescriptionProcessor::new()));
    let expected = json!({
        "key": "id14_log",
        "value": {
            "timestamp": full_timestamp(),
            "description": format!("{} FORWARDED_REQUEST ", short_timestamp()),
            "style": style("rgb(152, 208, 255)", false),
            "messageParts": [
                msg("id14", 0, "returning binary response:"),
                lines("id14", 0, &response_lines),
                msg("id14", 1, "from:"),
                object("id14", 1, json!("0.0.0.0:1234")),
                msg("id14", 2, "for forwarded binary request:"),
                object("id14", 2, json!(request_lines)),
            ],
        }
    });
    assert_same(&entry_value(&e), &expected);
}

// --- DashboardLogEntryDTOGroupSerializerTest -------------------------------------------------------------------------

#[test]
fn serialise_group_with_single_event() {
    let processor = DescriptionProcessor::new();
    let mut e = entry("g1", "TEMPLATE_GENERATED", FORMAT_TWO, vec![text("one"), text("two")]);
    e.description = Some(described(&e, &processor));
    let expected = template_generated("g1", vec![msg("g1", 0, "some random"), quoted("g1", 0, "one"), msg("g1", 1, "formatted string"), quoted("g1", 1, "two")]);
    assert_same(&group_value(&[e], &processor), &expected);
}

#[test]
fn serialise_group_with_multiple_events() {
    let processor = DescriptionProcessor::new();
    let mut forward = entry("g2", "FORWARDED_REQUEST", FORMAT_TWO, vec![text("one"), text("two")]);
    forward.description = Some(described(&forward, &processor));
    let mut not_matched = entry("g3", "EXPECTATION_NOT_MATCHED", FORMAT_TWO, vec![text("one"), text("two")]);
    not_matched.description = Some(described(&not_matched, &processor));
    let actual = group_value(&[forward, not_matched], &processor);
    // the header's description goes through the processor (maximum 36), which the first entry then pads against too
    let ts = short_timestamp();
    let parts = |id: &str| vec![msg(id, 0, "some random"), quoted(id, 0, "one"), msg(id, 1, "formatted string"), quoted(id, 1, "two")];
    let expected = json!({
        "key": "g2_log_group",
        "group": {
            "key": "g2_log",
            "value": {
                "timestamp": full_timestamp(),
                "description": format!("{ts} FORWARDED_REQUEST   "),
                "style": style("rgb(152, 208, 255)", false),
            }
        },
        "value": [
            {"key": "g2_log", "value": {
                "timestamp": full_timestamp(),
                "description": format!("{ts} FORWARDED_REQUEST   "),
                "style": style("rgb(152, 208, 255)", false),
                "messageParts": parts("g2"),
            }},
            {"key": "g3_log", "value": {
                "timestamp": full_timestamp(),
                "description": format!("{ts} EXPECTATION_NOT_MATCHED "),
                "style": style("rgb(204,165,163)", false),
                "messageParts": parts("g3"),
            }},
        ],
    });
    assert_same(&actual, &expected);
}

// --- DescriptionProcessorTest -----------------------------------------------------------------------------------------

fn log_description(processor: &std::rc::Rc<DescriptionProcessor>, kind: &str) -> Value {
    let mut e = DashEntry::new("id", None, Some(&full_timestamp()), Some(kind));
    e.message_format = None;
    processor.description(Described::Log(&e)).unwrap().to_value()
}

#[test]
fn multiple_log_message_descriptions() {
    // The descriptions are rendered once all exist, so each is padded to the longest.
    let processor = DescriptionProcessor::new();
    let created: Vec<Description> = ["EXPECTATION_RESPONSE", "DEBUG", "TEMPLATE_GENERATED"]
        .iter()
        .map(|kind| {
            let e = DashEntry::new("id", None, Some(&full_timestamp()), Some(kind));
            processor.description(Described::Log(&e)).unwrap()
        })
        .collect();
    let ts = short_timestamp();
    let rendered: Vec<Value> = created.iter().map(Description::to_value).collect();
    assert_eq!(
        rendered,
        vec![
            json!(format!("{ts} EXPECTATION_RESPONSE   ")),
            json!(format!("{ts} DEBUG                  ")),
            json!(format!("{ts} TEMPLATE_GENERATED     ")),
        ]
    );
    // a lone description is only as wide as itself (padding of two, then the closing space)
    assert_eq!(log_description(&DescriptionProcessor::new(), "DEBUG"), json!(format!("{ts} DEBUG   ")));
}

const INLINE_SPEC: &str = "---\nopenapi: 3.0.0\npaths:\n  \"/somePath\":\n    get:\n      operationId: someOperation\n";

fn open_api(spec: &str, operation: Option<&str>) -> Value {
    match operation {
        Some(operation) => json!({"specUrlOrPayload": spec, "operationId": operation}),
        None => json!({"specUrlOrPayload": spec}),
    }
}

fn inline_object() -> Value {
    json!({"openapi": "3.0.0", "paths": {"/somePath": {"get": {"operationId": "someOperation"}}}, "servers": [{"url": "/"}]})
}

#[test]
fn multiple_open_api_definitions() {
    let processor = DescriptionProcessor::new();
    let definitions = [
        open_api(INLINE_SPEC, Some("showPetById")),
        open_api(INLINE_SPEC, None),
        open_api("org/mockserver/openapi/openapi_petstore_example.json", None),
        open_api("org/mockserver/openapi/openapi_petstore_example.json", Some("someOtherOperationId")),
        open_api("https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v3.0/petstore-expanded.yaml", Some("someOtherOtherOperationId")),
        open_api("https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v3.0/petstore-expanded.yaml", None),
    ];
    let created: Vec<Description> = definitions.iter().map(|d| processor.description(Described::Definition(d)).unwrap()).collect();
    let rendered: Vec<Value> = created.iter().map(Description::to_value).collect();
    assert_eq!(
        rendered,
        vec![
            json!({"json": true, "object": inline_object(), "first": "spec ", "second": " showPetById"}),
            json!({"json": true, "object": inline_object(), "first": "spec ", "second": "            "}),
            json!("openapi_petstore_example.json                      "),
            json!("openapi_petstore_example.json  someOtherOperationId"),
            json!("petstore-expanded.yaml    someOtherOtherOperationId"),
            json!("petstore-expanded.yaml                             "),
        ]
    );
    assert_eq!(rendered[0].to_string(), json!({"json": true, "object": inline_object(), "first": "spec ", "second": " showPetById"}).to_string());
}

fn requests() -> Vec<Value> {
    vec![json!({"path": "somePathOne", "method": "POST"}), json!({"path": "veryLongPathThatHasASillyLength"}), json!({"method": "POST"}), json!({"path": "somePathOne"}), json!({})]
}

const REQUEST_DESCRIPTIONS: [&str; 5] = [
    "POST                  somePathOne",
    "  veryLongPathThatHasASillyLength",
    "POST                             ",
    "                      somePathOne",
    "                                 ",
];

#[test]
fn multiple_http_request_definitions() {
    let processor = DescriptionProcessor::new();
    let created: Vec<Description> = requests().iter().map(|r| processor.description(Described::Definition(r)).unwrap()).collect();
    let rendered: Vec<Value> = created.iter().map(Description::to_value).collect();
    assert_eq!(rendered, REQUEST_DESCRIPTIONS.iter().map(|s| json!(s)).collect::<Vec<_>>());
}

#[test]
fn multiple_http_request_and_open_api_definitions() {
    let processor = DescriptionProcessor::new();
    let mut definitions = requests();
    definitions.push(open_api(INLINE_SPEC, None));
    definitions.push(open_api("org/mockserver/openapi/openapi_petstore_example.json", None));
    definitions.push(open_api("org/mockserver/openapi/openapi_petstore_example.json", Some("someOtherOperationId")));
    let created: Vec<Description> = definitions.iter().map(|d| processor.description(Described::Definition(d)).unwrap()).collect();
    let rendered: Vec<Value> = created.iter().map(Description::to_value).collect();
    let mut expected: Vec<Value> = REQUEST_DESCRIPTIONS.iter().map(|s| json!(s)).collect();
    expected.push(json!({"json": true, "object": inline_object(), "first": "spec ", "second": " "}));
    expected.push(json!("openapi_petstore_example.json                      "));
    expected.push(json!("openapi_petstore_example.json  someOtherOperationId"));
    assert_eq!(rendered, expected);
    assert_eq!(processor.max_http_request_length(), 32);
}

#[test]
fn a_definition_that_is_not_a_request_has_no_description() {
    let processor = DescriptionProcessor::new();
    assert!(processor.description(Described::Definition(&json!({"dnsName": "example.com"}))).is_none());
}

// --- DashboardWebSocketHandlerTest: the frame --------------------------------------------------------------------------

fn received(id: &str, correlation: Option<&str>, path: &str, format: &str) -> DashEntry {
    let mut e = DashEntry::new(id, correlation, Some(&full_timestamp()), Some("RECEIVED_REQUEST"));
    e.requests = vec![json!({"path": path})];
    e.message_format = Some(format.into());
    e
}

fn plain(id: &str, correlation: Option<&str>, path: &str, format: &str, kind: &str) -> DashEntry {
    let mut e = DashEntry::new(id, correlation, Some(&full_timestamp()), Some(kind));
    e.requests = vec![json!({"path": path})];
    e.message_format = Some(format.into());
    e
}

fn keys(frame: &Value, panel: &str) -> Vec<String> {
    frame[panel].as_array().map(|a| a.iter().map(|i| i["key"].as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

#[test]
fn frame_lists_events_newest_first_and_leaves_out_empty_panels() {
    // entries come newest first; deleted ones are not passed in (the event log's predicate drops them)
    let entries = vec![received("e3", None, "/somePathTwo", "messageFormatThree"), received("e2", None, "/somePathOne", "messageFormatTwo"), received("e1", None, "/somePathOne", "messageFormatOne")];
    let frame = build_frame(entries, vec![]);
    assert_eq!(keys(&frame, "logMessages"), ["e3_log", "e2_log", "e1_log"]);
    assert_eq!(keys(&frame, "recordedRequests"), ["e3_request", "e2_request", "e1_request"]);
    assert!(frame.get("activeExpectations").is_none() && frame.get("proxiedRequests").is_none());
    let first = &frame["logMessages"][0];
    assert_eq!(first["value"]["description"], json!(format!("{} RECEIVED_REQUEST   ", short_timestamp())));
    assert_eq!(first["value"]["style"], style("rgb(114,160,193)", false));
    assert_eq!(first["value"]["messageParts"], json!([{"key": "e3_0msg", "value": "messageFormatThree"}]));
}

#[test]
fn frame_ignores_deleted_log_events() {
    let mut deleted_received = received("d2", None, "/somePathOne", "messageFormatOne");
    deleted_received.deleted = true;
    let mut deleted_plain = plain("d0", None, "/somePathOne", "messageFormat", "INFO");
    deleted_plain.deleted = true;
    let entries = vec![received("d3", None, "/somePathTwo", "messageFormatThree"), deleted_received, plain("d1", None, "/somePathOne", "messageFormat", "INFO"), deleted_plain];
    let frame = build_frame(entries, vec![]);
    assert_eq!(keys(&frame, "logMessages"), ["d3_log", "d1_log"]);
    assert_eq!(keys(&frame, "recordedRequests"), ["d3_request"]);
}

#[test]
fn frame_with_no_content_is_an_empty_object() {
    // empty panels are left out; the expectation count and the LLM flag are always written
    assert_eq!(frame_text(&build_frame(vec![], vec![]), false), r#"{"activeExpectationsTotal":0,"activeExpectationsIncludeLlm":false}"#);
}

#[test]
fn frame_rolls_up_events_with_the_same_correlation_id_and_not_unique_ones() {
    let entries = vec![
        plain("c4", Some("unique"), "/four", "four", "INFO"),
        plain("c3", Some("shared"), "/three", "three", "INFO"),
        plain("c2", Some("shared"), "/two", "two", "INFO"),
        plain("c1", None, "/one", "one", "INFO"),
    ];
    let frame = build_frame(entries, vec![]);
    // a correlation id seen once is just the entry; two roll up under the first (newest) one's header
    assert_eq!(keys(&frame, "logMessages"), ["c4_log", "c3_log_group", "c1_log"]);
    let group = &frame["logMessages"][1];
    assert_eq!(group["group"]["key"], json!("c3_log"));
    assert_eq!(group["value"].as_array().unwrap().iter().map(|e| e["key"].as_str().unwrap()).collect::<Vec<_>>(), ["c3_log", "c2_log"]);
}

#[test]
fn trace_events_are_never_rolled_up() {
    let entries = vec![plain("t2", Some("shared"), "/b", "b", "TRACE"), plain("t1", Some("shared"), "/a", "a", "TRACE")];
    assert_eq!(keys(&build_frame(entries, vec![]), "logMessages"), ["t2_log", "t1_log"]);
}

#[test]
fn recorded_request_is_paired_with_the_response_of_its_correlation_id() {
    let mut response = DashEntry::new("r2", Some("corr"), Some(&full_timestamp()), Some("EXPECTATION_RESPONSE"));
    response.response = Some(json!({"statusCode": 200, "body": "hello"}));
    response.requests = vec![json!({"path": "/some/path"})];
    let request = received("r1", Some("corr"), "/some/path", "received request");
    let unpaired = received("r0", Some("other"), "/other", "received request");
    let frame = build_frame(vec![response, request, unpaired], vec![]);
    let recorded = frame["recordedRequests"].as_array().unwrap();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0]["key"], json!("r1_request"));
    assert_eq!(recorded[0]["value"], json!({"httpRequest": {"path": "/some/path"}, "httpResponse": {"statusCode": 200, "body": "hello"}}));
    // no response with that correlation id: the request stands alone
    assert_eq!(recorded[1]["value"], json!({"httpRequest": {"path": "/other"}}));
    // key order of a recorded request: description, value, key, timestamp, correlationId
    assert_eq!(recorded[0].as_object().unwrap().keys().collect::<Vec<_>>(), ["description", "value", "key", "timestamp", "correlationId"]);
    assert_eq!(recorded[0]["correlationId"], json!("corr"));
}

// `DashboardNonHttpRequestRowTest` (upstream #102): a DNS query and a binary message are Received Requests
// rows described by kind and summary. Its cut, marker and size-ceiling cases are with the body cap's, below.

fn received_definition(id: &str, definition: Value) -> DashEntry {
    let mut e = DashEntry::new(id, None, Some(&full_timestamp()), Some("RECEIVED_REQUEST"));
    e.requests = vec![definition];
    e
}

#[test]
fn should_list_a_dns_query_by_its_name_and_type() {
    let frame = build_frame(vec![received_definition("n1", json!({"dnsName": "api.example.com", "dnsType": "A", "dnsClass": "IN"}))], vec![]);
    let rows = frame["recordedRequests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["value"], json!({"httpRequest": {"dnsName": "api.example.com", "dnsType": "A", "dnsClass": "IN"}}));
    assert_eq!(rows[0]["description"], json!({"json": false, "first": "DNS", "second": "api.example.com A"}));
}

#[test]
fn should_list_a_binary_message_by_its_length_and_first_bytes() {
    use base64::Engine;
    let message: Vec<u8> = (0..20).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&message);
    let frame = build_frame(vec![received_definition("b1", json!({"binaryData": encoded}))], vec![]);
    let rows = frame["recordedRequests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["value"]["httpRequest"]["binaryData"], json!(encoded));
    assert!(rows[0].get("truncatedBodies").is_none());
    assert_eq!(rows[0]["description"], json!({"json": false, "first": "BINARY", "second": "20 bytes 000102030405060708090a0b0c0d0e0f..."}));
}

#[test]
fn should_leave_out_a_binary_messages_bytes_when_redaction_is_on() {
    // the message itself arrives masked from the event log's redacted view
    let frame = build_frame_with(vec![received_definition("b1", json!({"binaryData": "KioqUkVEQUNURUQqKio="}))], vec![], true);
    assert_eq!(frame["recordedRequests"][0]["description"], json!({"json": false, "first": "BINARY", "second": "bytes redacted"}));
}

#[test]
fn a_binary_expectation_has_no_request_description() {
    // `DescriptionProcessor.description` describes only an `HttpRequest` or an `OpenAPIDefinition`
    let frame = build_frame(vec![], vec![ActiveExpectation {
        id: "bin-1".into(),
        http_request: json!({"binaryData": "AQI="}),
        value: json!({"httpRequest": {"binaryData": "AQI="}}),
    }]);
    assert_eq!(frame["activeExpectations"][0]["description"], json!("bin-1"));
}

#[test]
fn forwarded_requests_carry_request_and_response() {
    let mut forwarded = DashEntry::new("f1", None, Some(&full_timestamp()), Some("FORWARDED_REQUEST"));
    forwarded.requests = vec![json!({"path": "/proxied/path"})];
    forwarded.response = Some(json!({"statusCode": 200, "body": "proxied"}));
    forwarded.message_format = Some("forwarded request".into());
    // a forwarded entry with neither request nor response adds nothing to the panel
    let empty = DashEntry::new("f0", None, Some(&full_timestamp()), Some("FORWARDED_REQUEST"));
    let frame = build_frame(vec![forwarded, empty], vec![]);
    assert_eq!(keys(&frame, "proxiedRequests"), ["f1_proxied"]);
    let proxied = &frame["proxiedRequests"][0];
    assert_eq!(proxied["value"], json!({"httpRequest": {"path": "/proxied/path"}, "httpResponse": {"statusCode": 200, "body": "proxied"}}));
    assert_eq!(proxied["description"], json!("  /proxied/path"));
}

#[test]
fn forwarded_request_without_a_request_still_shows_the_response() {
    let mut forwarded = DashEntry::new("f2", None, Some(&full_timestamp()), Some("FORWARDED_REQUEST"));
    forwarded.response = Some(json!({"statusCode": 200}));
    let frame = build_frame(vec![forwarded], vec![]);
    let proxied = &frame["proxiedRequests"][0];
    assert!(proxied.get("description").is_none());
    assert_eq!(proxied["value"], json!({"httpResponse": {"statusCode": 200}}));
}

fn expectation(id: &str, path: &str, body: &str) -> ActiveExpectation {
    ActiveExpectation {
        id: id.into(),
        http_request: json!({"path": path}),
        value: json!({"httpRequest": {"path": path}, "httpResponse": {"statusCode": 200, "reasonPhrase": "OK", "body": body}, "id": id, "priority": 0, "timeToLive": {"unlimited": true}, "times": {"unlimited": true}}),
    }
}

#[test]
fn expectations_are_described_by_id_method_and_path() {
    let frame = build_frame(vec![], vec![expectation("x1", "one", "one"), expectation("x2", "three", "three")]);
    let active = frame["activeExpectations"].as_array().unwrap();
    assert_eq!(active[0].as_object().unwrap().keys().collect::<Vec<_>>(), ["key", "description", "value"]);
    // the id leads the first part; the longest path sets the padding of the rest
    assert_eq!(active[0]["description"], json!("x1:     one"));
    assert_eq!(active[1]["description"], json!("x2:   three"));
    assert_eq!(active[0]["value"]["httpResponse"]["reasonPhrase"], json!("OK"));
}

#[test]
fn expectation_total_and_llm_flag_cover_every_expectation_not_the_capped_page() {
    let mut expectations: Vec<ActiveExpectation> = (0..150).map(|i| expectation(&format!("x{i}"), "/p", "b")).collect();
    let mut llm = expectation("llm", "/v1/chat/completions", "");
    llm.value["httpLlmResponse"] = json!({"provider": "OPENAI"});
    expectations.push(llm);
    let frame = build_frame(vec![], expectations);
    assert_eq!(frame["activeExpectations"].as_array().unwrap().len(), 100);
    assert_eq!(frame["activeExpectationsTotal"], json!(151));
    assert_eq!(frame["activeExpectationsIncludeLlm"], json!(true));
}

#[test]
fn an_expectation_that_is_not_a_request_is_described_by_its_id() {
    let dns = ActiveExpectation { id: "d1".into(), http_request: json!({"dnsName": "example.com"}), value: json!({"id": "d1"}) };
    assert_eq!(build_frame(vec![], vec![dns])["activeExpectations"][0]["description"], json!("d1"));
}

#[test]
fn every_panel_is_limited_to_one_hundred_items() {
    let entries: Vec<DashEntry> = (0..150).map(|i| received(&format!("e{i}"), None, "/p", "received")).collect();
    let expectations: Vec<ActiveExpectation> = (0..150).map(|i| expectation(&format!("x{i}"), "/p", "b")).collect();
    let frame = build_frame(entries, expectations);
    assert_eq!(frame["logMessages"].as_array().unwrap().len(), 100);
    assert_eq!(frame["recordedRequests"].as_array().unwrap().len(), 100);
    assert_eq!(frame["activeExpectations"].as_array().unwrap().len(), 100);
}

// --- DashboardWebSocketFrameContractTest -------------------------------------------------------------------------------

/// The four panels populated, as `captureRealFrame` does: a received request, a forwarded one, two events that share a
/// correlation id, and an expectation.
fn contract_frame() -> Value {
    let mut received = DashEntry::new("11111111-aaaa-bbbb-cccc-000000000001", None, Some(&full_timestamp()), Some("RECEIVED_REQUEST"));
    received.requests = vec![json!({"path": "/some/path"})];
    received.message_format = Some("received request".into());
    let mut forwarded = DashEntry::new("11111111-aaaa-bbbb-cccc-000000000002", None, Some(&full_timestamp()), Some("FORWARDED_REQUEST"));
    forwarded.requests = vec![json!({"path": "/proxied/path"})];
    forwarded.response = Some(json!({"body": "proxied"}));
    forwarded.message_format = Some("forwarded request".into());
    let one = plain("11111111-aaaa-bbbb-cccc-000000000003", Some("shared"), "/general/one", "general one", "INFO");
    let two = plain("11111111-aaaa-bbbb-cccc-000000000004", Some("shared"), "/general/two", "general two", "INFO");
    build_frame(vec![two, one, forwarded, received], vec![expectation("11111111-aaaa-bbbb-cccc-000000000005", "/some/path", "hello")])
}

/// `jsonType`
fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
    }
}

/// The value-blind, order-independent fingerprint of the Java test.
fn fingerprint(v: &Value) -> String {
    match v {
        Value::Object(o) => {
            let mut parts: Vec<String> = o.iter().map(|(k, v)| format!("{k}:{}", fingerprint(v))).collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => {
            let mut parts: Vec<String> = a.iter().map(fingerprint).collect();
            parts.sort();
            format!("[{}]", parts.join(","))
        }
        other => json_type(other).to_string(),
    }
}

#[test]
fn frame_satisfies_the_field_contract_across_repeated_captures() {
    // the required fields the dashboard UI's store and panels read (`dashboardFrameContract.json`)
    let log_entry: &[(&str, &str)] = &[("key", "string"), ("value", "object")];
    let log_value: &[(&str, &str)] = &[("timestamp", "string"), ("description", "string"), ("style", "object"), ("messageParts", "array")];
    for _ in 0..5 {
        let frame = contract_frame();
        for panel in ["logMessages", "activeExpectations", "recordedRequests", "proxiedRequests"] {
            let items = frame[panel].as_array().unwrap_or_else(|| panic!("panel {panel} present and an array"));
            assert!(!items.is_empty(), "{panel} populated");
        }
        for item in frame["logMessages"].as_array().unwrap() {
            if item.get("group").is_some() {
                assert_eq!(json_type(&item["group"]), "object");
                assert_eq!(json_type(&item["value"]), "array");
                continue;
            }
            for (field, kind) in log_entry {
                assert_eq!(json_type(&item[*field]), *kind, "{field} in {item}");
            }
            for (field, kind) in log_value {
                assert_eq!(json_type(&item["value"][*field]), *kind, "{field} in {item}");
            }
        }
        for item in frame["activeExpectations"].as_array().unwrap() {
            assert_eq!(json_type(&item["key"]), "string");
            assert_eq!(json_type(&item["description"]), "string");
            assert_eq!(json_type(&item["value"]), "object");
        }
        // a recorded request's key is its originating RECEIVED_REQUEST log entry's id plus `_request`
        let log_keys = keys(&frame, "logMessages");
        for item in frame["recordedRequests"].as_array().unwrap() {
            assert_eq!(json_type(&item["value"]["httpRequest"]), "object");
            let id = item["key"].as_str().unwrap().strip_suffix("_request").expect("a `_request` key");
            assert!(log_keys.contains(&format!("{id}_log")), "{id} correlates with a log entry");
        }
        for item in frame["proxiedRequests"].as_array().unwrap() {
            let id = item["key"].as_str().unwrap().strip_suffix("_proxied").expect("a `_proxied` key");
            assert!(log_keys.contains(&format!("{id}_log")), "{id} correlates with a log entry");
        }
    }
}

#[test]
fn frame_structure_is_deterministic_across_captures() {
    assert_eq!(fingerprint(&contract_frame()), fingerprint(&contract_frame()));
}

// --- DashboardFrameBodyCapTest, DashboardNonHttpRequestRowTest's cut cases, DashboardActiveExpectationBodyCapTest ------
//
// `DashboardBodyCap`. Upstream tells an entry's own request or response by identity; here a
// `DashEntry` says so in `own_parts`, as the event log's dashboard JSON does (`$ownParts`). Not ported: the
// redaction case (`shouldCutAfterRedactingSoACutNeverShowsARedactedValue`: the frame is built from the event log's
// redacted view, so a cut never sees a redacted value), the short-circuit equality (the walk here always stops once
// no section can take more), and `DashboardCutBodyMemoTest`/`DashboardRedactedCutBodyMemoTest` (how often a cache
// decodes a body, which nothing here caches).

const CAP: usize = MAX_BODY_CHARACTERS;

/// `body(word, length)`: `word` repeated, cut to `length` characters.
fn body(word: &str, length: usize) -> String {
    word.repeat(length / word.len() + 1)[..length].to_string()
}

fn logged(id: &str, kind: &str, correlation: &str, format: &str) -> DashEntry {
    let mut e = DashEntry::new(id, Some(correlation), Some(&full_timestamp()), Some(kind));
    e.message_format = Some(format.into());
    e
}

fn own(parts: &[Option<&str>]) -> Option<Vec<Option<String>>> {
    Some(parts.iter().map(|p| p.map(str::to_string)).collect())
}

/// Newest first, as the dashboard walks the log: for each exchange its response entry, the match, then the request.
fn exchanges(count: usize, body_length: usize) -> Vec<DashEntry> {
    let mut reverse = Vec::new();
    for i in (0..count).rev() {
        let correlation = format!("exchange-{i}");
        let request = json!({"path": format!("/exchange-{i}"), "body": body(&format!("request-{i}-"), body_length)});
        let response = json!({"statusCode": 200, "body": body(&format!("response-{i}-"), body_length)});
        let expectation = json!({"httpRequest": {"path": format!("/exchange-{i}")}, "httpResponse": response.clone()});
        let mut answered = logged(&format!("{i}-response"), "EXPECTATION_RESPONSE", &correlation, "returning response:{}for request:{}");
        answered.requests = vec![request.clone()];
        answered.response = Some(response.clone());
        answered.arguments = Some(vec![DashArg::Json(response.clone()), DashArg::Json(request.clone())]);
        answered.own_parts = own(&[Some("response"), Some("request")]);
        let mut matched = logged(&format!("{i}-matched"), "EXPECTATION_MATCHED", &correlation, "request:{}matched expectation:{}");
        matched.requests = vec![request.clone()];
        matched.arguments = Some(vec![DashArg::Json(request.clone()), DashArg::Json(expectation)]);
        matched.own_parts = own(&[Some("request"), None]);
        let mut received = logged(&format!("{i}-received"), "RECEIVED_REQUEST", &correlation, "received request:{}");
        received.requests = vec![request.clone()];
        received.arguments = Some(vec![DashArg::Json(request)]);
        received.own_parts = own(&[Some("request")]);
        reverse.extend([answered, matched, received]);
    }
    reverse
}

/// `render`: the frame `populateLogSections` builds under `max_characters`, its text and the two flags.
fn render(reverse: Vec<DashEntry>, max_characters: u64) -> (Value, String, bool, bool) {
    let mut budget = FrameBudget::new(max_characters);
    let frame = build_frame_within(reverse, vec![], false, &mut budget);
    let text = frame_text(&frame, false);
    (frame, text, budget.rows_limit_reached(), budget.log_messages_limit_reached())
}

/// `findValues`: every value of `field`, anywhere in `value`.
fn find_values<'a>(value: &'a Value, field: &str, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(o) => {
            for (k, v) in o {
                if k == field {
                    out.push(v);
                }
                find_values(v, field, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| find_values(v, field, out)),
        _ => {}
    }
}

#[test]
fn should_cut_large_bodies_in_rows_and_say_where_to_load_them_whole() {
    let (frame, text, limit_reached, _) = render(exchanges(3, 200_000), MAX_UPDATE_CHARACTERS);
    let newest = &frame["recordedRequests"][0];
    assert_eq!(newest["value"]["httpRequest"]["path"], json!("/exchange-2"));
    assert_eq!(newest["value"]["httpRequest"]["body"], json!(body("request-2-", CAP)));
    assert_eq!(newest["value"]["httpResponse"]["body"].as_str().unwrap().len(), CAP);
    let request_marker = &newest["truncatedBodies"]["httpRequest"];
    assert_eq!(request_marker["logEntryId"], json!("2-received"));
    assert_eq!(request_marker["part"], json!("request"));
    assert_eq!(request_marker["originalLength"], json!(200_000));
    assert_eq!(request_marker["shownLength"], json!(CAP));
    // the response loads from the entry that holds it
    let response_marker = &newest["truncatedBodies"]["httpResponse"];
    assert_eq!(response_marker["logEntryId"], json!("2-response"));
    assert_eq!(response_marker["part"], json!("response"));
    // nothing in the update holds a body whole
    assert!(!text.contains(&body("request-2-", CAP + 1)));
    assert!(!text.contains(&body("response-2-", CAP + 1)));
    assert!(!limit_reached);
}

#[test]
fn should_mark_cut_bodies_in_log_message_arguments() {
    let (frame, text, _, _) = render(exchanges(1, 200_000), MAX_UPDATE_CHARACTERS);
    let mut markers = Vec::new();
    find_values(&frame["logMessages"], "truncatedBody", &mut markers);
    // response and request of the response entry, request and expectation of the match, request of the received entry
    assert_eq!(markers.len(), 5);
    assert_eq!(markers.iter().filter(|m| m["part"] == json!("expectation")).count(), 1);
    for marker in &markers {
        let expectation = marker["part"] == json!("expectation");
        // only the entry's own request or response loads
        assert_eq!(marker["loadable"], json!(!expectation), "{marker}");
    }
    assert!(!text.contains(&body("response-0-", CAP + 1)));
}

#[test]
fn should_leave_bodies_under_the_cap_whole() {
    let (frame, _, _, _) = render(exchanges(2, CAP), MAX_UPDATE_CHARACTERS);
    let newest = &frame["recordedRequests"][0];
    assert_eq!(newest["value"]["httpRequest"]["body"], json!(body("request-1-", CAP)));
    assert!(newest.get("truncatedBodies").is_none());
    let mut markers = Vec::new();
    find_values(&frame["logMessages"], "truncatedBody", &mut markers);
    assert!(markers.is_empty());
}

#[test]
fn should_drop_the_oldest_rows_at_the_ceiling_and_say_it_did() {
    let (frame, text, limit_reached, _) = render(exchanges(40, 200_000), 4 * 1024 * 1024);
    assert!(limit_reached);
    let recorded = frame["recordedRequests"].as_array().unwrap();
    assert!(!recorded.is_empty() && recorded.len() < 40, "{}", recorded.len());
    // the newest rows are the ones kept
    assert_eq!(recorded[0]["value"]["httpRequest"]["path"], json!("/exchange-39"));
    // the update stays near its ceiling
    assert!(text.len() < 5 * 1024 * 1024, "{}", text.len());
    assert_eq!(frame["frameLimitReached"], json!(true));
}

/// Newest first: each request matched none of the expectations, so it logs one "didn't match" message per expectation
/// between its request and its 404.
fn unmatched_exchanges(count: usize, expectations: usize) -> Vec<DashEntry> {
    let mut reverse = Vec::new();
    for i in (0..count).rev() {
        let correlation = format!("unmatched-{i}");
        let request = json!({"path": format!("/seed/{i}")});
        let mut no_match = logged(&format!("{i}-404"), "NO_MATCH_RESPONSE", &correlation, "no expectation for:{}returning response:{}");
        no_match.requests = vec![request.clone()];
        no_match.response = Some(json!({"statusCode": 404, "reasonPhrase": "Not Found"}));
        no_match.arguments = Some(vec![DashArg::Json(request.clone()), DashArg::Json(json!({"statusCode": 404}))]);
        no_match.own_parts = own(&[Some("request"), None]);
        reverse.push(no_match);
        for e in (0..expectations).rev() {
            let mut not_matched = logged(&format!("{i}-{e}-not"), "EXPECTATION_NOT_MATCHED", &correlation, "request:{}didn't match expectation:{}because:{}");
            not_matched.requests = vec![request.clone()];
            let because = format!("path /seed/{i} didn't match /cnt/{e}");
            not_matched.arguments = Some(vec![
                DashArg::Json(request.clone()),
                DashArg::Json(json!({"httpRequest": {"path": format!("/cnt/{e}")}, "httpResponse": {"statusCode": 200}})),
                DashArg::Text(because.clone()),
            ]);
            not_matched.because = Some(because);
            not_matched.own_parts = own(&[Some("request"), None, None]);
            reverse.push(not_matched);
        }
        let mut received = logged(&format!("{i}-received"), "RECEIVED_REQUEST", &correlation, "received request:{}");
        received.requests = vec![request.clone()];
        received.arguments = Some(vec![DashArg::Json(request)]);
        received.own_parts = own(&[Some("request")]);
        reverse.push(received);
    }
    reverse
}

#[test]
fn should_keep_the_newest_request_rows_when_many_did_not_match_messages_fill_the_log_share() {
    let (frame, text, limit_reached, log_messages_limit_reached) = render(unmatched_exchanges(120, 150), MAX_UPDATE_CHARACTERS);
    let recorded = frame["recordedRequests"].as_array().unwrap();
    // every row of the window is sent
    assert_eq!(recorded.len(), 100);
    assert_eq!(recorded[0]["value"]["httpRequest"]["path"], json!("/seed/119"));
    assert_eq!(recorded[99]["value"]["httpRequest"]["path"], json!("/seed/20"));
    // each row still carries its 404
    assert_eq!(recorded[99]["value"]["httpResponse"]["statusCode"], json!(404));
    assert!(!limit_reached, "no request row was left out");
    assert!(log_messages_limit_reached, "older log messages were left out, and the update says so");
    let groups = frame["logMessages"].as_array().unwrap().len();
    assert!(groups > 0 && groups < 100, "{groups}");
    assert!((text.len() as u64) < MAX_UPDATE_CHARACTERS);
    assert_eq!(frame["logMessagesLimitReached"], json!(true));
    assert!(frame.get("frameLimitReached").is_none());
}

#[test]
fn should_let_log_messages_use_only_their_share_of_the_update() {
    let mut budget = FrameBudget::with_log_share(100, 75);
    assert!(budget.admit_log_message(70));
    assert!(!budget.admit_log_message(10), "past the log share");
    assert!(budget.log_messages_limit_reached());
    assert!(!budget.admit_log_message(1), "every older log message is left out too");
    assert!(budget.admit_row(30), "rows still have the rest of the update");
    assert!(!budget.rows_limit_reached());
    assert!(!budget.admit_row(1), "past the whole update");
    assert!(budget.rows_limit_reached());
    assert!(!budget.admit_row(0), "every older row is left out too");
}

#[test]
fn should_stop_log_messages_at_the_whole_update_even_under_their_share() {
    let mut budget = FrameBudget::with_log_share(100, 75);
    assert!(budget.admit_row(60));
    assert!(budget.admit_log_message(30));
    assert!(!budget.admit_log_message(20), "under the log share but past the whole update");
    assert!(budget.log_messages_limit_reached());
    assert!(!budget.rows_limit_reached());
}

#[test]
fn should_always_admit_the_first_of_each_kind() {
    let mut budget = FrameBudget::with_log_share(100, 75);
    assert!(budget.admit_log_message(200), "one message larger than the share is still shown");
    assert!(budget.admit_row(200), "one row is still shown after it");
    assert!(!budget.admit_row(1));
    assert!(!budget.admit_log_message(1));
}

#[test]
fn should_send_cut_bodies_and_the_ceiling_flag_in_the_update_itself() {
    // the live case's log, newest first: per exchange its response entry, then its received entry
    let mut reverse = Vec::new();
    for i in (0..60).rev() {
        let correlation = format!("live-{i}");
        let request = json!({"path": format!("/live-{i}"), "body": body(&format!("request-{i}-"), 100_000)});
        let response = json!({"body": body(&format!("response-{i}-"), 100_000)});
        let mut answered = logged(&format!("{i}-response"), "EXPECTATION_RESPONSE", &correlation, "returning response:{}for request:{}");
        answered.requests = vec![request.clone()];
        answered.response = Some(response.clone());
        answered.arguments = Some(vec![DashArg::Json(response), DashArg::Json(request.clone())]);
        answered.own_parts = own(&[Some("response"), Some("request")]);
        let mut received = logged(&format!("{i}-received"), "RECEIVED_REQUEST", &correlation, "received request:{}");
        received.requests = vec![request.clone()];
        received.arguments = Some(vec![DashArg::Json(request)]);
        received.own_parts = own(&[Some("request")]);
        reverse.extend([answered, received]);
    }
    let frame = build_frame(reverse, vec![]);
    let text = frame_text(&frame, false);
    assert_eq!(frame["frameLimitReached"], json!(true));
    assert!(frame["recordedRequests"].as_array().unwrap().len() < 60);
    assert_eq!(frame["recordedRequests"][0]["truncatedBodies"]["httpRequest"]["originalLength"], json!(100_000));
    assert!((text.len() as u64) < MAX_UPDATE_CHARACTERS + 2 * 1024 * 1024);
    assert!(!text.contains(&body("request-59-", CAP + 1)));
}

#[test]
fn should_say_in_the_update_itself_when_only_log_messages_were_left_out() {
    let frame = build_frame(unmatched_exchanges(40, 150), vec![]);
    assert_eq!(frame["logMessagesLimitReached"], json!(true));
    assert!(frame.get("frameLimitReached").is_none(), "no request row was left out");
    assert_eq!(frame["recordedRequests"].as_array().unwrap().len(), 40);
    assert!(frame["logMessages"].as_array().unwrap().len() < 40);
}

#[test]
fn should_count_small_json_bodies_by_their_size_not_the_cap() {
    for proxied in [false, true] {
        let mut reverse = Vec::new();
        for i in (0..100).rev() {
            let correlation = format!("json-{i}");
            let request = json!({"method": "POST", "path": format!("/json-{i}"), "body": {"a": i}});
            let response = json!({"body": {"b": i}});
            let kind = if proxied { "FORWARDED_REQUEST" } else { "EXPECTATION_RESPONSE" };
            let mut answered = logged(&format!("{i}-response"), kind, &correlation, "returning response:{}for request:{}");
            answered.requests = vec![request.clone()];
            answered.response = Some(response.clone());
            answered.arguments = Some(vec![DashArg::Json(response), DashArg::Json(request.clone())]);
            answered.own_parts = own(&[Some("response"), Some("request")]);
            let mut received = logged(&format!("{i}-received"), "RECEIVED_REQUEST", &correlation, "received request:{}");
            received.requests = vec![request.clone()];
            received.arguments = Some(vec![DashArg::Json(request)]);
            received.own_parts = own(&[Some("request")]);
            reverse.extend([answered, received]);
        }
        let (frame, _, limit_reached, _) = render(reverse, MAX_UPDATE_CHARACTERS);
        assert!(!limit_reached, "proxied={proxied}: no rows dropped");
        assert_eq!(frame["recordedRequests"].as_array().unwrap().len(), 100);
        if proxied {
            assert_eq!(frame["proxiedRequests"].as_array().unwrap().len(), 100);
        }
    }
}

#[test]
fn should_keep_every_row_when_under_the_ceiling() {
    let (frame, _, limit_reached, _) = render(exchanges(40, 1_000), MAX_UPDATE_CHARACTERS);
    assert!(!limit_reached);
    assert_eq!(frame["recordedRequests"].as_array().unwrap().len(), 40);
}

#[test]
fn should_cut_a_json_body_by_its_text() {
    let items: Vec<Value> = (0..20_000).map(|i| json!({"id": i})).collect();
    let tree = json!({"items": items});
    let text = serde_json::to_string(&tree).unwrap();
    let mut forwarded = DashEntry::new("j1", None, Some(&full_timestamp()), Some("FORWARDED_REQUEST"));
    forwarded.requests = vec![json!({"path": "/json", "body": tree})];
    forwarded.response = Some(json!({"body": "ok"}));
    forwarded.message_format = Some("forwarded".into());
    let frame = build_frame(vec![forwarded], vec![]);
    let row = &frame["proxiedRequests"][0];
    assert_eq!(row["value"]["httpRequest"]["body"], json!(text[..CAP]));
    assert_eq!(row["truncatedBodies"]["httpRequest"]["originalLength"], json!(text.len()));
}

#[test]
fn should_not_cut_a_surrogate_pair_in_half() {
    let text = format!("{}\u{1F600}{}", "a".repeat(CAP - 1), "b".repeat(100));
    let mut received = DashEntry::new("s1", None, Some(&full_timestamp()), Some("RECEIVED_REQUEST"));
    received.requests = vec![json!({"path": "/emoji", "body": text})];
    received.message_format = Some("received".into());
    let frame = build_frame(vec![received], vec![]);
    let shown = frame["recordedRequests"][0]["value"]["httpRequest"]["body"].as_str().unwrap().to_string();
    // in UTF-16 units, as Java counts: the pair is left out whole
    assert_eq!(shown.encode_utf16().count(), CAP - 1);
    assert_eq!(shown, "a".repeat(CAP - 1));
    assert_eq!(frame["recordedRequests"][0]["truncatedBodies"]["httpRequest"]["originalLength"], json!(CAP - 1 + 2 + 100));
}

#[test]
fn should_offer_to_load_an_argument_only_when_it_is_the_entrys_own_message() {
    let request = json!({"path": "/own", "body": body("own-", 100_000)});
    let mut entry = DashEntry::new("o1", None, Some(&full_timestamp()), Some("RECEIVED_REQUEST"));
    entry.requests = vec![request.clone()];
    entry.message_format = Some("received request:{}and a copy:{}".into());
    entry.arguments = Some(vec![DashArg::Json(request.clone()), DashArg::Json(request)]);
    // an equal copy is not the entry's own request
    entry.own_parts = own(&[Some("request"), None]);
    let frame = build_frame(vec![entry], vec![]);
    let mut markers = Vec::new();
    find_values(&frame["logMessages"][0]["value"]["messageParts"], "truncatedBody", &mut markers);
    assert_eq!(markers.len(), 2);
    assert_eq!(markers[0]["loadable"], json!(true), "the entry's own request");
    assert_eq!(markers[1]["loadable"], json!(false), "an equal copy");
}

fn binary_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|i| i as u8).collect()
}

fn encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn should_cut_a_large_binary_message_and_say_where_to_load_it_whole() {
    use base64::Engine;
    let message = binary_bytes(200_000);
    let frame = build_frame(vec![received_definition("b2", json!({"binaryData": encode(&message)}))], vec![]);
    let row = &frame["recordedRequests"][0];
    let shown = row["value"]["httpRequest"]["binaryData"].as_str().unwrap();
    assert_eq!(shown.len(), CAP);
    assert_eq!(base64::engine::general_purpose::STANDARD.decode(shown).unwrap(), message[..CAP / 4 * 3]);
    let marker = &row["truncatedBodies"]["httpRequest"];
    assert_eq!(marker["logEntryId"], json!("b2"));
    assert_eq!(marker["part"], json!("request"));
    assert_eq!(marker["originalLength"], json!(encode(&message).len()));
    assert_eq!(marker["loadable"], json!(true));
    // the length received, not the length shown
    assert_eq!(row["description"]["second"], json!("200000 bytes 000102030405060708090a0b0c0d0e0f..."));
}

#[test]
fn should_cut_a_large_binary_message_quoted_in_a_log_message() {
    let message = json!({"binaryData": encode(&binary_bytes(200_000))});
    let mut entry = DashEntry::new("b3", None, Some(&full_timestamp()), Some("EXPECTATION_MATCHED"));
    entry.requests = vec![message.clone()];
    entry.message_format = Some("request:{}matched".into());
    // another object of the same value upstream, so no own part
    entry.arguments = Some(vec![DashArg::Json(message)]);
    let frame = build_frame(vec![entry], vec![]);
    let argument = &frame["logMessages"][0]["value"]["messageParts"][1];
    assert_eq!(argument["value"]["binaryData"].as_str().unwrap().len(), CAP);
    assert!(argument.get("truncatedBody").is_some());
}

#[test]
fn should_charge_binary_rows_to_the_update_size_ceiling() {
    // one size the dashboard cuts, and one it sends whole
    for length in [200_000usize, 40_000] {
        let entries: Vec<DashEntry> = (0..20).map(|i| received_definition(&format!("b{i}"), json!({"binaryData": encode(&binary_bytes(length))}))).collect();
        let (frame, _, _, _) = render(entries, 5 * (CAP as u64 + MESSAGE_OVERHEAD_CHARACTERS));
        let rows = frame["recordedRequests"].as_array().unwrap().len();
        assert!(rows > 0 && rows < 8, "rows of {length} bytes: {rows}");
    }
}

#[test]
fn should_cut_large_expectation_bodies_so_an_update_stays_small() {
    const MIB: usize = 1024 * 1024;
    const EXPECTATIONS: usize = 20;
    let body = "r".repeat(MIB);
    let expectations: Vec<ActiveExpectation> = (0..EXPECTATIONS).map(|i| expectation(&format!("large-{i:03}"), &format!("/large-{i}"), &body)).collect();
    let frame = build_frame(vec![], expectations);
    let active = frame["activeExpectations"].as_array().unwrap();
    assert_eq!(active.len(), EXPECTATIONS);
    assert!(frame_text(&frame, false).len() < EXPECTATIONS * (CAP + 2048));
    let item = &active[0];
    assert_eq!(item["value"]["httpResponse"]["body"], json!("r".repeat(CAP)));
    assert_eq!(item["truncatedExpectation"], json!({"expectationId": "large-000", "part": "expectation", "originalLength": MIB, "shownLength": CAP}));
}

#[test]
fn should_cut_request_matcher_json_bodies_and_other_long_strings_and_leave_small_expectations_whole() {
    let items: Vec<Value> = (0..CAP / 4).map(|_| json!("abcdefgh")).chain([json!("end")]).collect();
    let json_body = ActiveExpectation {
        id: "json-body".into(),
        http_request: json!({"path": "/json"}),
        value: json!({"httpRequest": {"path": "/json", "body": {"type": "JSON", "json": {"items": items}}}, "httpResponse": {"body": "small"}, "id": "json-body"}),
    };
    let template = ActiveExpectation {
        id: "long-template".into(),
        http_request: json!({"path": "/template"}),
        value: json!({"httpRequest": {"path": "/template"}, "httpResponseTemplate": {"templateType": "VELOCITY", "template": "t".repeat(CAP + 10)}, "id": "long-template"}),
    };
    // a binary message's bytes are not text in upstream's tree, and never cut
    let binary = ActiveExpectation {
        id: "binary".into(),
        http_request: json!({"binaryData": encode(&binary_bytes(60_000))}),
        value: json!({"httpRequest": {"binaryData": encode(&binary_bytes(60_000))}, "binaryResponse": {"binaryData": "AQID"}, "id": "binary"}),
    };
    let frame = build_frame(vec![], vec![json_body, template, expectation("small", "/small", "small body"), binary]);
    let active = frame["activeExpectations"].as_array().unwrap();
    let shown = active[0]["value"]["httpRequest"]["body"].as_str().unwrap();
    assert_eq!(shown.len(), CAP);
    assert!(shown.contains("\"items\""));
    assert_eq!(active[0]["value"]["httpResponse"]["body"], json!("small"));
    assert!(active[0].get("truncatedExpectation").is_some());
    assert_eq!(active[1]["value"]["httpResponseTemplate"]["template"].as_str().unwrap().len(), CAP);
    assert_eq!(active[1]["truncatedExpectation"]["originalLength"], json!(CAP + 10));
    assert_eq!(active[2]["value"]["httpResponse"]["body"], json!("small body"));
    assert!(active[2].get("truncatedExpectation").is_none());
    assert_eq!(active[3]["value"]["httpRequest"]["binaryData"].as_str().unwrap().len(), encode(&binary_bytes(60_000)).len());
    assert!(active[3].get("truncatedExpectation").is_none());
}
