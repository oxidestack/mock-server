//! `PublishOptionsTest` (mockserver-async): the per-message options a publisher receives.

use mock_server::asyncapi::broker::PublishOptions;

fn options(key: Option<&str>, qos: Option<i32>, retain: Option<bool>) -> PublishOptions {
    PublishOptions::new(key, qos, retain, &[]).unwrap()
}

fn headers(o: &PublishOptions) -> Vec<(&str, &str)> {
    o.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

// ---- PublishOptionsTest ----

#[test]
fn should_create_with_all_fields() {
    let o = options(Some("my-key"), Some(2), Some(true));
    assert_eq!((o.key.as_deref(), o.qos, o.retain), (Some("my-key"), Some(2), Some(true)));
    assert!(!o.is_empty());
}

#[test]
fn should_create_with_all_nulls() {
    let o = options(None, None, None);
    assert_eq!((o.key.as_deref(), o.qos, o.retain), (None, None, None));
    assert!(o.is_empty());
}

#[test]
fn none_should_be_empty() {
    let none = PublishOptions::none();
    assert!(none.is_empty());
    assert_eq!((none.key.as_deref(), none.qos, none.retain), (None, None, None));
    assert!(none.headers.is_empty());
}

#[test]
fn should_not_be_empty_with_only_key() {
    assert!(!options(Some("k"), None, None).is_empty());
}

#[test]
fn should_not_be_empty_with_only_qos() {
    assert!(!options(None, Some(1), None).is_empty());
}

#[test]
fn should_not_be_empty_with_only_retain() {
    assert!(!options(None, None, Some(false)).is_empty());
}

#[test]
fn should_accept_qos0() {
    assert_eq!(options(None, Some(0), None).qos, Some(0));
}

#[test]
fn should_accept_qos1() {
    assert_eq!(options(None, Some(1), None).qos, Some(1));
}

#[test]
fn should_accept_qos2() {
    assert_eq!(options(None, Some(2), None).qos, Some(2));
}

#[test]
fn should_reject_qos3() {
    assert_eq!(PublishOptions::new(None, Some(3), None, &[]).unwrap_err().message, "MQTT QoS must be 0, 1, or 2; got: 3");
}

#[test]
fn should_reject_negative_qos() {
    assert_eq!(PublishOptions::new(None, Some(-1), None, &[]).unwrap_err().message, "MQTT QoS must be 0, 1, or 2; got: -1");
}

#[test]
fn to_string_should_contain_all_fields() {
    let text = options(Some("k1"), Some(2), Some(true)).to_string();
    assert!(text.contains("key=k1") && text.contains("qos=2") && text.contains("retain=true"), "{text}");
    assert_eq!(text, "PublishOptions{key=k1, qos=2, retain=true, headers={}}");
}

// ---- Headers tests ----

#[test]
fn should_create_with_headers() {
    let o = PublishOptions::new(None, None, None, &[("correlationId", "abc-123"), ("trace-id", "xyz")]).unwrap();
    assert_eq!(headers(&o), [("correlationId", "abc-123"), ("trace-id", "xyz")]);
    assert!(!o.is_empty());
}

#[test]
fn should_return_empty_headers_when_null() {
    // A Java `null` map and an empty one are the same here: no headers.
    let o = PublishOptions::new(None, None, None, &[]).unwrap();
    assert!(o.headers.is_empty());
    assert!(o.is_empty());
}

#[test]
fn should_return_empty_headers_when_empty_map() {
    let o = PublishOptions::new(None, None, None, &[]).unwrap();
    assert!(o.headers.is_empty());
    assert!(o.is_empty());
}

#[test]
fn should_not_be_empty_with_only_headers() {
    assert!(!PublishOptions::new(None, None, None, &[("h1", "v1")]).unwrap().is_empty());
}

#[test]
fn headers_should_be_defensively_copied() {
    let mut source = vec![("key", "value")];
    let o = PublishOptions::new(None, None, None, &source).unwrap();
    source.push(("extra", "should-not-appear"));
    assert_eq!(headers(&o), [("key", "value")]);
}

/// Upstream wraps the headers in an unmodifiable map. Here a publisher only ever gets `&PublishOptions`, which the
/// compiler keeps from being changed; what a caller changes in its own copy does not reach the options it copied.
#[test]
fn headers_should_be_unmodifiable() {
    let o = PublishOptions::new(None, None, None, &[("key", "value")]).unwrap();
    let shared: &PublishOptions = &o;
    let mut copy = shared.clone();
    copy.headers.push(("new".into(), "should-fail".into()));
    assert_eq!(headers(&o), [("key", "value")]);
}

#[test]
fn backward_compat_constructor_should_have_empty_headers() {
    assert!(options(Some("k"), Some(1), Some(true)).headers.is_empty());
}

#[test]
fn to_string_should_contain_headers() {
    let text = PublishOptions::new(None, None, None, &[("h1", "v1")]).unwrap().to_string();
    assert!(text.contains("headers=") && text.contains("h1=v1"), "{text}");
    assert_eq!(text, "PublishOptions{key=null, qos=null, retain=null, headers={h1=v1}}");
}
