//! `MqttSecurityOptionsTest` (mockserver-async): the `MqttSecurity` model and the connect options it gives an MQTT
//! 3.1.1 client (`connect_options`, `MqttSecurityOptions.buildConnectOptions`). The builder is a struct literal here;
//! "null options" (Paho's defaults) is `None`.

use mock_server::asyncapi::mqtt::{MqttSecurity, connect_options};

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

fn ssl(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn ssl_property<'a>(properties: &'a [(String, String)], key: &str) -> Option<&'a str> {
    properties.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

// ---- MqttSecurityOptionsTest ----

#[test]
fn empty_security_should_be_empty() {
    assert!(MqttSecurity::default().is_empty());
}

#[test]
fn security_with_username_should_not_be_empty() {
    assert!(!MqttSecurity { username: some("user"), ..Default::default() }.is_empty());
}

#[test]
fn security_with_password_should_not_be_empty() {
    assert!(!MqttSecurity { password: some("pass"), ..Default::default() }.is_empty());
}

#[test]
fn security_with_ssl_properties_should_not_be_empty() {
    assert!(!MqttSecurity { ssl_properties: ssl(&[("com.ibm.ssl.trustStore", "/t.jks")]), ..Default::default() }.is_empty());
}

#[test]
fn security_with_blank_fields_should_be_empty() {
    assert!(MqttSecurity { username: some(""), password: some("  "), ..Default::default() }.is_empty());
}

/// The security keeps its own copy of the SSL properties: changing the caller's map afterwards does not reach it.
/// (Mutating them through a shared `&MqttSecurity` does not compile, where Java throws
/// `UnsupportedOperationException`.)
#[test]
fn ssl_properties_should_be_unmodifiable() {
    let mut mutable = ssl(&[("key", "value")]);
    let sec = MqttSecurity { ssl_properties: mutable.clone(), ..Default::default() };
    mutable.push(("key2".into(), "value2".into()));
    assert_eq!(sec.ssl_properties.len(), 1);
}

#[test]
fn should_return_null_for_null_security() {
    assert_eq!(connect_options(None), None);
}

#[test]
fn should_return_null_for_empty_security() {
    assert_eq!(connect_options(Some(&MqttSecurity::default())), None);
}

#[test]
fn should_set_username_and_password() {
    let options = connect_options(Some(&MqttSecurity { username: some("myuser"), password: some("mypass"), ..Default::default() })).unwrap();
    assert_eq!(options.username.as_deref(), Some("myuser"));
    assert_eq!(options.password.as_deref(), Some("mypass"));
}

#[test]
fn should_set_only_username() {
    let options = connect_options(Some(&MqttSecurity { username: some("myuser"), ..Default::default() })).unwrap();
    assert_eq!(options.username.as_deref(), Some("myuser"));
    assert_eq!(options.password, None, "the password stays at Paho's default");
}

#[test]
fn should_set_ssl_properties() {
    let security = MqttSecurity {
        ssl_properties: ssl(&[
            ("com.ibm.ssl.trustStore", "/truststore.jks"),
            ("com.ibm.ssl.trustStorePassword", "tspass"),
            ("com.ibm.ssl.protocol", "TLSv1.2"),
        ]),
        ..Default::default()
    };
    let options = connect_options(Some(&security)).unwrap();
    assert_eq!(ssl_property(&options.ssl_properties, "com.ibm.ssl.trustStore"), Some("/truststore.jks"));
    assert_eq!(ssl_property(&options.ssl_properties, "com.ibm.ssl.trustStorePassword"), Some("tspass"));
    assert_eq!(ssl_property(&options.ssl_properties, "com.ibm.ssl.protocol"), Some("TLSv1.2"));
}

#[test]
fn should_set_username_password_and_ssl_properties() {
    let security = MqttSecurity {
        username: some("u"),
        password: some("p"),
        ssl_properties: ssl(&[("com.ibm.ssl.trustStore", "/t.jks"), ("com.ibm.ssl.trustStorePassword", "x")]),
    };
    let options = connect_options(Some(&security)).unwrap();
    assert_eq!(options.username.as_deref(), Some("u"));
    assert_eq!(options.password.as_deref(), Some("p"));
    assert_eq!(ssl_property(&options.ssl_properties, "com.ibm.ssl.trustStore"), Some("/t.jks"));
    assert_eq!(ssl_property(&options.ssl_properties, "com.ibm.ssl.trustStorePassword"), Some("x"));
}

#[test]
fn should_not_set_blank_username() {
    let options = connect_options(Some(&MqttSecurity { username: some(""), password: some("pass"), ..Default::default() })).unwrap();
    assert_eq!(options.username, None, "a blank username is not set");
    assert_eq!(options.password.as_deref(), Some("pass"));
}
