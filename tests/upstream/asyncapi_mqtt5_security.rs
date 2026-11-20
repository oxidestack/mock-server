//! `Mqtt5SecurityOptionsTest` (mockserver-async): the connect options `MqttSecurity` gives an MQTT 5 client
//! (`connect_options`, `Mqtt5SecurityOptions.buildConnectOptions`), whose password goes out as its UTF-8 bytes.

use mock_server::asyncapi::mqtt::{MqttSecurity, connect_options};

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

// ---- Mqtt5SecurityOptionsTest ----

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
    let options = connect_options(Some(&MqttSecurity { username: some("u"), password: some("p"), ..Default::default() })).unwrap();
    assert_eq!(options.username.as_deref(), Some("u"));
    assert_eq!(options.password.as_deref().map(str::as_bytes), Some("p".as_bytes()));
}

#[test]
fn should_set_ssl_properties() {
    let security = MqttSecurity { ssl_properties: vec![("com.ibm.ssl.trustStore".into(), "/t.jks".into())], ..Default::default() };
    let options = connect_options(Some(&security)).unwrap();
    assert_eq!(options.ssl_properties, [("com.ibm.ssl.trustStore".to_string(), "/t.jks".to_string())]);
}

#[test]
fn should_not_set_blank_username() {
    let options = connect_options(Some(&MqttSecurity { username: some(""), password: some("pass"), ..Default::default() })).unwrap();
    assert_eq!(options.username, None);
    assert_eq!(options.password.as_deref().map(str::as_bytes), Some("pass".as_bytes()));
}
