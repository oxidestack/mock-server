//! An expectation's side actions: `beforeActions` run ahead of the response (a blocking webhook can gate it),
//! `afterActions` fire once it is served, and `steps` is the ordered pipeline that replaces both: the steps before
//! the `responder` step run like before-actions, the responder's action is the response, the rest fire afterwards.
//! Webhook requests resolve OpenAPI runtime expressions (`{$request.body#/id}`, `{$url}`, …) against the
//! triggering request (`OpenApiRuntimeExpressionResolver`), or are rendered from an `httpRequestTemplate`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::templates::PathMatch;

/// The step targets, each of which makes a step's action (`ExpectationStep`).
const STEP_TARGETS: &[&str] = &["httpRequest", "httpClassCallback", "httpObjectCallback", "httpForward", "httpOverrideForwardedRequest", "httpResponse", "httpError"];

/// `Expectation.hasTopLevelPrimaryAction`, and `getAllActions`' order.
const TOP_LEVEL_ACTIONS: &[&str] = &[
    "httpResponse",
    "httpResponseTemplate",
    "httpResponseClassCallback",
    "httpResponseObjectCallback",
    "httpForward",
    "httpForwardTemplate",
    "httpForwardClassCallback",
    "httpForwardObjectCallback",
    "httpOverrideForwardedRequest",
    "httpForwardValidateAction",
    "httpForwardWithFallback",
    "httpSseResponse",
    "httpLlmResponse",
    "httpWebSocketResponse",
    "grpcStreamResponse",
    "grpcBidiResponse",
    "binaryResponse",
    "dnsResponse",
    "httpError",
];

fn present<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

fn steps(expectation: &Map<String, Value>) -> &[Value] {
    present(expectation, "steps").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn is_responder(step: &Value) -> bool {
    step.get("responder").and_then(Value::as_bool) == Some(true)
}

/// `Expectation.validateSteps`: why the expectation's steps are unusable, if they are.
pub fn validate_steps(expectation: &Map<String, Value>) -> Option<String> {
    let steps = steps(expectation);
    if steps.is_empty() {
        return None;
    }
    if present(expectation, "beforeActions").and_then(Value::as_array).is_some_and(|b| !b.is_empty()) {
        return Some("steps cannot be combined with beforeActions - use steps for the full ordered pipeline".into());
    }
    let responses = present(expectation, "httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty());
    if responses || TOP_LEVEL_ACTIONS.iter().any(|k| present(expectation, k).is_some()) {
        return Some("steps cannot be combined with a top-level response action - the responder step defines the action".into());
    }
    let mut responders = 0;
    let mut error = false;
    for (i, step) in steps.iter().enumerate() {
        let empty = Map::new();
        let o = step.as_object().unwrap_or(&empty);
        match STEP_TARGETS.iter().filter(|k| present(o, k).is_some()).count() {
            0 => return Some(format!("step[{i}] has no action target set")),
            1 => {}
            _ => return Some(format!("step[{i}] has multiple action targets set; each step must have exactly one")),
        }
        error |= present(o, "httpError").is_some();
        if is_responder(step) {
            responders += 1;
            if present(o, "httpRequest").is_some() {
                return Some(format!(
                    "step[{i}] is marked as responder but uses httpRequest (webhook); webhooks are side-effect-only and cannot produce a response"
                ));
            }
        }
    }
    match responders {
        0 => Some("steps must contain exactly one step with responder=true, but none found".into()),
        1 if error && steps.len() > 1 => Some("httpError cannot be combined with other steps; it must be the only step".into()),
        1 => None,
        n => Some(format!("steps must contain exactly one step with responder=true, but found {n}")),
    }
}

/// `getAllActions`: the action keys the expectation sets, in upstream's order.
fn actions(expectation: &Map<String, Value>) -> Vec<&'static str> {
    let responses = present(expectation, "httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty());
    TOP_LEVEL_ACTIONS.iter().copied().filter(|k| present(expectation, k).is_some() && !(responses && *k == "httpResponse")).collect()
}

/// How many [`actions`] the expectation sets, told from its own (few) keys, without looking each action name up.
fn action_count(expectation: &Map<String, Value>) -> usize {
    let mut count = 0;
    let mut response = false;
    for (key, value) in expectation {
        if !value.is_null() && TOP_LEVEL_ACTIONS.contains(&key.as_str()) {
            count += 1;
            response |= key == "httpResponse";
        }
    }
    // a non-empty `httpResponses` stands in for `httpResponse`
    if response && present(expectation, "httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty()) {
        count -= 1;
    }
    count
}

/// `getPrimaryAction` with several action types: the one marked `primary`, or why there is none.
pub fn primary(expectation: &Map<String, Value>) -> Result<Option<&'static str>, &'static str> {
    if action_count(expectation) < 2 || !steps(expectation).is_empty() {
        return Ok(None);
    }
    let actions = actions(expectation);
    let marked: Vec<&str> = actions.into_iter().filter(|k| expectation[*k].get("primary").and_then(Value::as_bool) == Some(true)).collect();
    match marked.as_slice() {
        [one] => Ok(Some(one)),
        [] => Err("when multiple action types are configured, exactly one must be marked as primary"),
        _ => Err("multiple actions marked as primary, only one action can be primary when multiple action types are configured"),
    }
}

/// The input the expectation's primary action compiles from: the responder step, or with several action types the
/// expectation without its secondary actions.
pub fn primary_input(expectation: &Map<String, Value>) -> std::borrow::Cow<'_, Map<String, Value>> {
    use std::borrow::Cow;
    if let Some(step) = responder(expectation) {
        return Cow::Borrowed(step);
    }
    match primary(expectation) {
        Ok(Some(key)) => {
            let secondary = actions(expectation);
            Cow::Owned(expectation.iter().filter(|(k, _)| k.as_str() == key || !secondary.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect())
        }
        _ => Cow::Borrowed(expectation),
    }
}

/// `key` of the responder step of an expectation (in any JSON form), when steps are configured.
pub fn responder_value<'a>(expectation: &'a Value, key: &str) -> Option<&'a Value> {
    expectation.as_object().and_then(responder).and_then(|step| present(step, key))
}

/// The responder step, whose action is the expectation's primary action when steps are configured.
pub fn responder(expectation: &Map<String, Value>) -> Option<&Map<String, Value>> {
    steps(expectation).iter().find(|s| is_responder(s)).and_then(Value::as_object)
}

/// Whether serving the expectation involves anything this module runs.
pub fn any(expectation: &Value) -> bool {
    ["beforeActions", "afterActions", "steps"].iter().any(|k| expectation.get(k).and_then(Value::as_array).is_some_and(|a| !a.is_empty()))
        || expectation.as_object().is_some_and(|o| action_count(o) > 1)
}

/// `dispatchSecondaryAction`: every action but the primary, fire-and-forget after its own delay. Only forwards and
/// class callbacks have an effect anyone can see; a response or template action's result goes nowhere.
pub fn secondary(trigger: &Trigger, expectation: &Value) {
    let Some(o) = expectation.as_object() else { return };
    let Ok(Some(primary)) = primary(o) else { return };
    for key in actions(o).into_iter().filter(|k| *k != primary) {
        let action = o[key].clone();
        let trigger = trigger.clone();
        let delay = action.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay).map(|d| d.fixed);
        // `sheddable`: dropped when the delayed side actions' budget is full
        let Ok(waiting) = trigger.state.overload.side_action(&trigger.state, delay) else { continue };
        tokio::spawn(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            drop(waiting);
            let state = &trigger.state;
            match key {
                "httpResponseClassCallback" => {
                    if let Some(class) = action.get("callbackClass").and_then(Value::as_str) {
                        let model = crate::recorded::ordered_with_path_parameters(&trigger.request, &trigger.path.parameters);
                        let _ = crate::class_callback::respond(state, class, &trigger.request, model).await;
                    }
                }
                "httpForward" | "httpForwardTemplate" | "httpForwardClassCallback" | "httpOverrideForwardedRequest" | "httpForwardValidateAction" | "httpForwardWithFallback" => {
                    let single: Map<String, Value> = [(key.to_string(), action)].into_iter().collect();
                    if let Some(forward) = crate::forward::Forward::compile(&single) && forward.execute(state, &trigger.request, &trigger.path).await.is_err() {
                        crate::log::info(state, &format!("secondary forward action {} failed", action_type(key)));
                    }
                }
                _ => {}
            }
        });
    }
}

/// `Action.Type` of an action key.
fn action_type(key: &str) -> &'static str {
    match key {
        "httpForward" => "FORWARD",
        "httpForwardTemplate" => "FORWARD_TEMPLATE",
        "httpForwardClassCallback" => "FORWARD_CLASS_CALLBACK",
        "httpForwardObjectCallback" => "FORWARD_OBJECT_CALLBACK",
        "httpOverrideForwardedRequest" => "FORWARD_REPLACE",
        "httpForwardValidateAction" => "FORWARD_VALIDATE",
        "httpForwardWithFallback" => "FORWARD_WITH_FALLBACK",
        "httpResponseTemplate" => "RESPONSE_TEMPLATE",
        "httpResponseClassCallback" => "RESPONSE_CLASS_CALLBACK",
        "httpResponseObjectCallback" => "RESPONSE_OBJECT_CALLBACK",
        "httpSseResponse" => "SSE_RESPONSE",
        "httpWebSocketResponse" => "WEBSOCKET_RESPONSE",
        "grpcStreamResponse" => "GRPC_STREAM_RESPONSE",
        "grpcBidiResponse" => "GRPC_BIDI_RESPONSE",
        "binaryResponse" => "BINARY_RESPONSE",
        "dnsResponse" => "DNS_RESPONSE",
        "httpLlmResponse" => "LLM_RESPONSE",
        "httpError" => "ERROR",
        _ => "RESPONSE",
    }
}

/// The key of the expectation's primary action (`getAction`), if it has one.
fn primary_key(expectation: &Map<String, Value>) -> Option<&str> {
    if let Some(step) = responder(expectation) {
        return STEP_TARGETS.iter().copied().find(|k| present(step, k).is_some());
    }
    match primary(expectation) {
        Ok(Some(key)) => Some(key),
        Ok(None) => present(expectation, "httpResponses").and_then(Value::as_array).filter(|r| !r.is_empty()).map(|_| "httpResponse").or_else(|| actions(expectation).first().copied()),
        Err(_) => None,
    }
}

/// `RequestMatchers.validateRespondBeforeBody`: an expectation answered from the request headers can match nothing
/// in the body and can only respond or fail.
pub fn validate_respond_before_body(expectation: &Map<String, Value>) -> Option<String> {
    let request = present(expectation, "httpRequest")?;
    if request.get("respondBeforeBody").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    if request.get("body").is_some_and(|b| !b.is_null()) {
        return Some("respondBeforeBody=true cannot be combined with a body matcher: the body has not yet been received when matching occurs".into());
    }
    match primary_key(expectation).map(action_type) {
        None => Some("respondBeforeBody=true requires a RESPONSE or ERROR action".into()),
        Some("RESPONSE" | "ERROR") => None,
        Some(other) => Some(format!("respondBeforeBody=true only supports action types RESPONSE and ERROR, was: {other}")),
    }
}

/// A side action or step, as the dispatcher sees it.
struct Side<'a> {
    o: &'a Map<String, Value>,
}

impl Side<'_> {
    fn blocking(&self) -> bool {
        self.o.get("blocking").and_then(Value::as_bool).unwrap_or(true)
    }

    fn fail_fast(&self) -> bool {
        self.o.get("failurePolicy").and_then(Value::as_str) == Some("FAIL_FAST")
    }

    fn duration(&self, key: &str) -> Option<Duration> {
        present(self.o, key).and_then(crate::action::delay).map(|d| d.fixed)
    }
}

/// The context a side action runs in: the triggering request and what its path matched.
#[derive(Clone)]
pub struct Trigger {
    pub state: Arc<State>,
    pub request: HttpRequest,
    pub path: PathMatch,
}

/// Runs the before-actions (or the steps before the responder): `Err` with the 502's body when a fail-fast blocking
/// webhook failed, in which case the response is that ([`bad_gateway`]) and nothing else.
pub async fn before(trigger: &Trigger, expectation: &Value) -> Result<(), String> {
    let (list, label): (Vec<&Value>, &str) = match expectation.get("steps").and_then(Value::as_array).filter(|s| !s.is_empty()) {
        Some(steps) => (steps.iter().take_while(|s| !is_responder(s)).collect(), "step"),
        None => (expectation.get("beforeActions").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default(), "before-action"),
    };
    for action in list {
        let Some(o) = action.as_object() else { continue };
        let side = Side { o };
        let template = present(o, "httpRequestTemplate").filter(|_| label != "step");
        if !side.blocking() || (template.is_none() && present(o, "httpRequest").is_none()) {
            dispatch(trigger, o, label);
            continue;
        }
        let request = match webhook_request(trigger, o, label) {
            Some(Ok(request)) => request,
            Some(Err(failed)) => {
                log_not_sent(trigger, &failed, "blocking before-action");
                if side.fail_fast() {
                    return Err(format!("before-action failed: {}", failed.detail));
                }
                continue;
            }
            None => continue,
        };
        if let Some(refused) = crate::forward::refused_webhook(&trigger.state, &request, &trigger.request, label).await {
            if side.fail_fast() {
                return Err(format!("{label} failed: {refused}"));
            }
            continue;
        }
        let timeout = side.duration("timeout").unwrap_or_else(|| Duration::from_millis(trigger.state.config.int_property("maxSocketTimeoutInMillis", 20_000).max(0) as u64));
        let failure = match tokio::time::timeout(timeout, crate::forward::send_json(&trigger.state, &request)).await {
            Ok(Ok(_)) => None,
            Ok(Err(e)) => Some(WebhookFailure::blocking(&e)),
            Err(_) => Some(WebhookFailure::timed_out(&trigger.state)),
        };
        if let Some(failure) = failure {
            let what = if label == "step" { "blocking step" } else { "blocking before-action" };
            failure.log(trigger, what, &request, false);
            let message = failure.message;
            if side.fail_fast() {
                return Err(format!("{} failed: {message}", if label == "step" { "step" } else { "before-action" }));
            }
        }
    }
    Ok(())
}

/// The 502 a failed fail-fast blocking webhook answers with, `body` from [`before`].
pub fn bad_gateway(body: String) -> Reply {
    let mut reply = Reply::status(502);
    reply.reason = Some("Bad Gateway".into());
    reply.body = body.into();
    reply
}

/// Fires the steps after the responder (unless a fail-fast step aborted the pipeline), then the after-actions.
pub fn after(trigger: &Trigger, expectation: &Value, served: bool) {
    if let Some(steps) = expectation.get("steps").and_then(Value::as_array).filter(|_| served) {
        for step in steps.iter().skip_while(|s| !is_responder(s)).skip(1).filter_map(Value::as_object) {
            dispatch(trigger, step, "step");
        }
    }
    for action in expectation.get("afterActions").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
        dispatch(trigger, action, "after-action");
    }
}

/// Fires [`after`] when dropped, which is once the response has been handed over.
pub struct After {
    pub trigger: Trigger,
    pub expectation: Value,
}

impl Drop for After {
    fn drop(&mut self) {
        after(&self.trigger, &self.expectation, true);
    }
}


/// A failed webhook as `HttpActionHandler` logs it: the message after ` - ` (`getMessage()` of the throwable) and the
/// throwable's chain, outermost first.
struct WebhookFailure {
    message: String,
    chain: Vec<Thrown>,
}

/// One throwable of a chain: its class, its message, and whether it has frames (Netty's `AnnotatedConnectException`
/// has none, so Jackson writes no `stackTrace` for it). JVM frames cannot be reproduced: one that has them is written
/// with an empty `stackTrace`.
struct Thrown {
    class: String,
    message: Option<String>,
    frames: bool,
}

impl Thrown {
    fn new(class: impl Into<String>, message: Option<String>) -> Thrown {
        Thrown { class: class.into(), message, frames: true }
    }
}

impl WebhookFailure {
    /// `whenComplete`'s throwable (a fire-and-forget webhook): the exception the client's future failed with, Netty's
    /// `AnnotatedConnectException` around the JDK's `ConnectException` for a refused connection (8.0.0).
    fn completed(e: &crate::client::Error, webhook: &Value) -> WebhookFailure {
        if let Some(failure) = WebhookFailure::handshake(e, webhook) {
            return failure;
        }
        WebhookFailure { message: e.exception_message().unwrap_or_else(|| "null".into()), chain: WebhookFailure::future_chain(e) }
    }

    /// A TLS handshake the JDK failed (`SSLHandshakeException`): the client wraps it as `TLS handshake with <host:port>
    /// failed: <description>`, around the `SSLHandshakeException` and the exception behind it (the certificate or
    /// path validation fault the description quotes after `; caused by`, else the message past its alert), three
    /// deep (read off the 9.2.0 oracle).
    fn handshake(e: &crate::client::Error, webhook: &Value) -> Option<WebhookFailure> {
        let crate::client::Error::TlsFailure(description) = e else { return None };
        let detail = description.strip_prefix("SSLHandshakeException: ")?;
        let (host, port, _, _) = crate::forward::outbound_json(webhook);
        let (message, root) = match detail.split_once("; caused by ") {
            Some((message, root)) => (message, root.split_once(": ").map(|(class, text)| (class, text.to_string()))),
            None => (detail, None),
        };
        let behind = match root {
            Some((class, text)) => Thrown::new(format!("java.security.cert.{class}"), Some(text)),
            None => {
                let text = message.strip_prefix('(').and_then(|m| m.split_once(") ")).map_or(message, |(_, text)| text);
                let class = if text.starts_with("PKIX path") { "java.security.cert.CertPathValidatorException" } else { "java.security.cert.CertificateException" };
                Thrown::new(class, Some(text.into()))
            }
        };
        let wrapped = format!("TLS handshake with {host}:{port} failed: {description}");
        Some(WebhookFailure {
            chain: vec![
                Thrown::new("org.mockserver.httpclient.SocketConnectionException", Some(wrapped.clone())),
                Thrown::new("javax.net.ssl.SSLHandshakeException", Some(message.into())),
                behind,
            ],
            message: wrapped,
        })
    }

    fn future_chain(e: &crate::client::Error) -> Vec<Thrown> {
        let mut chain = vec![Thrown::new(e.exception_class(), e.exception_message())];
        if let crate::client::Error::Refused(_) = e {
            chain[0].frames = false;
            chain.push(Thrown::new("java.net.ConnectException", Some(crate::client::CONNECT_REFUSED.into())));
        }
        chain
    }

    /// What `NettyHttpClient.sendRequest(request, timeout, unit)` throws for that failure (a blocking webhook): a
    /// `SocketConnectionException` around a connect, resolve or other I/O failure, the client's own
    /// `SocketConnectionException` as it is, else a `RuntimeException` around the `ExecutionException` (8.0.0;
    /// only the refused connection is verified against the oracle).
    fn blocking(e: &crate::client::Error) -> WebhookFailure {
        use crate::client::Error;
        const CONNECTION: &str = "org.mockserver.httpclient.SocketConnectionException";
        let message = e.send_failure();
        let mut chain = WebhookFailure::future_chain(e);
        match e {
            _ if e.exception_class() == CONNECTION => {}
            Error::Refused(_) | Error::ConnectTimeout(_) | Error::Resolve { .. } | Error::Tls | Error::Jdk(_) => chain.insert(0, Thrown::new(CONNECTION, Some(message.clone()))),
            _ => {
                chain.insert(0, Thrown::new("java.util.concurrent.ExecutionException", Some(e.exception_string())));
                chain.insert(0, Thrown::new("java.lang.RuntimeException", Some(message.clone())));
            }
        }
        WebhookFailure { message, chain }
    }

    /// The blocking webhook's `timeout` (or `maxSocketTimeoutInMillis`) elapsed: `get(timeout, unit)`'s
    /// `TimeoutException` rethrown as a `SocketCommunicationException` that names `maxSocketTimeoutInMillis` whatever
    /// the timeout was, with no cause (8.0.0).
    fn timed_out(state: &State) -> WebhookFailure {
        let millis = state.config.int_property("maxSocketTimeoutInMillis", 20_000);
        let message = format!("Response was not received from MockServer after {millis} milliseconds, to wait longer please use \"mockserver.maxSocketTimeout\" system property or ConfigurationProperties.maxSocketTimeout(long milliseconds)");
        WebhookFailure { chain: vec![Thrown::new("org.mockserver.httpclient.SocketCommunicationException", Some(message.clone()))], message }
    }

    /// The console text of the chain: `<class>: <message>` and a `Caused by:` line for each cause.
    fn trace(&self) -> String {
        let lines: Vec<String> = self.chain.iter().enumerate().map(|(i, t)| {
            let prefix = if i == 0 { "" } else { "Caused by: " };
            match &t.message {
                Some(message) => format!("{prefix}{}: {message}", t.class),
                None => format!("{prefix}{}", t.class),
            }
        }).collect();
        lines.join("\n")
    }

    /// Jackson's bean of the chain (`cause`, `localizedMessage`, `message`, `stackTrace`).
    fn bean(chain: &[Thrown]) -> Value {
        let mut bean = Map::new();
        let Some((thrown, causes)) = chain.split_first() else { return Value::Object(bean) };
        if !causes.is_empty() {
            bean.insert("cause".into(), WebhookFailure::bean(causes));
        }
        if let Some(message) = &thrown.message {
            bean.insert("localizedMessage".into(), message.clone().into());
            bean.insert("message".into(), message.clone().into());
        }
        if thrown.frames {
            bean.insert("stackTrace".into(), Value::Array(Vec::new()));
        }
        Value::Object(bean)
    }

    /// `logEvent` of a WARN-typed entry at INFO about the triggering request (`setCorrelationId`, `setHttpRequest`),
    /// the webhook as its argument and the throwable: in the event log, and on the console with the throwable after it.
    /// `portless`: logged from the client's event loop (a fire-and-forget webhook's `whenComplete`), which stamps no
    /// port on the entry (8.0.0's event log; its console line shows the port on some runs).
    fn log(&self, trigger: &Trigger, what: &str, webhook: &Value, portless: bool) {
        let state = &trigger.state;
        if !state.info_enabled() {
            return;
        }
        let trace = self.trace();
        let mut entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format!("{what} webhook failed for request{{}} - {}", self.message))
            .level(crate::recorded::Level::Info)
            .request(&trigger.request)
            .args([webhook])
            .throwable(&trace)
            .throwable_bean(WebhookFailure::bean(&self.chain));
        entry.portless = portless;
        crate::log::entry_with_throwable(state, crate::recorded::Level::Info, &entry, Some(&trigger.request), &trace);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(trigger.request.clone())));
    }
}

/// `dispatchSideAction` / `dispatchStepSideEffect`: fire-and-forget after the action's delay; the outcome only
/// reaches the log.
fn dispatch(trigger: &Trigger, action: &Map<String, Value>, label: &'static str) {
    let trigger = trigger.clone();
    let action = action.clone();
    let delay = (Side { o: &action }).duration("delay");
    // `sheddable`: dropped when the delayed side actions' budget is full
    let Ok(waiting) = trigger.state.overload.side_action(&trigger.state, delay) else { return };
    tokio::spawn(async move {
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        drop(waiting);
        let state = &trigger.state;
        if let Some(request) = webhook_request(&trigger, &action, label) {
            let request = match request {
                Ok(request) => request,
                Err(failed) => return log_not_sent(&trigger, &failed, label),
            };
            if crate::forward::refused_webhook(state, &request, &trigger.request, label).await.is_some() {
                return;
            }
            if let Err(e) = crate::forward::send_json(state, &request).await {
                // the oracle stamps the port on it or not, depending on the thread that completes the client's future
                // (seen both ways)
                WebhookFailure::completed(&e, &request).log(&trigger, label, &request, true);
            }
        } else if let Some(class) = present(&action, "httpClassCallback").and_then(|c| c.get("callbackClass")).and_then(Value::as_str) {
            let model = crate::recorded::ordered_with_path_parameters(&trigger.request, &trigger.path.parameters);
            let _ = crate::class_callback::respond(state, class, &trigger.request, model).await;
        } else if (present(&action, "httpForward").is_some() || present(&action, "httpOverrideForwardedRequest").is_some()) && let Some(forward) = crate::forward::Forward::compile(&action) {
            let _ = forward.execute(state, &trigger.request, &trigger.path).await;
        }
        // `httpObjectCallback`: only an in-process callback would run (`LocalCallbackRegistry`), and there is none.
    });
}

/// The webhook request a side action sends (input JSON form): its `httpRequestTemplate` rendered against the
/// triggering request (`renderWebhookTemplate`, with the forward templates' engines), else its `httpRequest` with
/// runtime expressions resolved; `None` when it sends no webhook. Steps have no template.
fn webhook_request(trigger: &Trigger, action: &Map<String, Value>, label: &str) -> Option<Result<Value, crate::templates::Failed>> {
    use crate::templates::{self, Role};
    let Some(template) = present(action, "httpRequestTemplate").filter(|_| label != "step") else {
        return present(action, "httpRequest").map(|webhook| Ok(resolve(webhook, &trigger.request, &trigger.path)));
    };
    if present(template.as_object()?, "templateType").is_none() {
        return Some(Err(templates::Failed::untyped(Role::Webhook)));
    }
    let template = templates::Template::compile(template);
    let state = &trigger.state;
    Some(crate::blocking::off_worker(|| templates::execute(state, &state.velocity_engines.forward, &template, &trigger.request, &trigger.path, None, Role::Webhook)))
}

/// `logWebhookTemplateFailure`: a WARN-typed entry at INFO about the triggering request, the failure's detail as its
/// argument and the engine's failure as its throwable.
fn log_not_sent(trigger: &Trigger, failed: &crate::templates::Failed, label: &str) {
    let state = &trigger.state;
    if !state.info_enabled() {
        return;
    }
    let logged = &failed.logged;
    let trace = logged.java_string();
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format!("{label} webhook not sent:{{}}"))
        .level(crate::recorded::Level::Info)
        .request(&trigger.request)
        .args([failed.detail.clone()])
        .throwable(&trace)
        .throwable_bean(logged.bean.clone());
    crate::log::entry_with_throwable(state, crate::recorded::Level::Info, &entry, Some(&trigger.request), &trace);
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(trigger.request.clone())));
}

/// `OpenApiRuntimeExpressionResolver.resolve`: the webhook (input JSON form) with its path, header values and body
/// expressions resolved; a path that becomes an absolute URL sets `Host` and `secure`.
pub fn resolve(webhook: &Value, trigger: &HttpRequest, path: &PathMatch) -> Value {
    let mut resolved = webhook.clone();
    let Some(o) = resolved.as_object_mut() else { return resolved };
    let expand = |s: &str| expressions(s, trigger, path);
    if let Some(p) = o.get("path").and_then(Value::as_str).filter(|p| p.contains("{$")) {
        let p = expand(p);
        o.insert("path".into(), p.into());
    }
    if let Some(headers) = o.get_mut("headers") {
        resolve_values(headers, &expand);
    }
    if let Some(text) = body_text(o.get("body")).filter(|b| b.contains("{$")) {
        o.insert("body".into(), expand(&text).into());
    }
    if let Some(url) = o.get("path").and_then(Value::as_str).filter(|p| p.starts_with("http://") || p.starts_with("https://")).map(str::to_string) {
        let secure = url.starts_with("https://");
        let rest = url.split_once("://").map_or("", |(_, r)| r);
        let (authority, path) = rest.find(['/', '?', '#']).map_or((rest, ""), |i| rest.split_at(i));
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        let path = path.split(['?', '#']).next().unwrap_or_default();
        // `URI.getPort()` is -1 when absent: only an explicit port is kept.
        let host = match authority.rsplit_once(':').filter(|(h, p)| !h.ends_with(']') || p.parse::<u16>().is_ok()) {
            Some((h, p)) if p.parse::<u16>().is_ok_and(|p| p > 0) => format!("{h}:{p}"),
            Some((h, _)) => h.to_string(),
            None => authority.to_string(),
        };
        o.insert("path".into(), if path.is_empty() { "/".into() } else { path.into() });
        set_host(o, host);
        o.insert("secure".into(), secure.into());
    }
    resolved
}

/// Header values in either multimap form, resolved in place.
fn resolve_values(headers: &mut Value, expand: &dyn Fn(&str) -> String) {
    let each = |v: &mut Value| match v {
        Value::String(s) if s.contains("{$") => *s = expand(s),
        Value::Array(values) => {
            for value in values {
                if let Value::String(s) = value && s.contains("{$") {
                    *s = expand(s);
                }
            }
        }
        _ => {}
    };
    match headers {
        Value::Object(map) => map.values_mut().for_each(each),
        Value::Array(list) => {
            for entry in list {
                if let Some(values) = entry.get_mut("values") {
                    each(values);
                }
            }
        }
        _ => {}
    }
}

/// `withHeader("Host", …)`: replaces any `Host` header.
fn set_host(o: &mut Map<String, Value>, host: String) {
    match o.get_mut("headers") {
        Some(Value::Object(map)) => {
            map.retain(|k, _| !k.eq_ignore_ascii_case("host"));
            map.insert("Host".into(), Value::Array(vec![host.into()]));
        }
        Some(Value::Array(list)) => {
            list.retain(|e| !e.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case("host")));
            list.push(serde_json::json!({"name": "Host", "values": [host]}));
        }
        _ => {
            o.insert("headers".into(), serde_json::json!({"Host": [host]}));
        }
    }
}

/// `getBodyAsString` of a body in input form.
fn body_text(body: Option<&Value>) -> Option<String> {
    match body? {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => match o.get("type").and_then(Value::as_str) {
            Some("STRING") | Some("XML") | Some("REGEX") => o.get("string").or_else(|| o.get("xml")).or_else(|| o.get("regex")).and_then(Value::as_str).map(str::to_string),
            Some("JSON") => o.get("json").map(|j| j.as_str().map_or_else(|| j.to_string(), str::to_string)),
            Some(_) => None,
            None => Some(Value::Object(o.clone()).to_string()),
        },
        other => Some(other.to_string()),
    }
}

/// `resolveExpressions`: every `{$…}` replaced; unknown expressions resolve to nothing.
fn expressions(template: &str, trigger: &HttpRequest, path: &PathMatch) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{$") {
        let Some(len) = rest[start + 2..].find('}').filter(|l| *l > 0) else { break };
        out.push_str(&rest[..start]);
        out.push_str(&expression(&rest[start + 2..start + 2 + len], trigger, path));
        rest = &rest[start + 3 + len..];
    }
    out.push_str(rest);
    out
}

fn expression(expression: &str, trigger: &HttpRequest, path: &PathMatch) -> String {
    if let Some(pointer) = expression.strip_prefix("request.body#") {
        let body = trigger.body_str();
        return match serde_json::from_str::<Value>(&body).ok().as_ref().and_then(|root| root.pointer(pointer)) {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
    }
    if let Some(name) = expression.strip_prefix("request.query.") {
        return crate::request::first(&trigger.query, name).unwrap_or_default().to_string();
    }
    if let Some(name) = expression.strip_prefix("request.header.") {
        return trigger.first_header(name).unwrap_or_default().to_string();
    }
    if let Some(name) = expression.strip_prefix("request.path.") {
        return path.parameters.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.first()).cloned().unwrap_or_default();
    }
    match expression {
        "request.method" => trigger.method.clone(),
        "url" => {
            let scheme = if trigger.secure { "https" } else { "http" };
            match trigger.first_header("host").filter(|h| !h.is_empty()) {
                Some(host) => format!("{scheme}://{host}{}", trigger.path),
                None => trigger.path.clone(),
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_expressions_against_the_triggering_request() {
        let trigger = HttpRequest {
            method: "POST".into(),
            path: "/orders".into(),
            body: bytes::Bytes::from_static(br#"{"id":42,"cb":"https://hooks.example:8443/cb/x","o":{"a":1}}"#),
            headers: vec![("Host".into(), vec!["localhost:1080".into()])],
            ..HttpRequest::default()
        };
        let path = PathMatch::default();
        let hook = json!({"path": "{$request.body#/cb}", "body": "{$request.body#/o} {$request.body#/missing}|{$url} {$response.x}"});
        let resolved = resolve(&hook, &trigger, &path);
        assert_eq!(resolved["path"], "/cb/x");
        assert_eq!(resolved["headers"], json!({"Host": ["hooks.example:8443"]}));
        assert_eq!(resolved["secure"], true);
        assert_eq!(resolved["body"], r#"{"a":1} |http://localhost:1080/orders "#);
    }

    #[test]
    fn validates_steps() {
        let invalid = |v: Value| validate_steps(v.as_object().unwrap());
        assert_eq!(invalid(json!({"steps": [{"httpResponse": {}, "responder": true}]})), None);
        assert_eq!(invalid(json!({"steps": [{"responder": true}]})).unwrap(), "step[0] has no action target set");
        assert!(invalid(json!({"steps": [{"httpResponse": {}, "httpError": {}, "responder": true}]})).unwrap().contains("multiple action targets"));
    }
}
