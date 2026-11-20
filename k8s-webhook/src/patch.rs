//! `SidecarPatchBuilder`: decides whether a pod opts in, and builds the RFC 6902 JSON Patch that adds the
//! iptables-REDIRECT init container, the MockServer sidecar and the idempotency annotations.

use crate::config::{self, SidecarInjectionConfig};
use crate::java::{JavaException, equals_ignore_case, parse_int, trim};
use crate::log;
use jackson::{JsonNode, ObjectNode};

const CLASS: &str = "org.mockserver.webhook.SidecarPatchBuilder";

pub struct SidecarPatchBuilder {
    config: SidecarInjectionConfig,
}

impl SidecarPatchBuilder {
    pub fn new(config: SidecarInjectionConfig) -> SidecarPatchBuilder {
        SidecarPatchBuilder { config }
    }

    /// `shouldInject(JsonNode)`: the pod (`None` is Java's `null`) carries `mockserver.org/inject: true` (any case)
    /// and no `mockserver.org/injected: true`. Non-text annotation values compare by `asText`.
    pub fn should_inject(&self, pod: Option<&JsonNode>) -> bool {
        let Some(pod) = pod else {
            return false;
        };
        let annotations = pod.path("metadata").path("annotations");
        let Some(inject) = annotations.get(config::INJECT_ANNOTATION) else {
            return false;
        };
        if !equals_ignore_case(config::INJECT_ENABLED, &inject.as_text_or("")) {
            return false;
        }
        if let Some(injected) = annotations.get(config::INJECTED_ANNOTATION) && equals_ignore_case(config::INJECTED_VALUE, &injected.as_text_or("")) {
            return false;
        }
        true
    }

    /// `buildPatch(JsonNode)`: the patch as an `ArrayNode`. Fails (`IllegalArgumentException`) on a redirect port
    /// that is not a number in 1-65535.
    pub fn build_patch(&self, pod: &JsonNode) -> Result<JsonNode, JavaException> {
        let mut patch = Vec::new();
        let metadata = pod.get("metadata");
        let has_annotations = metadata.and_then(|m| m.get("annotations")).is_some_and(|a| a.size() > 0);
        let spec = pod.get("spec");
        let non_empty_array = |field: &str| spec.and_then(|s| s.get(field)).is_some_and(|v| v.is_array() && v.size() > 0);
        let has_init_containers = non_empty_array("initContainers");
        let has_containers = non_empty_array("containers");

        if has_annotations {
            patch.push(add_op(
                format!("/metadata/annotations/{}", escape_json_pointer(config::INJECTED_ANNOTATION)),
                text(config::INJECTED_VALUE),
            ));
            patch.push(add_op(format!("/metadata/annotations/{}", escape_json_pointer(config::STATUS_ANNOTATION)), text("injected")));
        } else {
            let annotations = object([(config::INJECTED_ANNOTATION, text(config::INJECTED_VALUE)), (config::STATUS_ANNOTATION, text("injected"))]);
            patch.push(add_op("/metadata/annotations".to_string(), annotations));
        }

        let init_container = self.build_iptables_init_container()?;
        if has_init_containers {
            patch.push(add_op("/spec/initContainers/-".to_string(), init_container));
        } else {
            patch.push(add_op("/spec/initContainers".to_string(), JsonNode::array(vec![init_container])));
        }

        let sidecar = self.build_sidecar_container();
        if has_containers {
            patch.push(add_op("/spec/containers/-".to_string(), sidecar));
        } else {
            patch.push(add_op("/spec/containers".to_string(), JsonNode::array(vec![sidecar])));
        }

        log::info(CLASS, "buildPatch", &format!("built injection patch with {} operations", patch.len()));
        Ok(JsonNode::array(patch))
    }

    /// `buildIptablesInitContainer()`: root with NET_ADMIN and NET_RAW; the script excludes the sidecar's UID from
    /// the REDIRECT (loop avoidance) before redirecting each configured port.
    pub fn build_iptables_init_container(&self) -> Result<JsonNode, JavaException> {
        let c = &self.config;
        let mut script = String::new();
        script.push_str("set -e\n");
        script.push_str("apk add --no-cache iptables > /dev/null 2>&1 || true\n");
        script.push_str(&format!("iptables -t nat -I OUTPUT -m owner --uid-owner {} -j RETURN\n", c.run_as_user));
        for port in c.redirect_ports.split(',') {
            let trimmed = trim(port);
            if !trimmed.is_empty() {
                validate_port(trimmed)?;
                script.push_str(&format!("iptables -t nat -A OUTPUT -p tcp --dport {trimmed} -j REDIRECT --to-ports {}\n", c.server_port));
            }
        }
        script.push_str(&format!(
            "echo \"iptables REDIRECT rules applied for ports {} -> {} (excludeUid={})\"\n",
            c.redirect_ports, c.server_port, c.run_as_user
        ));
        Ok(object([
            ("name", text("mockserver-iptables-init")),
            ("image", text(&c.iptables_image)),
            (
                "securityContext",
                object([
                    ("runAsUser", JsonNode::Int(0)),
                    ("runAsNonRoot", JsonNode::Boolean(false)),
                    ("capabilities", object([("add", texts(&["NET_ADMIN", "NET_RAW"]))])),
                ]),
            ),
            ("command", JsonNode::array(vec![text("sh"), text("-c"), text(&script)])),
        ]))
    }

    /// `buildSidecarContainer()`: MockServer as a transparent proxy, running as the excluded UID.
    pub fn build_sidecar_container(&self) -> JsonNode {
        let c = &self.config;
        let probe = |initial_delay: i32, period: i32| {
            object([
                ("httpGet", object([("path", text("/liveness/probe")), ("port", JsonNode::Int(c.server_port))])),
                ("initialDelaySeconds", JsonNode::Int(initial_delay)),
                ("periodSeconds", JsonNode::Int(period)),
                ("successThreshold", JsonNode::Int(1)),
                ("failureThreshold", JsonNode::Int(10)),
            ])
        };
        object([
            ("name", text("mockserver-sidecar")),
            ("image", text(&c.mockserver_image)),
            ("imagePullPolicy", text("IfNotPresent")),
            (
                "ports",
                JsonNode::array(vec![object([
                    ("name", text("mockserver")),
                    ("containerPort", JsonNode::Int(c.server_port)),
                    ("protocol", text("TCP")),
                ])]),
            ),
            (
                "env",
                JsonNode::array(vec![
                    env_var("MOCKSERVER_TRANSPARENT_PROXY_ENABLED", "true"),
                    env_var("MOCKSERVER_LOG_LEVEL", &c.log_level),
                    env_var("SERVER_PORT", &c.server_port.to_string()),
                    env_var("MOCKSERVER_LIVENESS_HTTP_GET_PATH", "/liveness/probe"),
                ]),
            ),
            (
                "securityContext",
                object([
                    ("runAsUser", JsonNode::Int(c.run_as_user)),
                    ("readOnlyRootFilesystem", JsonNode::Boolean(false)),
                    ("allowPrivilegeEscalation", JsonNode::Boolean(false)),
                    ("capabilities", object([("add", texts(&["NET_ADMIN"]))])),
                ]),
            ),
            ("readinessProbe", probe(2, 2)),
            ("livenessProbe", probe(10, 5)),
        ])
    }
}

/// `validatePort(String)`: `Integer.parseInt` in 1-65535.
pub fn validate_port(port: &str) -> Result<(), JavaException> {
    match parse_int(port) {
        Ok(n) if (1..=65535).contains(&n) => Ok(()),
        Ok(_) => Err(JavaException::illegal_argument(format!("redirect port out of range (1-65535): {port}"))),
        Err(e) => Err(JavaException::illegal_argument(format!("redirect port is not numeric: '{port}'")).with_cause(e)),
    }
}

/// `escapeJsonPointer(String)` (RFC 6901): `~` to `~0`, `/` to `~1`.
pub fn escape_json_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn text(s: &str) -> JsonNode {
    JsonNode::text(s)
}

fn texts(items: &[&str]) -> JsonNode {
    JsonNode::array(items.iter().map(|s| text(s)).collect())
}

fn object<const N: usize>(fields: [(&str, JsonNode); N]) -> JsonNode {
    let mut map = ObjectNode::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v);
    }
    JsonNode::object(map)
}

fn add_op(path: String, value: JsonNode) -> JsonNode {
    object([("op", text("add")), ("path", JsonNode::text(path)), ("value", value)])
}

fn env_var(name: &str, value: &str) -> JsonNode {
    object([("name", text(name)), ("value", text(value))])
}
