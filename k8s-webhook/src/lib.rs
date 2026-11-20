//! MockServer's Kubernetes `MutatingAdmissionWebhook` (upstream module `mockserver-k8s-webhook`, image
//! `mockserver/mockserver-webhook`): for a pod CREATE in a labelled namespace whose pod carries
//! `mockserver.org/inject: "true"`, it answers with a JSON Patch that adds an iptables-REDIRECT init container and a
//! MockServer transparent-proxy sidecar. A standalone binary, as upstream's is; the Helm chart deploys it when
//! `webhook.enabled=true`.

pub mod admission;
pub mod cbc;
pub mod config;
pub mod dsa;
pub mod java;
pub mod log;
pub mod patch;
pub mod server;
pub mod tls;
pub mod tls13;

pub use admission::AdmissionReviewHandler;
pub use config::SidecarInjectionConfig;
pub use patch::SidecarPatchBuilder;
pub use server::WebhookServer;
