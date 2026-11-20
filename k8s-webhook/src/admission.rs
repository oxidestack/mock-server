//! `AdmissionReviewHandler`: an `admission.k8s.io/v1` `AdmissionReview` in, the review with its response out, the
//! patch base64-encoded when the pod opts in. Stateless.

use crate::config::SidecarInjectionConfig;
use crate::java::JavaException;
use crate::log;
use crate::patch::SidecarPatchBuilder;
use base64::Engine;
use jackson::{JsonNode, ObjectNode};

const CLASS: &str = "org.mockserver.webhook.AdmissionReviewHandler";
const ADMISSION_API_VERSION: &str = "admission.k8s.io/v1";
const ADMISSION_KIND: &str = "AdmissionReview";
const PATCH_TYPE: &str = "JSONPatch";

pub struct AdmissionReviewHandler {
    patch_builder: SidecarPatchBuilder,
}

impl AdmissionReviewHandler {
    pub fn new(config: SidecarInjectionConfig) -> AdmissionReviewHandler {
        AdmissionReviewHandler { patch_builder: SidecarPatchBuilder::new(config) }
    }

    /// `handleAdmissionReview(byte[])`: `ObjectMapper.readTree(byte[])` (UTF-8, UTF-16 or UTF-32 as Jackson detects
    /// it, invalid UTF-8 reported as `UTF8StreamJsonParser` reports it), then the tree overload.
    pub fn handle_admission_review_bytes(&self, body: &[u8]) -> Result<Vec<u8>, JavaException> {
        let request = jackson::json::read_tree_bytes(body, jackson::json::ReadFeatures { tree_member_values: true, ..Default::default() })?;
        self.handle_admission_review(&request)
    }

    /// `handleAdmissionReview(JsonNode)`
    pub fn handle_admission_review(&self, request: &JsonNode) -> Result<Vec<u8>, JavaException> {
        let review_request = request.path("request");
        let uid = review_request.path("uid").as_text_or("");
        log::info(CLASS, "handleAdmissionReview", &format!("processing admission review, uid={uid}"));

        let mut admission_response = ObjectNode::new();
        admission_response.insert("uid".to_string(), JsonNode::text(uid.as_str()));
        admission_response.insert("allowed".to_string(), JsonNode::Boolean(true));

        let pod = review_request.path("object");
        if self.patch_builder.should_inject(Some(&pod)) {
            let patch = self.patch_builder.build_patch(&pod)?;
            let patch_json = jackson::convert::node_to_json_string(&patch, false, false);
            let patch_base64 = base64::engine::general_purpose::STANDARD.encode(patch_json.as_bytes());
            admission_response.insert("patchType".to_string(), JsonNode::text(PATCH_TYPE));
            admission_response.insert("patch".to_string(), JsonNode::text(patch_base64));
            log::info(CLASS, "handleAdmissionReview", &format!("injection patch applied for uid={uid}"));
        } else {
            log::info(CLASS, "handleAdmissionReview", &format!("no injection needed for uid={uid}"));
        }
        Ok(review(admission_response))
    }

    /// `createAllowResponse(String)`: allowed, no patch.
    pub fn create_allow_response(&self, uid: &str) -> Vec<u8> {
        let mut admission_response = ObjectNode::new();
        admission_response.insert("uid".to_string(), JsonNode::text(uid));
        admission_response.insert("allowed".to_string(), JsonNode::Boolean(true));
        review(admission_response)
    }

    /// `createAllowWithMessage(String, String)`: allowed, with `status.message` saying why nothing was mutated.
    pub fn create_allow_with_message(&self, uid: &str, message: &str) -> Vec<u8> {
        let mut admission_response = ObjectNode::new();
        admission_response.insert("uid".to_string(), JsonNode::text(uid));
        admission_response.insert("allowed".to_string(), JsonNode::Boolean(true));
        let mut status = ObjectNode::new();
        status.insert("message".to_string(), JsonNode::text(message));
        admission_response.insert("status".to_string(), JsonNode::object(status));
        review(admission_response)
    }
}

fn review(admission_response: ObjectNode) -> Vec<u8> {
    let mut response = ObjectNode::new();
    response.insert("apiVersion".to_string(), JsonNode::text(ADMISSION_API_VERSION));
    response.insert("kind".to_string(), JsonNode::text(ADMISSION_KIND));
    response.insert("response".to_string(), JsonNode::object(admission_response));
    utf8_generator_text(&jackson::convert::node_to_json_string(&JsonNode::object(response), false, false)).into_bytes()
}

/// `writeValueAsBytes` writes through `UTF8JsonGenerator`, which (without
/// `JsonWriteFeature.COMBINE_UNICODE_SURROGATES_IN_UTF8`) escapes a supplementary character as its two surrogates,
/// `\uD83D\uDE00`; the text writer this crate shares leaves it raw.
fn utf8_generator_text(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if (c as u32) > 0xFFFF {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}
