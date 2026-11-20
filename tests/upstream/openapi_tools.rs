//! mockserver-core's in-JVM unit tests of the classes behind the OpenAPI MCP tools, one to one, through the tools:
//! `OpenApiContractTestTest` (`run_contract_test`), `OpenApiResiliencyTestTest` (`run_resiliency_test`),
//! `OpenApiTrafficValidatorTest` (`verify_traffic_against_openapi`) and `McpToolSchemaGeneratorTest`
//! (`list_mock_tools`). Upstream's fake HTTP senders become a second in-process server answering as the fake
//! does; its recorded requests stand for what the fake captured. Tests of a sender that throws, or of a pair
//! without a request, cannot arise through a tool (the tools' sender turns every failure into a status-0
//! response); they are ported as the nearest reachable case, as each test says.

use serde_json::{Value, json};

use crate::common::{self, Transport};

fn resource(name: &str) -> String {
    let path = format!("{}/upstream/mockserver/mockserver/mockserver-core/src/test/resources/org/mockserver/openapi/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

fn petstore() -> String {
    resource("openapi_petstore_example.json")
}

/// A target service answering with `expectations`.
async fn service(expectations: &[Value]) -> common::Running {
    let server = common::start(&[]).await;
    for e in expectations {
        common::expect(server.port, e).await;
    }
    server
}

fn answer(method: Option<&str>, path: &str, status: u16, body: Option<&str>) -> Value {
    let mut request = json!({"path": path});
    if let Some(m) = method {
        request["method"] = json!(m);
    }
    let mut response = json!({"statusCode": status});
    if let Some(b) = body {
        response["headers"] = json!({"content-type": ["application/json"]});
        response["body"] = json!(b);
    }
    json!({"httpRequest": request, "httpResponse": response})
}

async fn tool(tool: &str, spec: &str, target: &common::Running, operation: Option<&str>) -> Value {
    let caller = common::start(&[]).await;
    let mut args = json!({"specUrlOrPayload": spec, "baseUrl": format!("http://127.0.0.1:{}", target.port)});
    if let Some(o) = operation {
        args["operationId"] = json!(o);
    }
    let result = caller.server.call_mcp_tool(tool, &args).await;
    caller.server.shutdown().await;
    result
}

/// The requests the target received.
async fn received(target: &common::Running) -> Vec<Value> {
    let body = common::send(target.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", "").await.body;
    serde_json::from_str::<Value>(&body).unwrap().as_array().cloned().unwrap_or_default()
}

fn results(report: &Value) -> Vec<Value> {
    report["results"].as_array().cloned().unwrap_or_else(|| panic!("{report}"))
}

const FIDO: &str = r#"{"id": 1, "name": "Fido"}"#;
const FIDOS: &str = r#"[{"id": 1, "name": "Fido"}]"#;

// ------------------------------------------------------------------ OpenApiContractTestTest

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_pass_when_responses_conform() {
    let target = service(&[
        answer(Some("GET"), "/pets", 200, Some(FIDOS)),
        answer(Some("POST"), "/pets", 201, None),
        answer(Some("GET"), "/pets/.+", 200, Some(FIDO)),
        answer(Some("GET"), "/some/path", 200, Some(FIDO)),
    ])
    .await;
    let report = tool("run_contract_test", &petstore(), &target, None).await;
    assert_eq!(results(&report).len(), 4, "{report}");
    for r in results(&report) {
        assert_eq!(r["passed"], true, "{r}");
    }
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_fail_when_response_does_not_conform() {
    let target = service(&[answer(Some("GET"), "/pets", 200, Some(r#"{"not": "an array"}"#)), answer(Some("POST"), "/pets", 201, None), answer(None, "/.*", 200, Some(FIDO))]).await;
    let report = tool("run_contract_test", &petstore(), &target, None).await;
    assert_eq!(results(&report).len(), 4);
    let list = results(&report).into_iter().find(|r| r["operationId"] == "listPets").expect("a listPets result");
    assert_eq!(list["passed"], false);
    assert!(!list["validationErrors"].as_array().unwrap().is_empty());
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_filter_by_operation_id() {
    let target = service(&[answer(None, "/.*", 200, Some(FIDOS))]).await;
    let report = tool("run_contract_test", &petstore(), &target, Some("listPets")).await;
    let r = results(&report);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["operationId"], "listPets");
    assert_eq!(r[0]["passed"], true, "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_build_example_request_with_path_parameters() {
    let target = service(&[answer(None, "/.*", 200, Some(FIDO))]).await;
    let report = tool("run_contract_test", &petstore(), &target, Some("showPetById")).await;
    assert_eq!(results(&report).len(), 1);
    let sent = received(&target).await;
    assert_eq!(sent.len(), 1);
    assert!(!sent[0]["path"].as_str().unwrap().contains('{'), "{}", sent[0]);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_build_example_request_with_request_body() {
    let target = service(&[answer(None, "/.*", 201, None)]).await;
    let report = tool("run_contract_test", &petstore(), &target, Some("createPets")).await;
    assert_eq!(results(&report).len(), 1);
    let sent = received(&target).await;
    assert!(sent[0].get("body").is_some_and(|b| !b.is_null() && b != ""), "{}", sent[0]);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_should_build_example_request_with_query_parameters() {
    let spec = json!({
        "openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"},
        "paths": {"/items": {"get": {"operationId": "listItems",
            "parameters": [{"name": "limit", "in": "query", "required": true, "schema": {"type": "integer", "default": 10}}],
            "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "array", "items": {"type": "string"}}}}}}}}}
    });
    let target = service(&[answer(None, "/.*", 200, Some(r#"["item1"]"#))]).await;
    let report = tool("run_contract_test", &spec.to_string(), &target, None).await;
    assert_eq!(results(&report).len(), 1);
    let sent = received(&target).await;
    assert!(sent[0].get("queryStringParameters").is_some(), "{}", sent[0]);
    target.server.shutdown().await;
}

/// `shouldHandleSenderException`: the tool's sender never throws; an unreachable target is its failure, reported
/// as a failed operation with status 0.
#[tokio::test(flavor = "multi_thread")]
async fn contract_should_handle_sender_exception() {
    let caller = common::start(&[]).await;
    let report = caller.server.call_mcp_tool("run_contract_test", &json!({"specUrlOrPayload": petstore(), "baseUrl": "http://127.0.0.1:1", "operationId": "listPets"})).await;
    let r = results(&report);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["passed"], false);
    assert_eq!(r[0]["statusCode"], 0);
    assert_eq!(r[0]["validationErrors"].as_array().unwrap().len(), 1, "{report}");
    caller.server.shutdown().await;
}

/// `shouldProduceMeaningfulErrorWhenSenderThrowsExceptionWithNullMessage`: as above; the error explains the
/// failed validation of the status-0 answer rather than a bare `null`.
#[tokio::test(flavor = "multi_thread")]
async fn contract_should_produce_meaningful_error_when_sender_throws_exception_with_null_message() {
    let caller = common::start(&[]).await;
    let report = caller.server.call_mcp_tool("run_contract_test", &json!({"specUrlOrPayload": petstore(), "baseUrl": "http://127.0.0.1:1", "operationId": "listPets"})).await;
    let error = results(&report)[0]["validationErrors"][0].as_str().unwrap().to_string();
    assert!(!error.is_empty() && !error.ends_with(": null"), "{error}");
    caller.server.shutdown().await;
}

// ------------------------------------------------------------------ OpenApiResiliencyTestTest

fn rich_spec() -> String {
    json!({
        "openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0"},
        "paths": {
            "/items": {"post": {"operationId": "createItem",
                "parameters": [{"name": "tenant", "in": "query", "required": true, "schema": {"type": "string", "default": "default-tenant"}}],
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name", "quantity"], "properties": {
                    "name": {"type": "string", "minLength": 3, "maxLength": 50},
                    "quantity": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "description": {"type": "string"},
                    "enabled": {"type": "boolean"}}}}}},
                "responses": {"201": {"description": "Created"}, "400": {"description": "Bad request"}}}},
            "/items/{itemId}": {"get": {"operationId": "getItem",
                "parameters": [{"name": "itemId", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}, "404": {"description": "Not found"}}}}
        }
    })
    .to_string()
}

fn no_body_spec() -> String {
    json!({"openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"}, "paths": {"/status": {"get": {"operationId": "getStatus", "responses": {"200": {"description": "OK"}}}}}}).to_string()
}

async fn resiliency(status: u16, operation: Option<&str>) -> Value {
    let target = service(&[answer(None, "/.*", status, None)]).await;
    let report = tool("run_resiliency_test", &rich_spec(), &target, operation).await;
    target.server.shutdown().await;
    report
}

fn of_type(report: &Value, kind: &str) -> Vec<Value> {
    results(report).into_iter().filter(|r| r["mutationType"] == kind).collect()
}

fn described(results: &[Value], text: &str) -> bool {
    results.iter().any(|r| r["mutationDescription"].as_str().unwrap().contains(text))
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_classify_4xx_as_handled() {
    let report = resiliency(400, Some("createItem")).await;
    assert!(!results(&report).is_empty());
    assert!(results(&report).iter().all(|r| r["classification"] == "HANDLED"), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_classify_422_as_handled() {
    let report = resiliency(422, Some("createItem")).await;
    assert!(results(&report).iter().all(|r| r["classification"] == "HANDLED"), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_classify_5xx_as_unexpected() {
    let report = resiliency(500, Some("createItem")).await;
    assert!(results(&report).iter().all(|r| r["classification"] == "UNEXPECTED"), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_classify_2xx_as_unexpected() {
    let report = resiliency(200, Some("createItem")).await;
    assert!(results(&report).iter().all(|r| r["classification"] == "UNEXPECTED"), "{report}");
}

/// `shouldClassifyConnectionErrorAsUnexpected`: an unreachable target (the tool's sender does not throw).
#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_classify_connection_error_as_unexpected() {
    let caller = common::start(&[]).await;
    let report = caller.server.call_mcp_tool("run_resiliency_test", &json!({"specUrlOrPayload": rich_spec(), "baseUrl": "http://127.0.0.1:1", "operationId": "createItem"})).await;
    assert!(!results(&report).is_empty());
    for r in results(&report) {
        assert_eq!(r["classification"], "UNEXPECTED");
        assert_eq!(r["statusCode"], 0);
    }
    caller.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_omit_required_query_param_mutation() {
    let found = of_type(&resiliency(400, Some("createItem")).await, "OMIT_REQUIRED_QUERY_PARAM");
    assert!(!found.is_empty());
    assert!(found.iter().all(|r| r["mutationDescription"].as_str().unwrap().contains("tenant")));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_omit_required_body_field_mutations() {
    let found = of_type(&resiliency(400, Some("createItem")).await, "OMIT_REQUIRED_BODY_FIELD");
    assert!(found.len() >= 2);
    assert!(described(&found, "'name'") && described(&found, "'quantity'"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_type_violation_mutations() {
    assert!(of_type(&resiliency(400, Some("createItem")).await, "TYPE_VIOLATION").len() >= 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_numeric_boundary_violations() {
    let found = of_type(&resiliency(400, Some("createItem")).await, "NUMERIC_BOUNDARY_VIOLATION");
    assert_eq!(found.len(), 2);
    assert!(described(&found, "minimum-1") && described(&found, "maximum+1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_string_length_boundary_violations() {
    let found = of_type(&resiliency(400, Some("createItem")).await, "STRING_LENGTH_BOUNDARY_VIOLATION");
    assert!(found.len() >= 2);
    assert!(described(&found, "minLength-1") && described(&found, "maxLength+1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_oversized_string_field_mutation() {
    assert!(described(&of_type(&resiliency(400, Some("createItem")).await, "OVERSIZED_STRING_FIELD"), "'description'"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_not_generate_oversized_string_for_fields_with_max_length() {
    assert!(!described(&of_type(&resiliency(400, Some("createItem")).await, "OVERSIZED_STRING_FIELD"), "'name'"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_malformed_json_body_mutation() {
    assert!(!of_type(&resiliency(400, Some("createItem")).await, "MALFORMED_JSON_BODY").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_generate_omit_path_param_mutation() {
    let found = of_type(&resiliency(400, Some("getItem")).await, "OMIT_REQUIRED_PATH_PARAM");
    assert!(!found.is_empty());
    assert!(found.iter().all(|r| r["mutationDescription"].as_str().unwrap().contains("itemId")));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_not_generate_body_mutations_when_no_request_body() {
    let target = service(&[answer(None, "/.*", 200, None)]).await;
    let report = tool("run_resiliency_test", &no_body_spec(), &target, None).await;
    assert_eq!(report["totalMutations"], 0, "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_produce_summary_counts() {
    // Alternating answers: 500 (unexpected), then 400 (handled), and so on.
    let target = service(&[json!({"httpRequest": {"path": "/.*"}, "httpResponses": [{"statusCode": 500}, {"statusCode": 400}], "responseMode": "SEQUENTIAL"})]).await;
    let report = tool("run_resiliency_test", &rich_spec(), &target, Some("createItem")).await;
    let (total, handled, unexpected) = (report["totalMutations"].as_i64().unwrap(), report["handled"].as_i64().unwrap(), report["unexpected"].as_i64().unwrap());
    assert!(total > 0 && handled + unexpected == total && handled > 0 && unexpected > 0, "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_produce_per_operation_summaries() {
    let report = resiliency(400, None).await;
    let summaries = report["operationSummaries"].as_array().unwrap();
    assert!(summaries.len() >= 2);
    let create = summaries.iter().find(|s| s["operationId"] == "createItem").expect("createItem");
    assert!(summaries.iter().any(|s| s["operationId"] == "getItem"));
    assert!(create["handled"].as_i64().unwrap() > 0);
    assert_eq!(create["unexpected"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_filter_by_operation_id() {
    assert!(results(&resiliency(400, Some("getItem")).await).iter().all(|r| r["operationId"] == "getItem"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resiliency_should_populate_all_result_fields() {
    let report = resiliency(400, Some("createItem")).await;
    assert!(!results(&report).is_empty());
    for r in results(&report) {
        for field in ["operationId", "method", "path", "mutationType", "mutationDescription", "classification"] {
            assert!(!r[field].is_null(), "{field} in {r}");
        }
    }
}

// ------------------------------------------------------------------ OpenApiTrafficValidatorTest

/// A request and its response: method, path, headers, body, status and response body.
type Pair<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], &'a str, u16, Option<&'a str>);

/// Each pair recorded by a server answering its request with its response, then the recorded traffic validated.
async fn validate(spec: &str, pairs: &[Pair<'_>]) -> Value {
    let server = common::start(&[]).await;
    for (method, path, headers, body, status, response) in pairs {
        common::expect(server.port, &json!({"httpRequest": {"method": method, "path": path}, "httpResponse": answer(None, "/", *status, *response)["httpResponse"], "times": {"remainingTimes": 1}})).await;
        common::exchange(server.port, Transport::Http, method, path, headers, body).await;
    }
    let report = server.server.call_mcp_tool("verify_traffic_against_openapi", &json!({"specUrlOrPayload": spec})).await;
    server.server.shutdown().await;
    report
}

fn errors(r: &Value, key: &str) -> usize {
    r.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

const JSON: &[(&str, &str)] = &[("content-type", "application/json")];

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_pass_for_conforming_get_request() {
    let report = validate(&petstore(), &[("GET", "/pets", &[], "", 200, Some(FIDOS))]).await;
    let r = &results(&report)[0];
    assert_eq!(r["passed"], true, "{report}");
    assert!(!r["matchedOperation"].is_null());
    assert_eq!((errors(r, "requestErrors"), errors(r, "responseErrors")), (0, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_pass_for_conforming_post_request() {
    let report = validate(&petstore(), &[("POST", "/pets", JSON, FIDO, 201, None)]).await;
    assert_eq!(results(&report)[0]["passed"], true, "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_fail_for_non_conforming_response_body() {
    let report = validate(&petstore(), &[("GET", "/pets", &[], "", 200, Some(r#"{"not": "an array"}"#))]).await;
    let r = &results(&report)[0];
    assert_eq!(r["passed"], false);
    assert!(errors(r, "responseErrors") > 0, "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_fail_for_non_conforming_request_body() {
    let report = validate(&petstore(), &[("POST", "/pets", JSON, r#"{"id": "not_a_number", "name": "Fido"}"#, 201, None)]).await;
    let r = &results(&report)[0];
    assert_eq!(r["passed"], false);
    assert!(errors(r, "requestErrors") > 0, "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_report_unmatched_operation() {
    let report = validate(&petstore(), &[("DELETE", "/unknown/path", &[], "", 200, None)]).await;
    let r = &results(&report)[0];
    assert_eq!(r["passed"], false);
    assert!(r["matchedOperation"].is_null());
    assert_eq!(errors(r, "requestErrors"), 1);
    assert!(r["requestErrors"][0].as_str().unwrap().contains("no matching operation"));
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_validate_multiple_pairs() {
    let report = validate(&petstore(), &[("GET", "/pets", &[], "", 200, Some(FIDOS)), ("GET", "/unknown", &[], "", 404, None)]).await;
    let r = results(&report);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0]["passed"], true, "{report}");
    assert_eq!(r[1]["passed"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_match_path_with_template_parameters() {
    let report = validate(&petstore(), &[("GET", "/pets/123", &[("X-Request-ID", "3fa85f64-5717-4562-b3fc-2c963f66afa6")], "", 200, Some(r#"{"id": 123, "name": "Rex"}"#))]).await;
    let r = &results(&report)[0];
    assert_eq!(r["passed"], true, "{report}");
    assert!(r["matchedOperation"].as_str().unwrap().contains("/pets/{petId}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_prefer_concrete_path_over_templated_path() {
    let report = validate(&resource("openapi_concrete_before_templated.yaml"), &[("GET", "/users/me", &[], "", 200, Some(r#"{"me": "value"}"#))]).await;
    let r = &results(&report)[0];
    assert!(r["matchedOperation"].as_str().unwrap().contains("/users/me"), "{report}");
    assert_eq!(r["passed"], true);
}

/// `shouldContinueBatchWhenOnePairThrows`: every recorded exchange has a request, so no pair throws through the
/// tool; a batch still validates every pair after a failing one.
#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_continue_batch_when_one_pair_throws() {
    let report = validate(&petstore(), &[("GET", "/nowhere", &[], "", 200, None), ("GET", "/pets", &[], "", 200, Some(FIDOS))]).await;
    let r = results(&report);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0]["passed"], false);
    assert!(errors(&r[0], "requestErrors") > 0);
    assert_eq!(r[1]["passed"], true, "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_not_npe_for_webhooks_only_spec() {
    let report = validate(&resource("openapi_31_webhooks_only.yaml"), &[("GET", "/pets", &[], "", 200, None)]).await;
    let r = results(&report);
    assert_eq!(r.len(), 1, "{report}");
    assert!(r[0]["matchedOperation"].is_null());
}

/// `shouldHandleEmptyPairsList`: nothing recorded is `no_traffic` through the tool.
#[tokio::test(flavor = "multi_thread")]
async fn traffic_should_handle_empty_pairs_list() {
    let report = validate(&petstore(), &[]).await;
    assert_eq!(report["status"], "no_traffic");
    assert_eq!(report["totalPairs"], 0);
}

// ------------------------------------------------------------------ McpToolSchemaGeneratorTest

async fn generated(expectations: &[Value]) -> Value {
    let server = service(expectations).await;
    let result = server.server.call_mcp_tool("list_mock_tools", &json!({})).await;
    server.server.shutdown().await;
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn generates_tool_from_response_expectation() {
    let result = generated(&[json!({"id": "getUsers", "httpRequest": {"method": "GET", "path": "/users", "queryStringParameters": {"page": ["1"]}}, "httpResponse": {"statusCode": 200, "body": "[]"}})]).await;
    assert_eq!(result["count"], 1);
    let tool = &result["tools"][0];
    assert_eq!(tool["name"], "get_users");
    assert_eq!(tool["description"], "Mock for GET /users");
    assert_eq!(tool["inputSchema"]["type"], "object");
    assert_eq!(tool["inputSchema"]["properties"]["page"]["type"], "string");
    assert_eq!(tool["_mockserver"], json!({"method": "GET", "path": "/users", "expectationId": "getUsers"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn exposes_request_body_in_input_schema() {
    let result = generated(&[json!({"httpRequest": {"method": "POST", "path": "/users", "body": "{}"}, "httpResponse": {"statusCode": 201}})]).await;
    assert!(result["tools"][0]["inputSchema"]["properties"]["body"].is_object(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sanitizes_and_deduplicates_tool_names() {
    let e = json!({"httpRequest": {"method": "GET", "path": "/users/{id}"}, "httpResponse": {"statusCode": 200}});
    let result = generated(&[e.clone(), e]).await;
    assert_eq!(result["tools"][0]["name"], "get_users_id");
    assert_eq!(result["tools"][1]["name"], "get_users_id_2");
}

#[tokio::test(flavor = "multi_thread")]
async fn skips_notted_method_matcher() {
    let result = generated(&[json!({"httpRequest": {"method": "!GET", "path": "/x"}, "httpResponse": {"statusCode": 200}})]).await;
    assert_eq!(result["count"], 0, "{result}");
}

/// `skipsExpectationWithoutResponseAction`: an expectation needs an action to be stored, so a forward stands
/// for "no response action".
#[tokio::test(flavor = "multi_thread")]
async fn skips_expectation_without_response_action() {
    let result = generated(&[json!({"httpRequest": {"path": "/x"}, "httpForward": {"host": "localhost", "port": 1}})]).await;
    assert_eq!(result["count"], 0, "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn omits_body_property_when_no_request_body() {
    let result = generated(&[json!({"httpRequest": {"method": "GET", "path": "/ping"}, "httpResponse": {"statusCode": 200}})]).await;
    assert!(result["tools"][0]["inputSchema"]["properties"].get("body").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn skips_notted_path_matcher() {
    let result = generated(&[json!({"httpRequest": {"method": "GET", "path": "!/x"}, "httpResponse": {"statusCode": 200}})]).await;
    assert_eq!(result["count"], 0, "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn deduplicated_name_stays_within_sixty_four_chars() {
    let e = json!({"httpRequest": {"method": "GET", "path": format!("/{}", "a".repeat(70))}, "httpResponse": {"statusCode": 200}});
    let result = generated(&[e.clone(), e]).await;
    let (a, b) = (result["tools"][0]["name"].as_str().unwrap(), result["tools"][1]["name"].as_str().unwrap());
    assert!(a.len() <= 64 && b.len() <= 64);
    assert_ne!(a, b);
}

/// `returnsEmptyForNullExpectations`: no expectations at all.
#[tokio::test(flavor = "multi_thread")]
async fn returns_empty_for_null_expectations() {
    assert_eq!(generated(&[]).await, json!({"tools": [], "count": 0}));
}
