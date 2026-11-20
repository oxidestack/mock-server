# MCP and LLM-analysis test coverage

Where each `@Test` of upstream's unit tests behind the MCP tools (mockserver-core and
mockserver-netty 8.0.0, in-JVM) is ported. They call the classes directly (`McpToolRegistry`, `AgentRunDiff`,
`OpenApiContractTest`, …), so none runs unmodified; each port is `tests/upstream/<file>::<fn>` and reaches the
same code through `Server::call_mcp_tool`, the MCP endpoint, `PUT /mockserver/llm/diffRuns` or, for
`AwsSigV4Signer`, `mock_server::aws_sigv4`. A port's doc comment says where a Java-only case (a fake sender
that throws, a `null` argument, an in-JVM `HttpState` that never logged) became its nearest reachable case.
`McpToolRegistryTest` lists only its tests of the fifteen tools added here. Oracle scenarios `w2_mcp_*` cover the
same tools on the wire.

## AgentRunAnalyzerTest (9)

| Test | Port |
|---|---|
| countsMatchingToolCalls | `llm_agent_runs.rs::counts_matching_tool_calls` |
| doesNotCountToolCallsForOtherNames | `llm_agent_runs.rs::does_not_count_tool_calls_for_other_names` |
| filtersToolCallsByArgumentsRegex | `llm_agent_runs.rs::filters_tool_calls_by_arguments_regex` |
| summarisesRunStructure | `llm_agent_runs.rs::summarises_run_structure` |
| picksRichestConversationAcrossSnapshots | `llm_agent_runs.rs::picks_richest_conversation_across_snapshots` |
| emptyWhenNothingDecodes | `llm_agent_runs.rs::empty_when_nothing_decodes` |
| buildsCorrelatedCallGraph | `llm_agent_runs.rs::builds_correlated_call_graph` |
| emptyCallGraphWhenNothingDecodes | `llm_agent_runs.rs::empty_call_graph_when_nothing_decodes` |
| toolResultsForReportsCorrelatedToolNames | `llm_agent_runs.rs::tool_results_for_reports_correlated_tool_names` |

## AgentRunDiffTest (8)

| Test | Port |
|---|---|
| surfacesChangedPromptMessage | `llm_agent_runs.rs::surfaces_changed_prompt_message` |
| identicalRunsReportNoPromptChange | `llm_agent_runs.rs::identical_runs_report_no_prompt_change` |
| surfacesAddedToolCall | `llm_agent_runs.rs::surfaces_added_tool_call` |
| surfacesRemovedToolCall | `llm_agent_runs.rs::surfaces_removed_tool_call` |
| computesTokenAndCostDeltaWhenBothSidesHaveTotals | `llm_agent_runs.rs::computes_token_and_cost_delta_when_both_sides_have_totals` |
| normalisationSuppressesCosmeticWhitespaceChange | `llm_agent_runs.rs::normalisation_suppresses_cosmetic_whitespace_change` |
| masksConfiguredBodyFieldInDiffOutputWhenRequestPreRedacted | `llm_agent_runs.rs::masks_configured_body_field_in_diff_output_when_request_pre_redacted` |
| handlesEmptyRunsGracefully | `llm_agent_runs.rs::handles_empty_runs_gracefully` |

## DriftDetectorTest (5)

| Test | Port |
|---|---|
| reportsNoDriftWhenLiveShapeMatchesRecorded | `llm_drift.rs::reports_no_drift_when_live_shape_matches_recorded` |
| reportsDriftWhenLiveHasNewField | `llm_drift.rs::reports_drift_when_live_has_new_field` |
| failsClosedOnTransportException | `llm_drift.rs::fails_closed_on_transport_exception` |
| failsClosedOnNon2xx | `llm_drift.rs::fails_closed_on_non2xx` |
| couldNotCheckWhenNoClientForProvider | `llm_drift.rs::could_not_check_when_no_client_for_provider` |

## StructuralShapeDiffTest (10)

| Test | Port |
|---|---|
| identicalShapesHaveNoDrift | `llm_drift.rs::identical_shapes_have_no_drift` |
| detectsAddedField | `llm_drift.rs::detects_added_field` |
| detectsRemovedField | `llm_drift.rs::detects_removed_field` |
| detectsTypeChange | `llm_drift.rs::detects_type_change` |
| walksNestedObjectsAndArrays | `llm_drift.rs::walks_nested_objects_and_arrays` |
| nullNodesTreatedAsEmptyShape | `llm_drift.rs::null_nodes_treated_as_empty_shape` |
| handlesTopLevelArrayRoot | `llm_drift.rs::handles_top_level_array_root` |
| detectsTypeChangeInArrayFirstElement | `llm_drift.rs::detects_type_change_in_array_first_element` |
| primitiveRootsOfSameTypeHaveNoDrift | `llm_drift.rs::primitive_roots_of_same_type_have_no_drift` |
| primitiveRootTypeChangeIsDrift | `llm_drift.rs::primitive_root_type_change_is_drift` |

## AwsSigV4SignerTest (11)

| Test | Port |
|---|---|
| signingKeyDerivationMatchesAwsPublishedVector | `aws_sigv4.rs::signing_key_derivation_matches_aws_published_vector` |
| fullSignatureIsStructurallyCorrectAndDeterministic | `aws_sigv4.rs::full_signature_is_structurally_correct_and_deterministic` |
| getVanillaSignatureMatchesAwsTestSuiteVector | `aws_sigv4.rs::get_vanilla_signature_matches_aws_test_suite_vector` |
| determinism_sameInputsProduceSameSignature | `aws_sigv4.rs::determinism_same_inputs_produce_same_signature` |
| differentBodyProducesDifferentSignature | `aws_sigv4.rs::different_body_produces_different_signature` |
| sessionTokenAddsSecurityTokenHeaderAndChangesSignedHeaders | `aws_sigv4.rs::session_token_adds_security_token_header_and_changes_signed_headers` |
| extraHeadersAreIncludedInSignature | `aws_sigv4.rs::extra_headers_are_included_in_signature` |
| uriEncodePathSegmentEncodesColonAndPreservesUnreserved | `aws_sigv4.rs::uri_encode_path_segment_encodes_colon_and_preserves_unreserved` |
| uriEncodePathPreservesSlashSeparators | `aws_sigv4.rs::uri_encode_path_preserves_slash_separators` |
| hexSha256OfEmptyPayloadMatchesKnownConstant | `aws_sigv4.rs::hex_sha256_of_empty_payload_matches_known_constant` |
| postWithJsonBodyProducesValidSignature | `aws_sigv4.rs::post_with_json_body_produces_valid_signature` |

## OpenApiContractTestTest (8)

| Test | Port |
|---|---|
| shouldPassWhenResponsesConform | `openapi_tools.rs::contract_should_pass_when_responses_conform` |
| shouldFailWhenResponseDoesNotConform | `openapi_tools.rs::contract_should_fail_when_response_does_not_conform` |
| shouldFilterByOperationId | `openapi_tools.rs::contract_should_filter_by_operation_id` |
| shouldBuildExampleRequestWithPathParameters | `openapi_tools.rs::contract_should_build_example_request_with_path_parameters` |
| shouldBuildExampleRequestWithRequestBody | `openapi_tools.rs::contract_should_build_example_request_with_request_body` |
| shouldBuildExampleRequestWithQueryParameters | `openapi_tools.rs::contract_should_build_example_request_with_query_parameters` |
| shouldHandleSenderException | `openapi_tools.rs::contract_should_handle_sender_exception` |
| shouldProduceMeaningfulErrorWhenSenderThrowsExceptionWithNullMessage | `openapi_tools.rs::contract_should_produce_meaningful_error_when_sender_throws_exception_with_null_message` |

## OpenApiResiliencyTestTest (19)

| Test | Port |
|---|---|
| shouldClassify4xxAsHandled | `openapi_tools.rs::resiliency_should_classify_4xx_as_handled` |
| shouldClassify422AsHandled | `openapi_tools.rs::resiliency_should_classify_422_as_handled` |
| shouldClassify5xxAsUnexpected | `openapi_tools.rs::resiliency_should_classify_5xx_as_unexpected` |
| shouldClassify2xxAsUnexpected | `openapi_tools.rs::resiliency_should_classify_2xx_as_unexpected` |
| shouldClassifyConnectionErrorAsUnexpected | `openapi_tools.rs::resiliency_should_classify_connection_error_as_unexpected` |
| shouldGenerateOmitRequiredQueryParamMutation | `openapi_tools.rs::resiliency_should_generate_omit_required_query_param_mutation` |
| shouldGenerateOmitRequiredBodyFieldMutations | `openapi_tools.rs::resiliency_should_generate_omit_required_body_field_mutations` |
| shouldGenerateTypeViolationMutations | `openapi_tools.rs::resiliency_should_generate_type_violation_mutations` |
| shouldGenerateNumericBoundaryViolations | `openapi_tools.rs::resiliency_should_generate_numeric_boundary_violations` |
| shouldGenerateStringLengthBoundaryViolations | `openapi_tools.rs::resiliency_should_generate_string_length_boundary_violations` |
| shouldGenerateOversizedStringFieldMutation | `openapi_tools.rs::resiliency_should_generate_oversized_string_field_mutation` |
| shouldNotGenerateOversizedStringForFieldsWithMaxLength | `openapi_tools.rs::resiliency_should_not_generate_oversized_string_for_fields_with_max_length` |
| shouldGenerateMalformedJsonBodyMutation | `openapi_tools.rs::resiliency_should_generate_malformed_json_body_mutation` |
| shouldGenerateOmitPathParamMutation | `openapi_tools.rs::resiliency_should_generate_omit_path_param_mutation` |
| shouldNotGenerateBodyMutationsWhenNoRequestBody | `openapi_tools.rs::resiliency_should_not_generate_body_mutations_when_no_request_body` |
| shouldProduceSummaryCounts | `openapi_tools.rs::resiliency_should_produce_summary_counts` |
| shouldProducePerOperationSummaries | `openapi_tools.rs::resiliency_should_produce_per_operation_summaries` |
| shouldFilterByOperationId | `openapi_tools.rs::resiliency_should_filter_by_operation_id` |
| shouldPopulateAllResultFields | `openapi_tools.rs::resiliency_should_populate_all_result_fields` |

## OpenApiTrafficValidatorTest (11)

| Test | Port |
|---|---|
| shouldPassForConformingGetRequest | `openapi_tools.rs::traffic_should_pass_for_conforming_get_request` |
| shouldPassForConformingPostRequest | `openapi_tools.rs::traffic_should_pass_for_conforming_post_request` |
| shouldFailForNonConformingResponseBody | `openapi_tools.rs::traffic_should_fail_for_non_conforming_response_body` |
| shouldFailForNonConformingRequestBody | `openapi_tools.rs::traffic_should_fail_for_non_conforming_request_body` |
| shouldReportUnmatchedOperation | `openapi_tools.rs::traffic_should_report_unmatched_operation` |
| shouldValidateMultiplePairs | `openapi_tools.rs::traffic_should_validate_multiple_pairs` |
| shouldMatchPathWithTemplateParameters | `openapi_tools.rs::traffic_should_match_path_with_template_parameters` |
| shouldPreferConcretePathOverTemplatedPath | `openapi_tools.rs::traffic_should_prefer_concrete_path_over_templated_path` |
| shouldContinueBatchWhenOnePairThrows | `openapi_tools.rs::traffic_should_continue_batch_when_one_pair_throws` |
| shouldNotNpeForWebhooksOnlySpec | `openapi_tools.rs::traffic_should_not_npe_for_webhooks_only_spec` |
| shouldHandleEmptyPairsList | `openapi_tools.rs::traffic_should_handle_empty_pairs_list` |

## McpToolSchemaGeneratorTest (9)

| Test | Port |
|---|---|
| generatesToolFromResponseExpectation | `openapi_tools.rs::generates_tool_from_response_expectation` |
| exposesRequestBodyInInputSchema | `openapi_tools.rs::exposes_request_body_in_input_schema` |
| sanitizesAndDeduplicatesToolNames | `openapi_tools.rs::sanitizes_and_deduplicates_tool_names` |
| skipsNottedMethodMatcher | `openapi_tools.rs::skips_notted_method_matcher` |
| skipsExpectationWithoutResponseAction | `openapi_tools.rs::skips_expectation_without_response_action` |
| omitsBodyPropertyWhenNoRequestBody | `openapi_tools.rs::omits_body_property_when_no_request_body` |
| skipsNottedPathMatcher | `openapi_tools.rs::skips_notted_path_matcher` |
| deduplicatedNameStaysWithinSixtyFourChars | `openapi_tools.rs::deduplicated_name_stays_within_sixty_four_chars` |
| returnsEmptyForNullExpectations | `openapi_tools.rs::returns_empty_for_null_expectations` |

## McpContractTestTest (18)

| Test | Port |
|---|---|
| conformantServerPassesAllCoreChecks | `mcp_contract.rs::conformant_server_passes_all_core_checks` |
| exercisesToolsCallWhenToolNameProvided | `mcp_contract.rs::exercises_tools_call_when_tool_name_provided` |
| usesSuppliedProtocolVersionWhenServerEchoesNone | `mcp_contract.rs::uses_supplied_protocol_version_when_server_echoes_none` |
| transportErrorOnInitializeReportsOnlyInitialize | `mcp_contract.rs::transport_error_on_initialize_reports_only_initialize` |
| initializeMissingServerInfoFails | `mcp_contract.rs::initialize_missing_server_info_fails` |
| toolsListWithMalformedToolFails | `mcp_contract.rs::tools_list_with_malformed_tool_fails` |
| unknownMethodWithWrongErrorCodeFails | `mcp_contract.rs::unknown_method_with_wrong_error_code_fails` |
| unknownMethodAcceptedWithoutErrorFails | `mcp_contract.rs::unknown_method_accepted_without_error_fails` |
| toolsListAcceptsInputSchemaWithoutTypeKeyword | `mcp_contract.rs::tools_list_accepts_input_schema_without_type_keyword` |
| toolsCallAcceptsOmittedIsError | `mcp_contract.rs::tools_call_accepts_omitted_is_error` |
| reportsNegotiated2025_06_18VersionAndValidatesNewCapabilityShapes | `mcp_contract.rs::reports_negotiated_2025_06_18_version_and_validates_new_capability_shapes` |
| resourceLinkMissingUriFails | `mcp_contract.rs::resource_link_missing_uri_fails` |
| nonObjectStructuredContentFails | `mcp_contract.rs::non_object_structured_content_fails` |
| failsNotificationCheckForTwoHundredWithResultBody | `mcp_contract.rs::fails_notification_check_for_two_hundred_with_result_body` |
| failsNotificationCheckForAcceptedWithBody | `mcp_contract.rs::fails_notification_check_for_accepted_with_body` |
| doesNotObjectToABodyOnTheNotificationRejectionPath | `mcp_contract.rs::does_not_object_to_a_body_on_the_notification_rejection_path` |
| failsNotificationCheckForTwoHundredWithNoBody | `mcp_contract.rs::fails_notification_check_for_two_hundred_with_no_body` |
| failsNotificationCheckForNoContentStatus | `mcp_contract.rs::fails_notification_check_for_no_content_status` |

## McpContractTestAgainstMockServerTest (8)

| Test | Port |
|---|---|
| shouldPassItsOwnMcpConformanceSuite | `mcp_contract.rs::should_pass_its_own_mcp_conformance_suite` |
| shouldNegotiateAnOlderProtocolVersionDuringConformanceRun | `mcp_contract.rs::should_negotiate_an_older_protocol_version_during_conformance_run` |
| shouldFallBackToLatestProtocolVersionForUnsupportedRevision | `mcp_contract.rs::should_fall_back_to_latest_protocol_version_for_unsupported_revision` |
| shouldReturnNotFoundForUnknownSession | `mcp_contract.rs::should_return_not_found_for_unknown_session` |
| shouldReturnNotFoundForTerminatedSession | `mcp_contract.rs::should_return_not_found_for_terminated_session` |
| shouldReturnBadRequestWhenSessionIdIsMissingOnNonInitialize | `mcp_contract.rs::should_return_bad_request_when_session_id_is_missing_on_non_initialize` |
| shouldTreatBlankSessionIdAsMissingRatherThanUnknown | `mcp_contract.rs::should_treat_blank_session_id_as_missing_rather_than_unknown` |
| shouldReturnAcceptedWithNoBodyForNotification | `mcp_contract.rs::should_return_accepted_with_no_body_for_notification` |

## LlmMcpToolsTest (53)

| Test | Port |
|---|---|
| shouldCreateLlmCompletionExpectation | `llm_mcp_tools.rs::should_create_llm_completion_expectation` |
| shouldCreateLlmCompletionWithToolCalls | `llm_mcp_tools.rs::should_create_llm_completion_with_tool_calls` |
| shouldCreateLlmCompletionWithToolCallsObjectArguments | `llm_mcp_tools.rs::should_create_llm_completion_with_tool_calls_object_arguments` |
| shouldCreateLlmCompletionWithOutputSchemaString | `llm_mcp_tools.rs::should_create_llm_completion_with_output_schema_string` |
| shouldCreateLlmCompletionWithOutputSchemaObject | `llm_mcp_tools.rs::should_create_llm_completion_with_output_schema_object` |
| shouldRejectNonStringNonObjectOutputSchema | `llm_mcp_tools.rs::should_reject_non_string_non_object_output_schema` |
| shouldParseQuotaFieldsInChaosProfile | `llm_mcp_tools.rs::should_parse_quota_fields_in_chaos_profile` |
| shouldCreateLlmCompletionWithUsage | `llm_mcp_tools.rs::should_create_llm_completion_with_usage` |
| shouldRejectUnknownProvider | `llm_mcp_tools.rs::should_reject_unknown_provider` |
| shouldAcceptGeminiProviderWithCodec | `llm_mcp_tools.rs::should_accept_gemini_provider_with_codec` |
| shouldRejectMissingProvider | `llm_mcp_tools.rs::should_reject_missing_provider` |
| shouldRejectMissingPath | `llm_mcp_tools.rs::should_reject_missing_path` |
| shouldRejectToolCallWithoutName | `llm_mcp_tools.rs::should_reject_tool_call_without_name` |
| shouldAcceptMalformedJsonStringArguments | `llm_mcp_tools.rs::should_accept_malformed_json_string_arguments` |
| shouldRejectNonStringNonObjectArguments | `llm_mcp_tools.rs::should_reject_non_string_non_object_arguments` |
| shouldAcceptValidJsonStringArguments | `llm_mcp_tools.rs::should_accept_valid_json_string_arguments` |
| shouldAcceptPlainTextStringArguments | `llm_mcp_tools.rs::should_accept_plain_text_string_arguments` |
| shouldCreateLlmConversationWithTwoTurns | `llm_mcp_tools.rs::should_create_llm_conversation_with_two_turns` |
| shouldCreateLlmConversationWithIsolation | `llm_mcp_tools.rs::should_create_llm_conversation_with_isolation` |
| shouldRejectConversationWithUnknownProvider | `llm_mcp_tools.rs::should_reject_conversation_with_unknown_provider` |
| shouldAcceptGeminiConversationWithCodec | `llm_mcp_tools.rs::should_accept_gemini_conversation_with_codec` |
| shouldRejectConversationWithEmptyTurns | `llm_mcp_tools.rs::should_reject_conversation_with_empty_turns` |
| shouldRejectConversationWithInvalidIsolateBySource | `llm_mcp_tools.rs::should_reject_conversation_with_invalid_isolate_by_source` |
| shouldCreateConversationWithThreeTurns | `llm_mcp_tools.rs::should_create_conversation_with_three_turns` |
| shouldVerifyToolCallWasMade | `llm_mcp_tools.rs::should_verify_tool_call_was_made` |
| shouldNotVerifyToolCallThatWasNotMade | `llm_mcp_tools.rs::should_not_verify_tool_call_that_was_not_made` |
| shouldFilterVerifyToolCallByArgumentsRegex | `llm_mcp_tools.rs::should_filter_verify_tool_call_by_arguments_regex` |
| shouldErrorWhenVerifyToolCallMissingToolName | `llm_mcp_tools.rs::should_error_when_verify_tool_call_missing_tool_name` |
| shouldExplainAgentRun | `llm_mcp_tools.rs::should_explain_agent_run` |
| shouldExplainAgentRunWithNoRecordedConversation | `llm_mcp_tools.rs::should_explain_agent_run_with_no_recorded_conversation` |
| shouldScopeExplainAgentRunToSessionByIsolationHeader | `llm_mcp_tools.rs::should_scope_explain_agent_run_to_session_by_isolation_header` |
| shouldAutoDetectProviderForVerifyToolCall | `llm_mcp_tools.rs::should_auto_detect_provider_for_verify_tool_call` |
| shouldAutoDetectProviderForExplainAgentRun | `llm_mcp_tools.rs::should_auto_detect_provider_for_explain_agent_run` |
| shouldErrorWhenAutoDetectFailsWithNoRecordedRequests | `llm_mcp_tools.rs::should_error_when_auto_detect_fails_with_no_recorded_requests` |
| shouldErrorWhenAutoDetectFailsForExplainAgentRun | `llm_mcp_tools.rs::should_error_when_auto_detect_fails_for_explain_agent_run` |
| shouldCreateLlmCompletionWithChaosProfile | `llm_mcp_tools.rs::should_create_llm_completion_with_chaos_profile` |
| shouldLoadFixturesInStrictMode | `llm_mcp_tools.rs::should_load_fixtures_in_strict_mode` |
| shouldLoadFixturesWithRequestBodyNormalization | `llm_mcp_tools.rs::should_load_fixtures_with_request_body_normalization` |
| shouldMockAdversarialLlmResponse | `llm_mcp_tools.rs::should_mock_adversarial_llm_response` |
| shouldErrorWhenAdversarialPayloadMissing | `llm_mcp_tools.rs::should_error_when_adversarial_payload_missing` |
| shouldErrorOnUnknownAdversarialPayload | `llm_mcp_tools.rs::should_error_on_unknown_adversarial_payload` |
| shouldErrorWhenDetectDriftMissingCassette | `llm_mcp_tools.rs::should_error_when_detect_drift_missing_cassette` |
| shouldErrorWhenDetectDriftCassetteFileMissing | `llm_mcp_tools.rs::should_error_when_detect_drift_cassette_file_missing` |
| shouldCreateLlmConversationWithPerTurnChaos | `llm_mcp_tools.rs::should_create_llm_conversation_with_per_turn_chaos` |
| shouldCreateLlmFailoverScenario | `llm_mcp_tools.rs::should_create_llm_failover_scenario` |
| shouldCreateLlmFailoverWithMixedStatuses | `llm_mcp_tools.rs::should_create_llm_failover_with_mixed_statuses` |
| shouldVerifyFailoverExpectationsAreRegistered | `llm_mcp_tools.rs::should_verify_failover_expectations_are_registered` |
| shouldCreateLlmFailoverWithToolCalls | `llm_mcp_tools.rs::should_create_llm_failover_with_tool_calls` |
| shouldRejectFailoverWithUnknownProvider | `llm_mcp_tools.rs::should_reject_failover_with_unknown_provider` |
| shouldRejectFailoverWithMissingProvider | `llm_mcp_tools.rs::should_reject_failover_with_missing_provider` |
| shouldRejectFailoverWithMissingPath | `llm_mcp_tools.rs::should_reject_failover_with_missing_path` |
| shouldRejectFailoverWithEmptyFailStatuses | `llm_mcp_tools.rs::should_reject_failover_with_empty_fail_statuses` |
| shouldRejectFailoverWithNonIntegerStatus | `llm_mcp_tools.rs::should_reject_failover_with_non_integer_status` |

## McpToolRegistryTest (38)

| Test | Port |
|---|---|
| shouldRegisterAllTools | `mcp_registry.rs::should_register_all_tools` |
| shouldVerifyTrafficAgainstOpenApiToolHasSchema | `mcp_registry.rs::should_verify_traffic_against_open_api_tool_has_schema` |
| shouldRejectBlankSpecForVerifyTraffic | `mcp_registry.rs::should_reject_blank_spec_for_verify_traffic` |
| shouldReturnNoTrafficWhenNoneExists | `mcp_registry.rs::should_return_no_traffic_when_none_exists` |
| shouldRunContractTestToolHasSchema | `mcp_registry.rs::should_run_contract_test_tool_has_schema` |
| shouldRejectBlankSpecForContractTest | `mcp_registry.rs::should_reject_blank_spec_for_contract_test` |
| shouldRejectBlankBaseUrlForContractTest | `mcp_registry.rs::should_reject_blank_base_url_for_contract_test` |
| shouldRejectInvalidBaseUrlForContractTest | `mcp_registry.rs::should_reject_invalid_base_url_for_contract_test` |
| shouldRunResiliencyTestToolHasSchema | `mcp_registry.rs::should_run_resiliency_test_tool_has_schema` |
| shouldRejectBlankSpecForResiliencyTest | `mcp_registry.rs::should_reject_blank_spec_for_resiliency_test` |
| shouldRejectBlankBaseUrlForResiliencyTest | `mcp_registry.rs::should_reject_blank_base_url_for_resiliency_test` |
| shouldRejectInvalidBaseUrlForResiliencyTest | `mcp_registry.rs::should_reject_invalid_base_url_for_resiliency_test` |
| shouldRejectBaseUrlWithNoHostForContractTest | `mcp_registry.rs::should_reject_base_url_with_no_host_for_contract_test` |
| shouldRejectBaseUrlWithNoHostForResiliencyTest | `mcp_registry.rs::should_reject_base_url_with_no_host_for_resiliency_test` |
| shouldRejectNonHttpSchemeForContractTest | `mcp_registry.rs::should_reject_non_http_scheme_for_contract_test` |
| shouldRejectNonHttpSchemeForResiliencyTest | `mcp_registry.rs::should_reject_non_http_scheme_for_resiliency_test` |
| shouldRunMcpContractTestToolHasSchema | `mcp_registry.rs::should_run_mcp_contract_test_tool_has_schema` |
| shouldRejectBlankTargetUrlForMcpContractTest | `mcp_registry.rs::should_reject_blank_target_url_for_mcp_contract_test` |
| shouldRejectTargetUrlWithNoHostForMcpContractTest | `mcp_registry.rs::should_reject_target_url_with_no_host_for_mcp_contract_test` |
| shouldRejectNonHttpSchemeForMcpContractTest | `mcp_registry.rs::should_reject_non_http_scheme_for_mcp_contract_test` |
| shouldVerifyStructuredOutputToolHasSchema | `mcp_registry.rs::should_verify_structured_output_tool_has_schema` |
| shouldRejectMissingProviderForVerifyStructuredOutput | `mcp_registry.rs::should_reject_missing_provider_for_verify_structured_output` |
| shouldRejectBlankSchemaForVerifyStructuredOutput | `mcp_registry.rs::should_reject_blank_schema_for_verify_structured_output` |
| shouldReturnZeroCheckedWhenNoRecordedResponses | `mcp_registry.rs::should_return_zero_checked_when_no_recorded_responses` |
| shouldReportConformingStructuredOutput | `mcp_registry.rs::should_report_conforming_structured_output` |
| shouldFlagNonConformingStructuredOutput | `mcp_registry.rs::should_flag_non_conforming_structured_output` |
| shouldRejectMissingMaxCostForVerifyCostBudget | `mcp_registry.rs::should_reject_missing_max_cost_for_verify_cost_budget` |
| shouldRejectNegativeMaxCostForVerifyCostBudget | `mcp_registry.rs::should_reject_negative_max_cost_for_verify_cost_budget` |
| shouldReportZeroCostWhenNoRecordedResponses | `mcp_registry.rs::should_report_zero_cost_when_no_recorded_responses` |
| shouldPassWhenCostWithinBudget | `mcp_registry.rs::should_pass_when_cost_within_budget` |
| shouldSumCostAcrossMultipleResponses | `mcp_registry.rs::should_sum_cost_across_multiple_responses` |
| shouldReportPartialTotalAndNonAuthoritativeForMixedPriceability | `mcp_registry.rs::should_report_partial_total_and_non_authoritative_for_mixed_priceability` |
| shouldFailWhenCostExceedsBudget | `mcp_registry.rs::should_fail_when_cost_exceeds_budget` |
| shouldReportUnpriceableWhenModelUnknown | `mcp_registry.rs::should_report_unpriceable_when_model_unknown` |
| shouldNotBeAuthoritativeWhenNoResponses | `mcp_registry.rs::should_not_be_authoritative_when_no_responses` |
| shouldGenerateMcpToolsFromMockExpectations | `mcp_registry.rs::should_generate_mcp_tools_from_mock_expectations` |
| shouldClassifyStateMutatingToolsAsMutating | `mcp_registry.rs::should_classify_state_mutating_tools_as_mutating` |
| shouldClassifyReadOnlyToolsAsNonMutating | `mcp_registry.rs::should_classify_read_only_tools_as_non_mutating` |
