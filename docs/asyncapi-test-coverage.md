# AsyncAPI test coverage

Where each `@Test` of upstream's `mockserver-async` tests (MockServer 8.0.0) is checked in mock-server: 49 classes, 421 tests. "Port" means `tests/upstream/<file>.rs::<fn>` (one Rust test per upstream test, named after it in snake_case); the few upstream tests with no Rust counterpart say "not portable" and why. The in-JVM unit tests hand the adapters Mockito mocks of the broker clients, so none of them runs unmodified; each section says what stands in for the mocks.

| Class | Tests |
|---|---|
| AsyncApiParserTest | 38 |
| AmqpBindingParserTest | 6 |
| MessageExampleGeneratorTest | 11 |
| MessageExampleGeneratorSchemaAwareTest | 11 |
| AsyncApiSchemaValidatorTest | 10 |
| AsyncApiFirstMessageExampleValidationTest | 13 |
| AsyncApiControlPlaneImplTest | 16 |
| AsyncApiControlPlaneVerifyTest | 28 |
| AsyncApiControlPlaneSecurityTest | 15 |
| AsyncApiControlPlaneParityConfigTest | 8 |
| AsyncApiControlPlaneConfigurationInstanceTest | 7 |
| AsyncApiHttpExpectationGeneratorTest | 7 |
| AsyncApiMockOrchestratorTest | 19 |
| PublishOptionsTest | 20 |
| AmqpMessagePublisherTest | 18 |
| KafkaAvroMessagePublisherTest | 5 |
| KafkaMessagePublisherDeliveryFailureTest | 4 |
| KafkaMessagePublisherKeyHeadersTest | 12 |
| KafkaMessagePublisherTest | 2 |
| Mqtt5MessagePublisherTest | 6 |
| MqttMessagePublisherQosTest | 12 |
| MqttMessagePublisherTest | 3 |
| AmqpMessageSubscriberTest | 6 |
| KafkaMessageSubscriberTest | 9 |
| KafkaMessageSubscriberSecurityTest | 4 |
| Mqtt5MessageSubscriberTest | 5 |
| MqttMessageSubscriberTest | 7 |
| MqttWildcardSubscriptionTest | 5 |
| MqttTopicFilterTest | 15 |
| BoundedMessageStoreTest | 9 |
| KafkaAvroSchemaIdMismatchTest | 3 |
| KafkaSecurityPropertiesTest | 10 |
| MqttSecurityOptionsTest | 13 |
| Mqtt5SecurityOptionsTest | 5 |
| KafkaMessagePublisherSecurityTest | 4 |
| ConfluentWireFormatTest | 7 |
| AvroPayloadCodecTest | 4 |
| SchemaRegistryClientTest | 7 |
| AsyncApiScheduledPublishResilienceTest | 3 |
| AsyncApiOrchestratorStopTest | 2 |
| MqttLiveBrokerIntegrationTest | 6 |
| Mqtt5LiveBrokerIntegrationTest | 4 |
| MqttTlsLiveBrokerIntegrationTest | 3 |
| MqttTlsHandshakeLiveBrokerIntegrationTest | 2 |
| AmqpLiveBrokerIntegrationTest | 7 |
| KafkaLiveBrokerIntegrationTest | 4 |
| KafkaSecurityLiveBrokerIntegrationTest | 2 |
| KafkaAvroLiveBrokerIntegrationTest | 3 |
| AsyncApiControlPlaneLiveBrokerIntegrationTest | 1 |

## Spec parsing, examples and validation

Where each `@Test` of mockserver-async's parser, example-generator and schema-validation unit tests (8.0.0, in-JVM)
is ported. "Port" means `tests/upstream/<file>.rs::<fn>`. The parser, generator and validator tests call
`mock_server::asyncapi::spec` directly (`parse`, `Channel::example`, `Message::example`, `examples`,
`Channel::to_publish_options`, `validate`); `AsyncApiFirstMessageExampleValidationTest` calls
`AsyncApiControlPlaneImpl.load`/`status` upstream and here sends `PUT`/`GET /mockserver/asyncapi` to an in-process
server without brokers. Every test is ported; none is marked not portable.

### AsyncApiParserTest (38)

| Test | Where |
|---|---|
| shouldParseAsyncApi2xWithExplicitExample | `tests/upstream/asyncapi_spec.rs::should_parse_async_api2x_with_explicit_example` |
| shouldParseAsyncApi2xWithMessageExamplesArray | `tests/upstream/asyncapi_spec.rs::should_parse_async_api2x_with_message_examples_array` |
| shouldParseAsyncApi2xWithMultipleChannels | `tests/upstream/asyncapi_spec.rs::should_parse_async_api2x_with_multiple_channels` |
| shouldParseAsyncApi2xYaml | `tests/upstream/asyncapi_spec.rs::should_parse_async_api2x_yaml` |
| shouldTolerateChannelWithNoMessage | `tests/upstream/asyncapi_spec.rs::should_tolerate_channel_with_no_message` |
| shouldParseAsyncApi3xWithInlineMessage | `tests/upstream/asyncapi_spec.rs::should_parse_async_api3x_with_inline_message` |
| shouldParseAsyncApi3xWithRefToComponentsMessages | `tests/upstream/asyncapi_spec.rs::should_parse_async_api3x_with_ref_to_components_messages` |
| shouldParseV2MqttBindingsQosAndRetain | `tests/upstream/asyncapi_spec.rs::should_parse_v2_mqtt_bindings_qos_and_retain` |
| shouldParseV2KafkaKeyLiteral | `tests/upstream/asyncapi_spec.rs::should_parse_v2_kafka_key_literal` |
| shouldParseV2KafkaKeyFromSchemaConst | `tests/upstream/asyncapi_spec.rs::should_parse_v2_kafka_key_from_schema_const` |
| shouldParseV2KafkaKeyFromSchemaExample | `tests/upstream/asyncapi_spec.rs::should_parse_v2_kafka_key_from_schema_example` |
| shouldParseV2KafkaKeyFromSchemaExamplesArray | `tests/upstream/asyncapi_spec.rs::should_parse_v2_kafka_key_from_schema_examples_array` |
| shouldReturnNullKafkaKeyForBareSchema | `tests/upstream/asyncapi_spec.rs::should_return_null_kafka_key_for_bare_schema` |
| shouldReturnNullBindingsWhenAbsent | `tests/upstream/asyncapi_spec.rs::should_return_null_bindings_when_absent` |
| shouldIgnoreMalformedMqttBinding | `tests/upstream/asyncapi_spec.rs::should_ignore_malformed_mqtt_binding` |
| shouldIgnoreOutOfRangeMqttQos | `tests/upstream/asyncapi_spec.rs::should_ignore_out_of_range_mqtt_qos` |
| shouldParseV3KafkaKeyFromMessage | `tests/upstream/asyncapi_spec.rs::should_parse_v3_kafka_key_from_message` |
| shouldParseV3ChannelLevelMqttBindings | `tests/upstream/asyncapi_spec.rs::should_parse_v3_channel_level_mqtt_bindings` |
| shouldReturnNullV3MqttBindingsWhenOnlyOnOperations | `tests/upstream/asyncapi_spec.rs::should_return_null_v3_mqtt_bindings_when_only_on_operations` |
| channelToPublishOptionsShouldCarryBindings | `tests/upstream/asyncapi_spec.rs::channel_to_publish_options_should_carry_bindings` (`isEmpty()` as inequality with `PublishOptions::none()`) |
| channelToPublishOptionsShouldReturnNoneWhenNoBindings | `tests/upstream/asyncapi_spec.rs::channel_to_publish_options_should_return_none_when_no_bindings` (`isEmpty()` as equality with `PublishOptions::none()`) |
| shouldParseV3ChannelWithMultipleMessages | `tests/upstream/asyncapi_spec.rs::should_parse_v3_channel_with_multiple_messages` |
| shouldParseV3SingleMessageChannelGetMessagesReturnsOne | `tests/upstream/asyncapi_spec.rs::should_parse_v3_single_message_channel_get_messages_returns_one` |
| shouldParseV3MultiMessageWithRef | `tests/upstream/asyncapi_spec.rs::should_parse_v3_multi_message_with_ref` |
| shouldParseV2ChannelWithOneOfMultiMessage | `tests/upstream/asyncapi_spec.rs::should_parse_v2_channel_with_one_of_multi_message` |
| shouldParseV2SingleMessageNoOneOfGetMessagesReturnsOne | `tests/upstream/asyncapi_spec.rs::should_parse_v2_single_message_no_one_of_get_messages_returns_one` |
| shouldParseV2OneOfWithMqttBindingsAtOperationLevel | `tests/upstream/asyncapi_spec.rs::should_parse_v2_one_of_with_mqtt_bindings_at_operation_level` |
| shouldTolerateV2OneOfWithSingleEntry | `tests/upstream/asyncapi_spec.rs::should_tolerate_v2_one_of_with_single_entry` |
| shouldParseV2CorrelationIdHeaderLocation | `tests/upstream/asyncapi_spec.rs::should_parse_v2_correlation_id_header_location` |
| shouldParseV2CorrelationIdPayloadLocation | `tests/upstream/asyncapi_spec.rs::should_parse_v2_correlation_id_payload_location` |
| shouldParseV2CorrelationIdFromRefToComponents | `tests/upstream/asyncapi_spec.rs::should_parse_v2_correlation_id_from_ref_to_components` |
| shouldReturnNullCorrelationIdWhenAbsent | `tests/upstream/asyncapi_spec.rs::should_return_null_correlation_id_when_absent` |
| shouldReturnNullCorrelationIdWhenMalformed | `tests/upstream/asyncapi_spec.rs::should_return_null_correlation_id_when_malformed` |
| shouldParseV2OneOfCorrelationIdPerVariant | `tests/upstream/asyncapi_spec.rs::should_parse_v2_one_of_correlation_id_per_variant` |
| shouldParseV3CorrelationId | `tests/upstream/asyncapi_spec.rs::should_parse_v3_correlation_id` |
| shouldParseV3CorrelationIdWithRefToComponents | `tests/upstream/asyncapi_spec.rs::should_parse_v3_correlation_id_with_ref_to_components` |
| shouldRejectNullDocument | `tests/upstream/asyncapi_spec.rs::should_reject_null_document` (a `&str` cannot be null: the empty document, same message) |
| shouldRejectBlankDocument | `tests/upstream/asyncapi_spec.rs::should_reject_blank_document` |

### AmqpBindingParserTest (6)

| Test | Where |
|---|---|
| shouldParseRoutingKeyExchangeBindingV2 | `tests/upstream/asyncapi_spec.rs::should_parse_routing_key_exchange_binding_v2` |
| shouldParseQueueBindingV3 | `tests/upstream/asyncapi_spec.rs::should_parse_queue_binding_v3` |
| shouldDefaultToRoutingKeyWhenIsAbsent | `tests/upstream/asyncapi_spec.rs::should_default_to_routing_key_when_is_absent` |
| shouldReturnNullBindingWhenNoAmqpBindingPresent | `tests/upstream/asyncapi_spec.rs::should_return_null_binding_when_no_amqp_binding_present` |
| shouldParseExplicitRoutingKeyExtension | `tests/upstream/asyncapi_spec.rs::should_parse_explicit_routing_key_extension` |
| shouldNotAffectKafkaOrMqttChannels | `tests/upstream/asyncapi_spec.rs::should_not_affect_kafka_or_mqtt_channels` |

### MessageExampleGeneratorTest (11)

| Test | Where |
|---|---|
| shouldUseExplicitExampleWhenPresent | `tests/upstream/asyncapi_examples.rs::should_use_explicit_example_when_present` |
| shouldSynthesizeFromSchemaWhenNoExample | `tests/upstream/asyncapi_examples.rs::should_synthesize_from_schema_when_no_example` |
| shouldSynthesizeArrayType | `tests/upstream/asyncapi_examples.rs::should_synthesize_array_type` |
| shouldFallbackToEmptyObjectWhenNoSchemaAndNoExample | `tests/upstream/asyncapi_examples.rs::should_fallback_to_empty_object_when_no_schema_and_no_example` |
| shouldSynthesizeNestedObject | `tests/upstream/asyncapi_examples.rs::should_synthesize_nested_object` |
| shouldGenerateExamplesForMultipleChannels | `tests/upstream/asyncapi_examples.rs::should_generate_examples_for_multiple_channels` |
| shouldHandleSchemaWithoutExplicitType | `tests/upstream/asyncapi_examples.rs::should_handle_schema_without_explicit_type` |
| shouldGenerateExampleFromMessageWithExplicitExample | `tests/upstream/asyncapi_examples.rs::should_generate_example_from_message_with_explicit_example` |
| shouldGenerateExampleFromMessageWithSchema | `tests/upstream/asyncapi_examples.rs::should_generate_example_from_message_with_schema` |
| shouldGenerateEmptyObjectFromMessageWithNoSchemaOrExample | `tests/upstream/asyncapi_examples.rs::should_generate_empty_object_from_message_with_no_schema_or_example` |
| shouldPreferExplicitExampleOverSchemaForMessage | `tests/upstream/asyncapi_examples.rs::should_prefer_explicit_example_over_schema_for_message` |

### MessageExampleGeneratorSchemaAwareTest (11)

| Test | Where |
|---|---|
| shouldUseEnumFirstValue | `tests/upstream/asyncapi_examples.rs::should_use_enum_first_value` |
| shouldUseDefaultValue | `tests/upstream/asyncapi_examples.rs::should_use_default_value` |
| shouldUseConstValue | `tests/upstream/asyncapi_examples.rs::should_use_const_value` |
| shouldRespectMinimum | `tests/upstream/asyncapi_examples.rs::should_respect_minimum` |
| shouldRespectExclusiveMinimum | `tests/upstream/asyncapi_examples.rs::should_respect_exclusive_minimum` |
| shouldSynthesizeDateTimeFormat | `tests/upstream/asyncapi_examples.rs::should_synthesize_date_time_format` |
| shouldSynthesizeEmailFormat | `tests/upstream/asyncapi_examples.rs::should_synthesize_email_format` |
| shouldSynthesizeUuidFormat | `tests/upstream/asyncapi_examples.rs::should_synthesize_uuid_format` |
| shouldRespectMinLength | `tests/upstream/asyncapi_examples.rs::should_respect_min_length` |
| shouldRespectMinItems | `tests/upstream/asyncapi_examples.rs::should_respect_min_items` |
| shouldSynthesizeNumberWithMinimum | `tests/upstream/asyncapi_examples.rs::should_synthesize_number_with_minimum` |

### AsyncApiSchemaValidatorTest (10)

| Test | Where |
|---|---|
| shouldAcceptValidPayload | `tests/upstream/asyncapi_validation.rs::should_accept_valid_payload` |
| shouldRejectMissingRequiredField | `tests/upstream/asyncapi_validation.rs::should_reject_missing_required_field` |
| shouldRejectWrongType | `tests/upstream/asyncapi_validation.rs::should_reject_wrong_type` |
| shouldAcceptValidEnum | `tests/upstream/asyncapi_validation.rs::should_accept_valid_enum` |
| shouldRejectInvalidEnum | `tests/upstream/asyncapi_validation.rs::should_reject_invalid_enum` |
| shouldAcceptWhenNoSchema | `tests/upstream/asyncapi_validation.rs::should_accept_when_no_schema` (`None` schema) |
| shouldRejectNullPayload | `tests/upstream/asyncapi_validation.rs::should_reject_null_payload` (`None`) |
| shouldRejectBlankPayload | `tests/upstream/asyncapi_validation.rs::should_reject_blank_payload` |
| shouldValidateMinimum | `tests/upstream/asyncapi_validation.rs::should_validate_minimum` |
| shouldValidatePattern | `tests/upstream/asyncapi_validation.rs::should_validate_pattern` |

### AsyncApiFirstMessageExampleValidationTest (13)

| Test | Where |
|---|---|
| shouldNotReportIssueWhenFirstExampleConformsToSchema | `tests/upstream/asyncapi_validation.rs::should_not_report_issue_when_first_example_conforms_to_schema` |
| shouldNotReportIssueForConformingV3Example | `tests/upstream/asyncapi_validation.rs::should_not_report_issue_for_conforming_v3_example` |
| shouldReportIssueWhenFirstExampleViolatesSchema | `tests/upstream/asyncapi_validation.rs::should_report_issue_when_first_example_violates_schema` |
| shouldReportIssueForMissingRequiredFieldInExample | `tests/upstream/asyncapi_validation.rs::should_report_issue_for_missing_required_field_in_example` |
| shouldReportIssueInStatusAfterLoadWithBadExample | `tests/upstream/asyncapi_validation.rs::should_report_issue_in_status_after_load_with_bad_example` |
| shouldSkipValidationWhenNoSchema | `tests/upstream/asyncapi_validation.rs::should_skip_validation_when_no_schema` |
| shouldSkipValidationWhenNoExamples | `tests/upstream/asyncapi_validation.rs::should_skip_validation_when_no_examples` |
| shouldSkipValidationWhenNeitherSchemaNorExamples | `tests/upstream/asyncapi_validation.rs::should_skip_validation_when_neither_schema_nor_examples` |
| shouldValidateFirstExampleOfEachMessageInMultiMessageChannel | `tests/upstream/asyncapi_validation.rs::should_validate_first_example_of_each_message_in_multi_message_channel` |
| shouldNotHardFailLoadOnExampleValidationIssue | `tests/upstream/asyncapi_validation.rs::should_not_hard_fail_load_on_example_validation_issue` |
| shouldValidateOnlyFirstExampleNotSubsequent | `tests/upstream/asyncapi_validation.rs::should_validate_only_first_example_not_subsequent` |
| shouldIncludeMessageNameInContextForV3MultiMessage | `tests/upstream/asyncapi_validation.rs::should_include_message_name_in_context_for_v3_multi_message` |
| shouldUsePlainContextForSingleMessageChannel | `tests/upstream/asyncapi_validation.rs::should_use_plain_context_for_single_message_channel` |

### Additional Rust checks (not upstream tests)

| Check | Where |
|---|---|
| numeric Kafka key (`asText()` of a number) and an example double printed as Jackson prints it (moved from the removed `spec.rs` unit tests) | `tests/upstream/asyncapi_spec.rs::kafka_key_numbers_and_example_doubles_print_as_jackson_does` |
| `minItems`/`minLength`/`minimum` given as doubles are read as `asInt()`/`asLong()` read them; `minimum + 1` wraps as a Java `long` | `tests/upstream/asyncapi_examples.rs::numeric_constraints_are_read_as_jackson_reads_them` |

## Control plane

Where each `@Test` of upstream's control-plane unit tests (mockserver-async 8.0.0, `org.mockserver.async.controlplane`)
is checked. Each has a port, `tests/upstream/<file>.rs::<fn>`, run by `cargo test --test upstream`. The ports drive
the control plane over HTTP on an in-process server (`PUT`/`GET /mockserver/asyncapi`, `PUT /mockserver/asyncapi/verify`,
`PUT /mockserver/asyncapi/http`, `PUT /mockserver/reset`, `PUT /mockserver/configuration`), except:

- `parseBrokerConfig` tests call `mock_server::asyncapi::BrokerConfig::parse`. Upstream's `Configuration` instance
  is the server's runtime values (`Config::set_runtime`, which `PUT /mockserver/configuration` sets), and its static
  `ConfigurationProperties` store is the properties the server started with (`Config::with_property`).
- `load("")` cannot come over HTTP (the route answers an empty body itself), so those two tests call `AsyncApi::load`.
- The verify tests install upstream's stub subscriber with `AsyncApi::add_subscriber_for_testing`, reached through
  `Server::asyncapi`.

Over HTTP, `verify(null)` and `verify("")` are the same request. Nothing in these classes is unportable.

Two more ports check what upstream gets from having one control plane per JVM:
`asyncapi_control_plane.rs::each_server_keeps_its_own_asyncapi_state` and
`asyncapi_control_plane.rs::stopping_the_server_closes_and_unloads_asyncapi`.

### AsyncApiControlPlaneImplTest (16)

| Test | Where |
|---|---|
| shouldReturnEmptyStatusWhenNoSpecLoaded | `tests/upstream/asyncapi_control_plane.rs::should_return_empty_status_when_no_spec_loaded` |
| shouldLoadSpecWithoutBrokerConfig | `tests/upstream/asyncapi_control_plane.rs::should_load_spec_without_broker_config` |
| shouldReturnStatusAfterLoad | `tests/upstream/asyncapi_control_plane.rs::should_return_status_after_load` |
| shouldResetState | `tests/upstream/asyncapi_control_plane.rs::should_reset_state` |
| shouldLoadSpecFromWrappedBody | `tests/upstream/asyncapi_control_plane.rs::should_load_spec_from_wrapped_body` |
| shouldHandleInvalidSpec | `tests/upstream/asyncapi_control_plane.rs::should_handle_invalid_spec` |
| shouldThrowOnEmptyBody | `tests/upstream/asyncapi_control_plane.rs::should_throw_on_empty_body` |
| shouldLoadYamlSpec | `tests/upstream/asyncapi_control_plane.rs::should_load_yaml_spec` |
| shouldLoadAsyncApi3xSpec | `tests/upstream/asyncapi_control_plane.rs::should_load_async_api3x_spec` |
| shouldReloadSpecReplacingPrevious | `tests/upstream/asyncapi_control_plane.rs::should_reload_spec_replacing_previous` |
| shouldThrowOnFailureAndCleanUpPartialState | `tests/upstream/asyncapi_control_plane.rs::should_throw_on_failure_and_clean_up_partial_state` |
| loadFailureShouldThrowRuntimeException | `tests/upstream/asyncapi_control_plane.rs::load_failure_should_throw_runtime_exception` |
| shouldFallBackToConfigDefaultKafkaBootstrapServers | `tests/upstream/asyncapi_control_plane.rs::should_fall_back_to_config_default_kafka_bootstrap_servers` |
| shouldPreferRequestBodyKafkaOverConfigDefault | `tests/upstream/asyncapi_control_plane.rs::should_prefer_request_body_kafka_over_config_default` |
| shouldUseAsyncRecordedMessageMaxEntriesFromConfig | `tests/upstream/asyncapi_control_plane.rs::should_use_async_recorded_message_max_entries_from_config` |
| shouldNoBrokersWhenNoConfigDefaultAndNoRequestConfig | `tests/upstream/asyncapi_control_plane.rs::should_no_brokers_when_no_config_default_and_no_request_config` |

### AsyncApiControlPlaneVerifyTest (28)

| Test | Where |
|---|---|
| shouldPassWhenAtLeastOneMessageMatchesChannel | `tests/upstream/asyncapi_verify.rs::should_pass_when_at_least_one_message_matches_channel` |
| shouldPassWhenExactlyMatchesCount | `tests/upstream/asyncapi_verify.rs::should_pass_when_exactly_matches_count` |
| shouldPassWhenAtLeastMatchesCount | `tests/upstream/asyncapi_verify.rs::should_pass_when_at_least_matches_count` |
| shouldPassWhenAtMostMatchesCount | `tests/upstream/asyncapi_verify.rs::should_pass_when_at_most_matches_count` |
| shouldPassWithPayloadSubstringMatch | `tests/upstream/asyncapi_verify.rs::should_pass_with_payload_substring_match` |
| shouldPassWithJsonPathMatch | `tests/upstream/asyncapi_verify.rs::should_pass_with_json_path_match` |
| shouldPassWithBothSubstringAndJsonPathMatch | `tests/upstream/asyncapi_verify.rs::should_pass_with_both_substring_and_json_path_match` |
| shouldPassWhenExactlyZeroAndNoMessages | `tests/upstream/asyncapi_verify.rs::should_pass_when_exactly_zero_and_no_messages` |
| shouldPassWithAtMostZeroAndNoMessages | `tests/upstream/asyncapi_verify.rs::should_pass_with_at_most_zero_and_no_messages` |
| shouldFailWhenNoMessagesMatchChannel | `tests/upstream/asyncapi_verify.rs::should_fail_when_no_messages_match_channel` |
| shouldFailWhenExactlyDoesNotMatch | `tests/upstream/asyncapi_verify.rs::should_fail_when_exactly_does_not_match` |
| shouldFailWhenAtLeastNotMet | `tests/upstream/asyncapi_verify.rs::should_fail_when_at_least_not_met` |
| shouldFailWhenAtMostExceeded | `tests/upstream/asyncapi_verify.rs::should_fail_when_at_most_exceeded` |
| shouldFailWhenPayloadSubstringNotFound | `tests/upstream/asyncapi_verify.rs::should_fail_when_payload_substring_not_found` |
| shouldFailWhenJsonPathValueDoesNotMatch | `tests/upstream/asyncapi_verify.rs::should_fail_when_json_path_value_does_not_match` |
| shouldPassWhenBothAtLeastAndAtMostSatisfied | `tests/upstream/asyncapi_verify.rs::should_pass_when_both_at_least_and_at_most_satisfied` |
| shouldFailWhenAtLeastMetButAtMostExceeded | `tests/upstream/asyncapi_verify.rs::should_fail_when_at_least_met_but_at_most_exceeded` |
| shouldThrowOnNullBody | `tests/upstream/asyncapi_verify.rs::should_throw_on_null_body` |
| shouldThrowOnEmptyBody | `tests/upstream/asyncapi_verify.rs::should_throw_on_empty_body` |
| shouldThrowOnBlankBody | `tests/upstream/asyncapi_verify.rs::should_throw_on_blank_body` |
| shouldThrowOnInvalidJson | `tests/upstream/asyncapi_verify.rs::should_throw_on_invalid_json` |
| shouldThrowWhenChannelFieldMissing | `tests/upstream/asyncapi_verify.rs::should_throw_when_channel_field_missing` |
| shouldHandleJsonPathToNumericValue | `tests/upstream/asyncapi_verify.rs::should_handle_json_path_to_numeric_value` |
| shouldHandleJsonPathToBooleanValue | `tests/upstream/asyncapi_verify.rs::should_handle_json_path_to_boolean_value` |
| shouldHandleNonExistentJsonPath | `tests/upstream/asyncapi_verify.rs::should_handle_non_existent_json_path` |
| shouldHandleNonJsonPayloadGracefully | `tests/upstream/asyncapi_verify.rs::should_handle_non_json_payload_gracefully` |
| shouldHandleNullPayloadMessage | `tests/upstream/asyncapi_verify.rs::should_handle_null_payload_message` |
| shouldDefaultToAtLeastOneWhenNoCountSpecified | `tests/upstream/asyncapi_verify.rs::should_default_to_at_least_one_when_no_count_specified` |

### AsyncApiControlPlaneSecurityTest (15)

| Test | Where |
|---|---|
| shouldParseKafkaSecurityFromBrokerConfig | `tests/upstream/asyncapi_broker_config.rs::should_parse_kafka_security_from_broker_config` |
| shouldReturnNullKafkaSecurityWhenAbsent | `tests/upstream/asyncapi_broker_config.rs::should_return_null_kafka_security_when_absent` |
| shouldReturnNullKafkaSecurityWhenEmptyObject | `tests/upstream/asyncapi_broker_config.rs::should_return_null_kafka_security_when_empty_object` |
| shouldParsePartialKafkaSecurity | `tests/upstream/asyncapi_broker_config.rs::should_parse_partial_kafka_security` |
| shouldParseMqttSecurityFromBrokerConfig | `tests/upstream/asyncapi_broker_config.rs::should_parse_mqtt_security_from_broker_config` |
| shouldReturnNullMqttSecurityWhenAbsent | `tests/upstream/asyncapi_broker_config.rs::should_return_null_mqtt_security_when_absent` |
| shouldReturnNullMqttSecurityWhenEmptyObject | `tests/upstream/asyncapi_broker_config.rs::should_return_null_mqtt_security_when_empty_object` |
| shouldParseMqttSecurityWithUsernameOnly | `tests/upstream/asyncapi_broker_config.rs::should_parse_mqtt_security_with_username_only` |
| shouldParseMqttSecurityWithSslPropertiesOnly | `tests/upstream/asyncapi_broker_config.rs::should_parse_mqtt_security_with_ssl_properties_only` |
| shouldHandleNullBrokerConfigNode | `tests/upstream/asyncapi_broker_config.rs::should_handle_null_broker_config_node` |
| shouldParseBothKafkaAndMqttSecurity | `tests/upstream/asyncapi_broker_config.rs::should_parse_both_kafka_and_mqtt_security` |
| shouldIgnoreNonObjectKafkaSecurityNode | `tests/upstream/asyncapi_broker_config.rs::should_ignore_non_object_kafka_security_node` |
| shouldIgnoreNonObjectMqttSecurityNode | `tests/upstream/asyncapi_broker_config.rs::should_ignore_non_object_mqtt_security_node` |
| shouldIgnoreNonTextualSslPropertyValues | `tests/upstream/asyncapi_broker_config.rs::should_ignore_non_textual_ssl_property_values` |
| existingBrokerConfigFieldsShouldStillParseWhenSecurityPresent | `tests/upstream/asyncapi_broker_config.rs::existing_broker_config_fields_should_still_parse_when_security_present` |

### AsyncApiControlPlaneParityConfigTest (8)

| Test | Where |
|---|---|
| shouldDefaultToMqttV3 | `tests/upstream/asyncapi_broker_config.rs::should_default_to_mqtt_v3` |
| shouldParseMqttProtocolVersion5 | `tests/upstream/asyncapi_broker_config.rs::should_parse_mqtt_protocol_version5` |
| shouldDefaultToJsonValueFormat | `tests/upstream/asyncapi_broker_config.rs::should_default_to_json_value_format` |
| shouldParseAvroValueFormatWithRegistryAndSchema | `tests/upstream/asyncapi_broker_config.rs::should_parse_avro_value_format_with_registry_and_schema` |
| shouldRejectUnsupportedMqttProtocolVersion | `tests/upstream/asyncapi_broker_config.rs::should_reject_unsupported_mqtt_protocol_version` |
| shouldRejectProtobufKafkaValueFormat | `tests/upstream/asyncapi_broker_config.rs::should_reject_protobuf_kafka_value_format` |
| shouldRejectUnknownKafkaValueFormat | `tests/upstream/asyncapi_broker_config.rs::should_reject_unknown_kafka_value_format` |
| shouldAcceptInlineAvroSchemaObject | `tests/upstream/asyncapi_broker_config.rs::should_accept_inline_avro_schema_object` |

### AsyncApiControlPlaneConfigurationInstanceTest (7)

| Test | Where |
|---|---|
| shouldUseKafkaBootstrapServersFromConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_use_kafka_bootstrap_servers_from_configuration_instance` |
| shouldUseMqttBrokerUrlFromConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_use_mqtt_broker_url_from_configuration_instance` |
| shouldUseAmqpUriFromConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_use_amqp_uri_from_configuration_instance` |
| shouldUseRecordedMessageMaxEntriesFromConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_use_recorded_message_max_entries_from_configuration_instance` |
| shouldPreferExplicitRequestValuesOverConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_prefer_explicit_request_values_over_configuration_instance` |
| shouldFallBackToStaticStoreWhenNoConfigurationInstance | `tests/upstream/asyncapi_broker_config.rs::should_fall_back_to_static_store_when_no_configuration_instance` |
| shouldFallBackThroughConfigurationInstanceToStaticStore | `tests/upstream/asyncapi_broker_config.rs::should_fall_back_through_configuration_instance_to_static_store` |

### AsyncApiHttpExpectationGeneratorTest (7)

| Test | Where |
|---|---|
| shouldGenerateOneGetExpectationPerChannel | `tests/upstream/asyncapi_http_expectations.rs::should_generate_one_get_expectation_per_channel` |
| shouldApplyChannelPathPrefixFromWrapper | `tests/upstream/asyncapi_http_expectations.rs::should_apply_channel_path_prefix_from_wrapper` |
| shouldSerializeToExpectationJsonArray | `tests/upstream/asyncapi_http_expectations.rs::should_serialize_to_expectation_json_array` |
| shouldRejectBlankBody | `tests/upstream/asyncapi_http_expectations.rs::should_reject_blank_body` |
| shouldRejectMalformedSpec | `tests/upstream/asyncapi_http_expectations.rs::should_reject_malformed_spec` |
| shouldRejectSpecWithNoChannels | `tests/upstream/asyncapi_http_expectations.rs::should_reject_spec_with_no_channels` |
| shouldDisambiguateCollidingChannelPaths | `tests/upstream/asyncapi_http_expectations.rs::should_disambiguate_colliding_channel_paths` |

## Publishers and publish options

Where each `@Test` of upstream's mockserver-async publisher unit tests (8.0.0, `publish/*Test` and
`AsyncApiMockOrchestratorTest`) is checked. These tests hand the publishers Mockito mocks of the broker clients
(Paho `MqttClient`, RabbitMQ `Channel`/`Connection`, `KafkaProducer`, the `MessagePublisher`), so none of them runs
unmodified. "Port" means `tests/upstream/<file>.rs::<fn>`:

- MQTT and AMQP publishers connect to a fake broker in the test, which records the packets and methods it receives
  (what upstream's mocks capture) and answers as the test scripts it (acks, nacks, returns, refusals, silence).
- Kafka publishers are checked on the record they send (`kafka::producer_record`, the key, headers and value, Avro
  framed or not) and on `kafka::Deliveries` (the send callback's failure and what `flush` waits for and reports).
- The orchestrator runs over the stub publisher of `tests/upstream/asyncapi_stubs.rs`.

A Java `null` for the options is `PublishOptions::default()` (the same as `none()`); upstream's
`publish(channel, key, payload, headers)` overload is the options' key and headers.

### AsyncApiMockOrchestratorTest (19)

| Test | Where |
|---|---|
| shouldPublishExampleForEachChannel | `tests/upstream/asyncapi_orchestrator.rs::should_publish_example_for_each_channel` |
| shouldPublishSynthesizedPayloadWhenNoExample | `tests/upstream/asyncapi_orchestrator.rs::should_publish_synthesized_payload_when_no_example` |
| shouldPublishEmptyObjectWhenNoExampleAndNoSchema | `tests/upstream/asyncapi_orchestrator.rs::should_publish_empty_object_when_no_example_and_no_schema` |
| shouldDoNothingWhenNoChannels | `tests/upstream/asyncapi_orchestrator.rs::should_do_nothing_when_no_channels` |
| shouldStartAndStopScheduledPublishing | `tests/upstream/asyncapi_orchestrator.rs::should_start_and_stop_scheduled_publishing` |
| shouldThreadMqttBindingsToPublisher | `tests/upstream/asyncapi_orchestrator.rs::should_thread_mqtt_bindings_to_publisher` |
| shouldThreadKafkaKeyToPublisher | `tests/upstream/asyncapi_orchestrator.rs::should_thread_kafka_key_to_publisher` |
| shouldPassNoneOptionsWhenChannelHasNoBindings | `tests/upstream/asyncapi_orchestrator.rs::should_pass_none_options_when_channel_has_no_bindings` |
| shouldPublishOnePerMessageForMultiMessageChannel | `tests/upstream/asyncapi_orchestrator.rs::should_publish_one_per_message_for_multi_message_channel` |
| shouldPublishMultiMessageWithChannelLevelMqttBindings | `tests/upstream/asyncapi_orchestrator.rs::should_publish_multi_message_with_channel_level_mqtt_bindings` |
| shouldPublishSingleMessageFromChannelWithNoExplicitMessages | `tests/upstream/asyncapi_orchestrator.rs::should_publish_single_message_from_channel_with_no_explicit_messages` |
| shouldInjectCorrelationIdIntoHeaders | `tests/upstream/asyncapi_orchestrator.rs::should_inject_correlation_id_into_headers` |
| shouldInjectCorrelationIdIntoPayloadSingleLevel | `tests/upstream/asyncapi_orchestrator.rs::should_inject_correlation_id_into_payload_single_level` |
| shouldInjectCorrelationIdIntoPayloadNestedPointer | `tests/upstream/asyncapi_orchestrator.rs::should_inject_correlation_id_into_payload_nested_pointer` |
| shouldLeavePayloadUnchangedWhenNotJson | `tests/upstream/asyncapi_orchestrator.rs::should_leave_payload_unchanged_when_not_json` (the example generator cannot be swapped: `inject_into_payload` on `not-valid-json`, and the orchestrator on a string example) |
| shouldSkipCorrelationIdForUnrecognisedLocationPrefix | `tests/upstream/asyncapi_orchestrator.rs::should_skip_correlation_id_for_unrecognised_location_prefix` |
| shouldNotInjectCorrelationIdWhenLocationIsNull | `tests/upstream/asyncapi_orchestrator.rs::should_not_inject_correlation_id_when_location_is_null` |
| shouldCombineCorrelationIdHeaderWithKafkaKey | `tests/upstream/asyncapi_orchestrator.rs::should_combine_correlation_id_header_with_kafka_key` |
| shouldInjectCorrelationIdViaChannelSynthesizedMessage | `tests/upstream/asyncapi_orchestrator.rs::should_inject_correlation_id_via_channel_synthesized_message` |

### PublishOptionsTest (20)

| Test | Where |
|---|---|
| shouldCreateWithAllFields | `tests/upstream/asyncapi_publish_options.rs::should_create_with_all_fields` |
| shouldCreateWithAllNulls | `tests/upstream/asyncapi_publish_options.rs::should_create_with_all_nulls` |
| noneShouldBeEmpty | `tests/upstream/asyncapi_publish_options.rs::none_should_be_empty` |
| shouldNotBeEmptyWithOnlyKey | `tests/upstream/asyncapi_publish_options.rs::should_not_be_empty_with_only_key` |
| shouldNotBeEmptyWithOnlyQos | `tests/upstream/asyncapi_publish_options.rs::should_not_be_empty_with_only_qos` |
| shouldNotBeEmptyWithOnlyRetain | `tests/upstream/asyncapi_publish_options.rs::should_not_be_empty_with_only_retain` |
| shouldAcceptQos0 | `tests/upstream/asyncapi_publish_options.rs::should_accept_qos0` |
| shouldAcceptQos1 | `tests/upstream/asyncapi_publish_options.rs::should_accept_qos1` |
| shouldAcceptQos2 | `tests/upstream/asyncapi_publish_options.rs::should_accept_qos2` |
| shouldRejectQos3 | `tests/upstream/asyncapi_publish_options.rs::should_reject_qos3` |
| shouldRejectNegativeQos | `tests/upstream/asyncapi_publish_options.rs::should_reject_negative_qos` |
| toStringShouldContainAllFields | `tests/upstream/asyncapi_publish_options.rs::to_string_should_contain_all_fields` |
| shouldCreateWithHeaders | `tests/upstream/asyncapi_publish_options.rs::should_create_with_headers` |
| shouldReturnEmptyHeadersWhenNull | `tests/upstream/asyncapi_publish_options.rs::should_return_empty_headers_when_null` (no `null` map in Rust: no headers) |
| shouldReturnEmptyHeadersWhenEmptyMap | `tests/upstream/asyncapi_publish_options.rs::should_return_empty_headers_when_empty_map` |
| shouldNotBeEmptyWithOnlyHeaders | `tests/upstream/asyncapi_publish_options.rs::should_not_be_empty_with_only_headers` |
| headersShouldBeDefensivelyCopied | `tests/upstream/asyncapi_publish_options.rs::headers_should_be_defensively_copied` |
| headersShouldBeUnmodifiable | `tests/upstream/asyncapi_publish_options.rs::headers_should_be_unmodifiable` (the unmodifiable map is the compiler's here: publishers get `&PublishOptions`; the test checks a changed copy leaves the original alone) |
| backwardCompatConstructorShouldHaveEmptyHeaders | `tests/upstream/asyncapi_publish_options.rs::backward_compat_constructor_should_have_empty_headers` |
| toStringShouldContainHeaders | `tests/upstream/asyncapi_publish_options.rs::to_string_should_contain_headers` |

### AmqpMessagePublisherTest (18)

| Test | Where |
|---|---|
| shouldDeriveDefaultExchangeWithChannelNameWhenNoBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_derive_default_exchange_with_channel_name_when_no_binding` |
| shouldDeriveExchangeAndChannelNameRoutingKeyForRoutingKeyBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_derive_exchange_and_channel_name_routing_key_for_routing_key_binding` |
| shouldPreferExplicitRoutingKeyOverChannelName | `tests/upstream/asyncapi_amqp_publisher.rs::should_prefer_explicit_routing_key_over_channel_name` |
| shouldDeriveDefaultExchangeAndQueueNameForQueueBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_derive_default_exchange_and_queue_name_for_queue_binding` |
| shouldFallBackToChannelNameForQueueBindingWithoutQueueName | `tests/upstream/asyncapi_amqp_publisher.rs::should_fall_back_to_channel_name_for_queue_binding_without_queue_name` |
| shouldPublishToDefaultExchangeWhenNoBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_publish_to_default_exchange_when_no_binding` |
| shouldDeclareAndPublishToExchangeForRoutingKeyBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_declare_and_publish_to_exchange_for_routing_key_binding` |
| shouldDeclareQueueAndPublishToDefaultExchangeForQueueBinding | `tests/upstream/asyncapi_amqp_publisher.rs::should_declare_queue_and_publish_to_default_exchange_for_queue_binding` |
| shouldDeclareExchangeOnlyOnceAcrossMultiplePublishes | `tests/upstream/asyncapi_amqp_publisher.rs::should_declare_exchange_only_once_across_multiple_publishes` |
| shouldEmitHeadersAsAmqpProperties | `tests/upstream/asyncapi_amqp_publisher.rs::should_emit_headers_as_amqp_properties` |
| shouldPutChannelIntoConfirmModeAndListenForReturns | `tests/upstream/asyncapi_amqp_publisher.rs::should_put_channel_into_confirm_mode_and_listen_for_returns` (`confirm.select` on the channel; lapin has no return listener to register, the returns show in the unroutable tests) |
| shouldWaitForPublisherConfirmOnEveryPublish | `tests/upstream/asyncapi_amqp_publisher.rs::should_wait_for_publisher_confirm_on_every_publish` (a late ack delays the publish; the channel is never closed) |
| shouldFailPublishWhenBrokerReturnsMessageAsUnroutable | `tests/upstream/asyncapi_amqp_publisher.rs::should_fail_publish_when_broker_returns_message_as_unroutable` |
| shouldNotFailSubsequentPublishAfterAnUnroutableOne | `tests/upstream/asyncapi_amqp_publisher.rs::should_not_fail_subsequent_publish_after_an_unroutable_one` |
| shouldReplaceClosedChannelAndKeepPublishingWhenConfirmsAreUnsupported | `tests/upstream/asyncapi_amqp_publisher.rs::should_replace_closed_channel_and_keep_publishing_when_confirms_are_unsupported` |
| shouldFailPublishOnNackWithoutClosingTheChannel | `tests/upstream/asyncapi_amqp_publisher.rs::should_fail_publish_on_nack_without_closing_the_channel` |
| shouldFailPublishOnConfirmTimeoutWithoutClosingTheChannel | `tests/upstream/asyncapi_amqp_publisher.rs::should_fail_publish_on_confirm_timeout_without_closing_the_channel` (waits the 5 s confirm timeout) |
| closeShouldCloseChannelAndConnection | `tests/upstream/asyncapi_amqp_publisher.rs::close_should_close_channel_and_connection` |

### KafkaAvroMessagePublisherTest (5)

| Test | Where |
|---|---|
| shouldFrameRegistrylessMessageWithFixedSchemaId | `tests/upstream/asyncapi_kafka_publishers.rs::should_frame_registryless_message_with_fixed_schema_id` |
| shouldUseRegistryIdWhenRegistryPresent | `tests/upstream/asyncapi_kafka_publishers.rs::should_use_registry_id_when_registry_present` (an in-process server plays the registry) |
| shouldApplyKeyAndHeadersFromPublishOptions | `tests/upstream/asyncapi_kafka_publishers.rs::should_apply_key_and_headers_from_publish_options` |
| shouldRejectMissingSchema | `tests/upstream/asyncapi_kafka_publishers.rs::should_reject_missing_schema` (`AvroWriter::new`, built before the producer as upstream's constructor checks the schema first) |
| shouldRaiseWhenPayloadDoesNotMatchSchema | `tests/upstream/asyncapi_kafka_publishers.rs::should_raise_when_payload_does_not_match_schema` |

### KafkaMessagePublisherDeliveryFailureTest (4)

| Test | Where |
|---|---|
| flushShouldDrainTheProducer | `tests/upstream/asyncapi_kafka_publishers.rs::flush_should_drain_the_producer` |
| flushShouldReportADeliveryFailure | `tests/upstream/asyncapi_kafka_publishers.rs::flush_should_report_a_delivery_failure` |
| flushShouldNotThrowWhenEveryDeliverySucceeded | `tests/upstream/asyncapi_kafka_publishers.rs::flush_should_not_throw_when_every_delivery_succeeded` |
| flushShouldNotRepeatAPreviouslyReportedFailure | `tests/upstream/asyncapi_kafka_publishers.rs::flush_should_not_repeat_a_previously_reported_failure` |

### KafkaMessagePublisherKeyHeadersTest (12)

| Test | Where |
|---|---|
| shouldSendRecordWithKey | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_record_with_key` |
| shouldSendRecordWithNullKey | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_record_with_null_key` |
| shouldSendRecordWithHeaders | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_record_with_headers` |
| shouldSendWithoutHeadersWhenNull | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_without_headers_when_null` |
| shouldSendViaDefaultInterfaceMethod | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_via_default_interface_method` |
| shouldSendWithKeyFromPublishOptions | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_with_key_from_publish_options` |
| shouldSendWithNullKeyWhenPublishOptionsHasNoKey | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_with_null_key_when_publish_options_has_no_key` |
| shouldSendWithNullKeyWhenPublishOptionsAreNull | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_with_null_key_when_publish_options_are_null` |
| shouldSendWithNullKeyWhenPublishOptionsNone | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_with_null_key_when_publish_options_none` |
| shouldSendHeadersFromPublishOptions | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_headers_from_publish_options` |
| shouldNotAddHeadersFromPublishOptionsWhenEmpty | `tests/upstream/asyncapi_kafka_publishers.rs::should_not_add_headers_from_publish_options_when_empty` |
| shouldCombineKeyAndHeadersFromPublishOptions | `tests/upstream/asyncapi_kafka_publishers.rs::should_combine_key_and_headers_from_publish_options` |

### KafkaMessagePublisherTest (2)

| Test | Where |
|---|---|
| shouldSendProducerRecordWithTopicAndPayload | `tests/upstream/asyncapi_kafka_publishers.rs::should_send_producer_record_with_topic_and_payload` |
| shouldCloseUnderlyingProducer | `tests/upstream/asyncapi_kafka_publishers.rs::should_close_underlying_producer` (the closed producer refuses the next send at once, as `KafkaProducer.send` does) |

### Mqtt5MessagePublisherTest (6)

| Test | Where |
|---|---|
| shouldPublishPayloadWithConfiguredQos | `tests/upstream/asyncapi_mqtt_publishers.rs::should_publish_payload_with_configured_qos` |
| shouldApplyQosAndRetainFromOptions | `tests/upstream/asyncapi_mqtt_publishers.rs::should_apply_qos_and_retain_from_options` |
| shouldDeliverHeadersAsUserProperties | `tests/upstream/asyncapi_mqtt_publishers.rs::should_deliver_headers_as_user_properties` |
| shouldPublishBinaryPayload | `tests/upstream/asyncapi_mqtt_publishers.rs::mqtt5_should_publish_binary_payload` |
| shouldRejectInvalidQosInConstructor | `tests/upstream/asyncapi_mqtt_publishers.rs::should_reject_invalid_qos_in_constructor` |
| shouldReportConfiguredQos | `tests/upstream/asyncapi_mqtt_publishers.rs::mqtt5_should_report_configured_qos` |

### MqttMessagePublisherQosTest (12)

| Test | Where |
|---|---|
| shouldPublishWithQos0 | `tests/upstream/asyncapi_mqtt_publishers.rs::should_publish_with_qos0` |
| shouldPublishWithQos2 | `tests/upstream/asyncapi_mqtt_publishers.rs::should_publish_with_qos2` |
| shouldPublishBinaryPayload | `tests/upstream/asyncapi_mqtt_publishers.rs::should_publish_binary_payload` |
| shouldReportConfiguredQos | `tests/upstream/asyncapi_mqtt_publishers.rs::should_report_configured_qos` |
| shouldConvertStringToUtf8Bytes | `tests/upstream/asyncapi_mqtt_publishers.rs::should_convert_string_to_utf8_bytes` |
| shouldApplyPublishOptionsQosAndRetain | `tests/upstream/asyncapi_mqtt_publishers.rs::should_apply_publish_options_qos_and_retain` |
| shouldFallBackToInstanceQosWhenOptionsQosIsNull | `tests/upstream/asyncapi_mqtt_publishers.rs::should_fall_back_to_instance_qos_when_options_qos_is_null` |
| shouldNotSetRetainedWhenOptionsRetainIsNull | `tests/upstream/asyncapi_mqtt_publishers.rs::should_not_set_retained_when_options_retain_is_null` |
| shouldUseInstanceDefaultsWhenOptionsAreNull | `tests/upstream/asyncapi_mqtt_publishers.rs::should_use_instance_defaults_when_options_are_null` |
| shouldUseInstanceDefaultsWhenOptionsNone | `tests/upstream/asyncapi_mqtt_publishers.rs::should_use_instance_defaults_when_options_none` |
| shouldIgnoreKafkaKeyInMqttPublishOptions | `tests/upstream/asyncapi_mqtt_publishers.rs::should_ignore_kafka_key_in_mqtt_publish_options` |
| shouldNotThrowWhenPublishOptionsHasHeaders | `tests/upstream/asyncapi_mqtt_publishers.rs::should_not_throw_when_publish_options_has_headers` |

### MqttMessagePublisherTest (3)

| Test | Where |
|---|---|
| shouldPublishMqttMessageWithTopicAndPayload | `tests/upstream/asyncapi_mqtt_publishers.rs::should_publish_mqtt_message_with_topic_and_payload` |
| shouldDisconnectAndCloseClient | `tests/upstream/asyncapi_mqtt_publishers.rs::should_disconnect_and_close_client` |
| shouldCloseWithoutDisconnectIfNotConnected | `tests/upstream/asyncapi_mqtt_publishers.rs::should_close_without_disconnect_if_not_connected` (the fake broker ends the connection after the CONNACK) |

## Subscribers, security options, store and serde

Where each `@Test` of upstream's mockserver-async unit tests (8.0.0, in-JVM) for subscribers, security options, the
consumed-message store and the Avro/Confluent serde is checked. These tests call adapter classes directly, most of
them over Mockito mocks of a broker client, so none of them runs unmodified. "Port" means
`tests/upstream/<file>.rs::<fn>`. Where upstream mocks a client, the port checks the same decision where the Rust
adapter makes it: MQTT subscribers connect to a stub broker (`asyncapi_mqtt_stub.rs`) that records subscriptions and
delivers messages; the Kafka subscriber takes prepared records through `KafkaSubscriber::record` (what its poll loop
does with each polled record); the AMQP subscriber's queue resolution and delivery conversion are `consume_source` and
`consumed_message`; Kafka client properties are `producer_properties`, `consumer_properties` and `apply_security`
(what the producer and consumer settings are read from); MQTT connect options are `connect_options`. Java `null`
arguments have no Rust counterpart (`&str`, slices and `usize` are never null or negative); the nearest input is
named.

### AmqpMessageSubscriberTest (6)

| Test | Where |
|---|---|
| shouldDeclareAndConsumeQueueBasedChannel | `tests/upstream/asyncapi_amqp_subscriber.rs::should_declare_and_consume_queue_based_channel` |
| shouldDeclareExchangeBindPrivateQueueForRoutingKeyChannel | `tests/upstream/asyncapi_amqp_subscriber.rs::should_declare_exchange_bind_private_queue_for_routing_key_channel` |
| shouldNormaliseNonLowercaseExchangeType | `tests/upstream/asyncapi_amqp_subscriber.rs::should_normalise_non_lowercase_exchange_type` |
| shouldConsumeChannelNameQueueWhenNoBinding | `tests/upstream/asyncapi_amqp_subscriber.rs::should_consume_channel_name_queue_when_no_binding` |
| shouldCancelConsumerOnUnsubscribe | not portable: `MessageSubscriber.unsubscribe` is never called by upstream's production code (the control plane only subscribes and closes), so it has no observable effect; the Rust `Subscriber` has no `unsubscribe` |
| shouldEvictOldestWhenCapReached | `tests/upstream/asyncapi_amqp_subscriber.rs::should_evict_oldest_when_cap_reached` |

### KafkaMessageSubscriberTest (9)

| Test | Where |
|---|---|
| shouldSubscribeToTopic | `tests/upstream/asyncapi_kafka_subscriber.rs::should_subscribe_to_topic` (the topic joins the poll loop's subscription) |
| shouldReturnEmptyListWhenNoMessages | `tests/upstream/asyncapi_kafka_subscriber.rs::should_return_empty_list_when_no_messages` |
| shouldRecordMessagesFromPoll | `tests/upstream/asyncapi_kafka_subscriber.rs::should_record_messages_from_poll` |
| shouldUnsubscribeFromTopic | not portable: `unsubscribe` is never called by upstream's production code; the Rust `Subscriber` has no `unsubscribe` |
| shouldReturnAllRecordedMessages | `tests/upstream/asyncapi_kafka_subscriber.rs::should_return_all_recorded_messages` |
| shouldClearOnClose | `tests/upstream/asyncapi_kafka_subscriber.rs::should_clear_on_close` |
| shouldEvictOldestWhenCapReached | `tests/upstream/asyncapi_kafka_subscriber.rs::should_evict_oldest_when_cap_reached` |
| shouldQueueSubscribeOpsAndNotCallConsumerDirectlyFromCallerThread | `tests/upstream/asyncapi_kafka_subscriber.rs::should_queue_subscribe_ops_and_not_call_consumer_directly_from_caller_thread` (`subscribe` returns at once with no broker reachable; the poll loop takes the topic) |
| shouldStartPollLoopExactlyOnceWithMultipleSubscribes | `tests/upstream/asyncapi_kafka_subscriber.rs::should_start_poll_loop_exactly_once_with_multiple_subscribes` (one subscription with all three topics) |

### KafkaMessageSubscriberSecurityTest (4)

| Test | Where |
|---|---|
| shouldBuildConsumerPropertiesWithSaslSslSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_consumer_properties_with_sasl_ssl_security` |
| shouldBuildConsumerPropertiesWithNullSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_consumer_properties_with_null_security` |
| shouldBuildConsumerPropertiesWithEmptySecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_consumer_properties_with_empty_security` |
| shouldBuildConsumerPropertiesWithSaslPlaintext | `tests/upstream/asyncapi_kafka_security.rs::should_build_consumer_properties_with_sasl_plaintext` |

### Mqtt5MessageSubscriberTest (5)

| Test | Where |
|---|---|
| shouldSubscribeToTopic | `tests/upstream/asyncapi_mqtt5_subscriber.rs::should_subscribe_to_topic` (the stub broker sees the filter at QoS 1) |
| shouldRecordMessagesViaCallback | `tests/upstream/asyncapi_mqtt5_subscriber.rs::should_record_messages_via_callback` |
| shouldRecordUserPropertiesAsHeaders | `tests/upstream/asyncapi_mqtt5_subscriber.rs::should_record_user_properties_as_headers` |
| shouldReportUnhealthyAfterDisconnect | `tests/upstream/asyncapi_mqtt5_subscriber.rs::should_report_unhealthy_after_disconnect` (the broker sends DISCONNECT and closes) |
| shouldEvictOldestWhenCapReached | `tests/upstream/asyncapi_mqtt5_subscriber.rs::should_evict_oldest_when_cap_reached` |

### MqttMessageSubscriberTest (7)

| Test | Where |
|---|---|
| shouldSubscribeToTopic | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_subscribe_to_topic` (the stub broker sees the filter at QoS 1) |
| shouldRecordMessagesViaCallback | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_record_messages_via_callback` |
| shouldReturnEmptyListForUnknownTopic | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_return_empty_list_for_unknown_topic` |
| shouldUnsubscribeFromTopic | not portable: `unsubscribe` is never called by upstream's production code; the Rust `Subscriber` has no `unsubscribe` |
| shouldReturnAllRecordedMessages | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_return_all_recorded_messages` |
| shouldClearOnClose | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_clear_on_close` (also: the connected client disconnects) |
| shouldEvictOldestWhenCapReached | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_evict_oldest_when_cap_reached` |

### MqttWildcardSubscriptionTest (5)

| Test | Where |
|---|---|
| shouldRetrieveMessagesOnConcreteTopicViaSingleLevelWildcardFilter | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_retrieve_messages_on_concrete_topic_via_single_level_wildcard_filter` |
| shouldRetrieveMessagesAcrossLevelsViaMultiLevelWildcardFilter | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_retrieve_messages_across_levels_via_multi_level_wildcard_filter` |
| shouldNotMatchUnrelatedTopicsForWildcardFilter | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_not_match_unrelated_topics_for_wildcard_filter` |
| shouldStillMatchExactTopicWhenFilterHasNoWildcard | `tests/upstream/asyncapi_mqtt_subscriber.rs::should_still_match_exact_topic_when_filter_has_no_wildcard` |
| mqtt5ShouldRetrieveMessagesOnConcreteTopicViaWildcardFilter | `tests/upstream/asyncapi_mqtt_subscriber.rs::mqtt5_should_retrieve_messages_on_concrete_topic_via_wildcard_filter` |

### MqttTopicFilterTest (15)

| Test | Where |
|---|---|
| shouldMatchIdenticalTopic | `tests/upstream/asyncapi_store.rs::should_match_identical_topic` |
| multiLevelWildcardShouldMatchDescendants | `tests/upstream/asyncapi_store.rs::multi_level_wildcard_should_match_descendants` |
| multiLevelWildcardShouldIncludeTheParentLevel | `tests/upstream/asyncapi_store.rs::multi_level_wildcard_should_include_the_parent_level` |
| loneMultiLevelWildcardShouldMatchEveryTopic | `tests/upstream/asyncapi_store.rs::lone_multi_level_wildcard_should_match_every_topic` |
| multiLevelWildcardShouldNotMatchASiblingPrefix | `tests/upstream/asyncapi_store.rs::multi_level_wildcard_should_not_match_a_sibling_prefix` |
| singleLevelWildcardShouldMatchExactlyOneLevel | `tests/upstream/asyncapi_store.rs::single_level_wildcard_should_match_exactly_one_level` |
| singleLevelWildcardShouldNotMatchTheParentLevel | `tests/upstream/asyncapi_store.rs::single_level_wildcard_should_not_match_the_parent_level` |
| loneSingleLevelWildcardShouldMatchOnlyTopLevelTopics | `tests/upstream/asyncapi_store.rs::lone_single_level_wildcard_should_match_only_top_level_topics` |
| singleLevelWildcardShouldMatchAtAnyPosition | `tests/upstream/asyncapi_store.rs::single_level_wildcard_should_match_at_any_position` |
| wildcardShouldNotMatchReservedDollarTopics | `tests/upstream/asyncapi_store.rs::wildcard_should_not_match_reserved_dollar_topics` |
| explicitDollarPrefixShouldMatchReservedTopics | `tests/upstream/asyncapi_store.rs::explicit_dollar_prefix_should_match_reserved_topics` |
| malformedFiltersShouldNotMatch | `tests/upstream/asyncapi_store.rs::malformed_filters_should_not_match` |
| shouldReportFilterValidity | `tests/upstream/asyncapi_store.rs::should_report_filter_validity` (without the `null` filter) |
| shouldDetectWildcardPresence | `tests/upstream/asyncapi_store.rs::should_detect_wildcard_presence` (without the `null` filter) |
| shouldHandleNullsWithoutMatching | `tests/upstream/asyncapi_store.rs::should_handle_nulls_without_matching` (empty filter and topic for `null`) |

### BoundedMessageStoreTest (9)

| Test | Where |
|---|---|
| shouldStoreMessagesUpToCapacity | `tests/upstream/asyncapi_store.rs::should_store_messages_up_to_capacity` |
| shouldEvictOldestWhenCapReached | `tests/upstream/asyncapi_store.rs::should_evict_oldest_when_cap_reached` |
| shouldReturnEmptySnapshotWhenEmpty | `tests/upstream/asyncapi_store.rs::should_return_empty_snapshot_when_empty` |
| shouldClearAllMessages | `tests/upstream/asyncapi_store.rs::should_clear_all_messages` |
| snapshotShouldBeIndependentOfStore | `tests/upstream/asyncapi_store.rs::snapshot_should_be_independent_of_store` |
| shouldRejectZeroMaxSize | `tests/upstream/asyncapi_store.rs::should_reject_zero_max_size` |
| shouldRejectNegativeMaxSize | `tests/upstream/asyncapi_store.rs::should_reject_negative_max_size` (a negative `maxRecordedMessages` through a subscriber's `ConsumedMessages`) |
| shouldWorkWithCapacityOfOne | `tests/upstream/asyncapi_store.rs::should_work_with_capacity_of_one` |
| shouldUseDefaultCapacity | `tests/upstream/asyncapi_store.rs::should_use_default_capacity` |

### KafkaAvroSchemaIdMismatchTest (3)

| Test | Where |
|---|---|
| shouldDecodeMessageFramedWithTheConfiguredSchemaId | `tests/upstream/asyncapi_kafka_subscriber.rs::should_decode_message_framed_with_the_configured_schema_id` |
| shouldNotDecodeMessageFramedWithADifferentSchemaId | `tests/upstream/asyncapi_kafka_subscriber.rs::should_not_decode_message_framed_with_a_different_schema_id` |
| shouldRecordNonAvroPayloadsUnchanged | `tests/upstream/asyncapi_kafka_subscriber.rs::should_record_non_avro_payloads_unchanged` |

### KafkaSecurityPropertiesTest (10)

| Test | Where |
|---|---|
| emptySecurityShouldBeEmpty | `tests/upstream/asyncapi_kafka_security.rs::empty_security_should_be_empty` |
| securityWithAnyFieldShouldNotBeEmpty | `tests/upstream/asyncapi_kafka_security.rs::security_with_any_field_should_not_be_empty` |
| securityWithBlankFieldsShouldBeEmpty | `tests/upstream/asyncapi_kafka_security.rs::security_with_blank_fields_should_be_empty` |
| gettersShouldReturnConfiguredValues | `tests/upstream/asyncapi_kafka_security.rs::getters_should_return_configured_values` (the fields) |
| shouldApplyAllSecurityProperties | `tests/upstream/asyncapi_kafka_security.rs::should_apply_all_security_properties` |
| shouldApplyPartialSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_apply_partial_security` |
| shouldSkipBlankValues | `tests/upstream/asyncapi_kafka_security.rs::should_skip_blank_values` |
| shouldBeNoOpWithNullSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_be_no_op_with_null_security` |
| shouldBeNoOpWithEmptySecurity | `tests/upstream/asyncapi_kafka_security.rs::should_be_no_op_with_empty_security` |
| shouldNotOverrideExistingProperties | `tests/upstream/asyncapi_kafka_security.rs::should_not_override_existing_properties` |

### MqttSecurityOptionsTest (13)

| Test | Where |
|---|---|
| emptySecurityShouldBeEmpty | `tests/upstream/asyncapi_mqtt_security.rs::empty_security_should_be_empty` |
| securityWithUsernameShouldNotBeEmpty | `tests/upstream/asyncapi_mqtt_security.rs::security_with_username_should_not_be_empty` |
| securityWithPasswordShouldNotBeEmpty | `tests/upstream/asyncapi_mqtt_security.rs::security_with_password_should_not_be_empty` |
| securityWithSslPropertiesShouldNotBeEmpty | `tests/upstream/asyncapi_mqtt_security.rs::security_with_ssl_properties_should_not_be_empty` |
| securityWithBlankFieldsShouldBeEmpty | `tests/upstream/asyncapi_mqtt_security.rs::security_with_blank_fields_should_be_empty` |
| sslPropertiesShouldBeUnmodifiable | `tests/upstream/asyncapi_mqtt_security.rs::ssl_properties_should_be_unmodifiable` (the security's own copy; mutation through a shared reference does not compile) |
| shouldReturnNullForNullSecurity | `tests/upstream/asyncapi_mqtt_security.rs::should_return_null_for_null_security` |
| shouldReturnNullForEmptySecurity | `tests/upstream/asyncapi_mqtt_security.rs::should_return_null_for_empty_security` |
| shouldSetUsernameAndPassword | `tests/upstream/asyncapi_mqtt_security.rs::should_set_username_and_password` |
| shouldSetOnlyUsername | `tests/upstream/asyncapi_mqtt_security.rs::should_set_only_username` |
| shouldSetSslProperties | `tests/upstream/asyncapi_mqtt_security.rs::should_set_ssl_properties` |
| shouldSetUsernamePasswordAndSslProperties | `tests/upstream/asyncapi_mqtt_security.rs::should_set_username_password_and_ssl_properties` |
| shouldNotSetBlankUsername | `tests/upstream/asyncapi_mqtt_security.rs::should_not_set_blank_username` |

### Mqtt5SecurityOptionsTest (5)

| Test | Where |
|---|---|
| shouldReturnNullForNullSecurity | `tests/upstream/asyncapi_mqtt5_security.rs::should_return_null_for_null_security` |
| shouldReturnNullForEmptySecurity | `tests/upstream/asyncapi_mqtt5_security.rs::should_return_null_for_empty_security` |
| shouldSetUsernameAndPassword | `tests/upstream/asyncapi_mqtt5_security.rs::should_set_username_and_password` |
| shouldSetSslProperties | `tests/upstream/asyncapi_mqtt5_security.rs::should_set_ssl_properties` |
| shouldNotSetBlankUsername | `tests/upstream/asyncapi_mqtt5_security.rs::should_not_set_blank_username` |

### KafkaMessagePublisherSecurityTest (4)

| Test | Where |
|---|---|
| shouldBuildProducerPropertiesWithSaslSslSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_producer_properties_with_sasl_ssl_security` |
| shouldBuildProducerPropertiesWithNullSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_producer_properties_with_null_security` |
| shouldBuildProducerPropertiesWithEmptySecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_producer_properties_with_empty_security` |
| shouldBuildProducerPropertiesWithPartialSecurity | `tests/upstream/asyncapi_kafka_security.rs::should_build_producer_properties_with_partial_security` |

### ConfluentWireFormatTest (7)

| Test | Where |
|---|---|
| shouldEncodeMagicByteAndSchemaId | `tests/upstream/asyncapi_serde.rs::should_encode_magic_byte_and_schema_id` |
| shouldRoundTripEncodeDecode | `tests/upstream/asyncapi_serde.rs::should_round_trip_encode_decode` |
| shouldDetectWireFormat | `tests/upstream/asyncapi_serde.rs::should_detect_wire_format` |
| shouldRejectNonWireFormatBytes | `tests/upstream/asyncapi_serde.rs::should_reject_non_wire_format_bytes` (without the `null` array) |
| shouldDecodeEmptyPayload | `tests/upstream/asyncapi_serde.rs::should_decode_empty_payload` |
| shouldThrowDecodingNonWireFormat | `tests/upstream/asyncapi_serde.rs::should_throw_decoding_non_wire_format` |
| shouldThrowEncodingNullPayload | not portable: the payload is a byte slice, which cannot be null (the empty payload is `should_decode_empty_payload`) |

### AvroPayloadCodecTest (4)

| Test | Where |
|---|---|
| shouldRoundTripJsonThroughAvroBinary | `tests/upstream/asyncapi_serde.rs::should_round_trip_json_through_avro_binary` |
| shouldEncodeDifferentValuesDistinctly | `tests/upstream/asyncapi_serde.rs::should_encode_different_values_distinctly` |
| shouldPreserveNumericAndStringTypes | `tests/upstream/asyncapi_serde.rs::should_preserve_numeric_and_string_types` |
| shouldThrowOnPayloadNotConformingToSchema | `tests/upstream/asyncapi_serde.rs::should_throw_on_payload_not_conforming_to_schema` |

### SchemaRegistryClientTest (7)

| Test | Where |
|---|---|
| shouldGetSchemaById | `tests/upstream/schema_registry_client.rs::should_get_schema_by_id` |
| shouldCacheSchemaById | `tests/upstream/schema_registry_client.rs::should_cache_schema_by_id` |
| shouldRegisterSchemaAndReturnId | `tests/upstream/schema_registry_client.rs::should_register_schema_and_return_id` |
| shouldUrlEncodeSubjectContainingSlash | `tests/upstream/schema_registry_client.rs::should_url_encode_subject_containing_slash` |
| shouldCacheRegistration | `tests/upstream/schema_registry_client.rs::should_cache_registration` |
| shouldThrowOnNon200GettingSchema | `tests/upstream/schema_registry_client.rs::should_throw_on_non200_getting_schema` |
| shouldRejectBlankBaseUrl | `tests/upstream/schema_registry_client.rs::should_reject_blank_base_url` |

## Orchestrator schedules and live brokers

The orchestrator's schedule and stop tests run over the stub publisher (`tests/upstream/asyncapi_orchestrator.rs`). The live-broker integration tests run against Mosquitto, RabbitMQ and Kafka containers with `make broker-tests` (`MOCK_SERVER_BROKER_TESTS=1`); plain `cargo test` skips them.

### AsyncApiScheduledPublishResilienceTest (3)

| Test | Where |
|---|---|
| scheduleShouldSurviveAFailingPublishCycle | `tests/upstream/asyncapi_orchestrator.rs::schedule_should_survive_a_failing_publish_cycle` |
| scheduleShouldRecoverOncePublishingSucceedsAgain | `tests/upstream/asyncapi_orchestrator.rs::schedule_should_recover_once_publishing_succeeds_again` |
| oneFailingChannelShouldNotStopTheOthersPublishing | `tests/upstream/asyncapi_orchestrator.rs::one_failing_channel_should_not_stop_the_others_publishing` |

### AsyncApiOrchestratorStopTest (2)

| Test | Where |
|---|---|
| stopShouldWaitForAnInFlightPublishToFinish | `tests/upstream/asyncapi_orchestrator.rs::stop_should_wait_for_an_in_flight_publish_to_finish` |
| stopShouldBeIdempotentAndReturnPromptlyWhenIdle | `tests/upstream/asyncapi_orchestrator.rs::stop_should_be_idempotent_and_return_promptly_when_idle` |

### MqttLiveBrokerIntegrationTest (6)

| Test | Where |
|---|---|
| shouldPublishAndReceiveMessageViaLiveMqttBroker | `tests/upstream/mqtt_live_broker.rs::should_publish_and_receive_message_via_live_mqtt_broker` |
| shouldPublishBinaryPayloadViaLiveBroker | `tests/upstream/mqtt_live_broker.rs::should_publish_binary_payload_via_live_broker` |
| subscriberShouldRecordMessagesFromLiveBroker | `tests/upstream/mqtt_live_broker.rs::subscriber_should_record_messages_from_live_broker` |
| subscriberShouldRecordWildcardSubscriptionFromLiveBroker | `tests/upstream/mqtt_live_broker.rs::subscriber_should_record_wildcard_subscription_from_live_broker` |
| orchestratorShouldPublishExamplesToLiveMqttBroker | `tests/upstream/mqtt_live_broker.rs::orchestrator_should_publish_examples_to_live_mqtt_broker` |
| shouldRoundTripPublishAndSubscribeViaMockServerAdapters | `tests/upstream/mqtt_live_broker.rs::should_round_trip_publish_and_subscribe_via_mock_server_adapters` |

### Mqtt5LiveBrokerIntegrationTest (4)

| Test | Where |
|---|---|
| shouldPublishAndReceiveViaMqtt5 | `tests/upstream/mqtt_live_broker.rs::should_publish_and_receive_via_mqtt5` |
| shouldDeliverUserPropertiesViaMqtt5 | `tests/upstream/mqtt_live_broker.rs::should_deliver_user_properties_via_mqtt5` |
| subscriberShouldRecordViaMqtt5 | `tests/upstream/mqtt_live_broker.rs::subscriber_should_record_via_mqtt5` |
| shouldRoundTripViaMqtt5Adapters | `tests/upstream/mqtt_live_broker.rs::should_round_trip_via_mqtt5_adapters` |

### MqttTlsLiveBrokerIntegrationTest (3)

| Test | Where |
|---|---|
| correctCredentialsShouldAuthenticateAndDeliverViaSecuredBroker | `tests/upstream/mqtt_live_broker.rs::correct_credentials_should_authenticate_and_deliver_via_secured_broker` |
| wrongPasswordShouldBeRejectedBySecuredBroker | `tests/upstream/mqtt_live_broker.rs::wrong_password_should_be_rejected_by_secured_broker` |
| anonymousConnectionShouldBeRejectedBySecuredBroker | `tests/upstream/mqtt_live_broker.rs::anonymous_connection_should_be_rejected_by_secured_broker` |

### MqttTlsHandshakeLiveBrokerIntegrationTest (2)

| Test | Where |
|---|---|
| trustingClientShouldCompleteTlsHandshakeAndDeliverViaSecuredBroker | `tests/upstream/mqtt_live_broker.rs::trusting_client_should_complete_tls_handshake_and_deliver_via_secured_broker` |
| clientNotTrustingBrokerCertShouldFailTlsHandshake | `tests/upstream/mqtt_live_broker.rs::client_not_trusting_broker_cert_should_fail_tls_handshake` |

### AmqpLiveBrokerIntegrationTest (7)

| Test | Where |
|---|---|
| shouldPublishToQueueBoundChannelViaLiveBroker | `tests/upstream/amqp_live_broker.rs::should_publish_to_queue_bound_channel_via_live_broker` |
| shouldPublishToExchangeWithRoutingKeyViaLiveBroker | `tests/upstream/amqp_live_broker.rs::should_publish_to_exchange_with_routing_key_via_live_broker` |
| shouldFailPublishWhenNoQueueIsBoundToExchange | `tests/upstream/amqp_live_broker.rs::should_fail_publish_when_no_queue_is_bound_to_exchange` |
| shouldSucceedOnceAQueueIsBoundToTheExchange | `tests/upstream/amqp_live_broker.rs::should_succeed_once_a_queue_is_bound_to_the_exchange` |
| orchestratorShouldPublishExampleToLiveBroker | `tests/upstream/amqp_live_broker.rs::orchestrator_should_publish_example_to_live_broker` |
| subscriberShouldRecordFromQueueBoundChannel | `tests/upstream/amqp_live_broker.rs::subscriber_should_record_from_queue_bound_channel` |
| subscriberShouldRecordFromExchangeRoutingKeyChannel | `tests/upstream/amqp_live_broker.rs::subscriber_should_record_from_exchange_routing_key_channel` |

### KafkaLiveBrokerIntegrationTest (4)

| Test | Where |
|---|---|
| shouldPublishAndConsumeMessageViaLiveKafkaBroker | `tests/upstream/kafka_live_broker.rs::should_publish_and_consume_message_via_live_kafka_broker` |
| shouldPublishWithKeyAndHeadersViaLiveBroker | `tests/upstream/kafka_live_broker.rs::should_publish_with_key_and_headers_via_live_broker` |
| subscriberShouldRecordMessagesFromLiveBroker | `tests/upstream/mqtt_live_broker.rs::subscriber_should_record_messages_from_live_broker` |
| orchestratorShouldPublishExamplesToLiveBroker | `tests/upstream/kafka_live_broker.rs::orchestrator_should_publish_examples_to_live_broker` |

### KafkaSecurityLiveBrokerIntegrationTest (2)

| Test | Where |
|---|---|
| credentialedPublisherReachesSaslBrokerAndMessageIsConsumable | `tests/upstream/kafka_live_broker.rs::credentialed_publisher_reaches_sasl_broker_and_message_is_consumable` |
| publisherWithWrongCredentialsIsRejectedBySaslBroker | `tests/upstream/kafka_live_broker.rs::publisher_with_wrong_credentials_is_rejected_by_sasl_broker` |

### KafkaAvroLiveBrokerIntegrationTest (3)

| Test | Where |
|---|---|
| shouldPublishConfluentFramedAvroReadableByPlainConsumer | `tests/upstream/kafka_live_broker.rs::should_publish_confluent_framed_avro_readable_by_plain_consumer` |
| shouldRoundTripAvroThroughMockServerAdapters | `tests/upstream/kafka_live_broker.rs::should_round_trip_avro_through_mock_server_adapters` |
| shouldNotDecodeMessageWrittenWithADifferentSchemaId | `tests/upstream/kafka_live_broker.rs::should_not_decode_message_written_with_a_different_schema_id` |

### AsyncApiControlPlaneLiveBrokerIntegrationTest (1)

| Test | Where |
|---|---|
| loadShouldConnectToLiveBrokerAndPublishOnLoad | `tests/upstream/kafka_live_broker.rs::load_should_connect_to_live_broker_and_publish_on_load` |
