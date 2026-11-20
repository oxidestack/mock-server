# Import test coverage

Where each `@Test` of upstream's importer unit tests (mockserver-core 8.0.0, in-JVM) is checked against
`PUT /mockserver/import`, `/mockserver/pact/import` and `/mockserver/recordings/promote`. These tests call the
importer classes directly, so none of them runs unmodified. "Scenario" means an oracle scenario in
`tests/scenarios/<name>.json`, cited by step note or fixture; "port" means `tests/upstream/<file>.rs::<fn>`; "unit"
means a Rust unit test. "HTTP n/a" marks a Java-API case that an HTTP body cannot produce (a `null` argument); the
nearest HTTP case is named.

Every importer call of the `imports` test classes at the oracle's revision (including the tests
added after 8.0.0) is also harvested as kind `importer`: `tests/scenarios/upstream/B4-importer-<Class>.json`, one
`PUT /mockserver/import` per call. The tables below are the
hand-written cases of 8.0.0's tests.

## HarImporterTest (14)

| Test | Where |
|---|---|
| importsTwoEntriesAsExpectations | `w2_import_har` "har with redaction" (fixture `import/har.json`) |
| firstEntryHasCorrectMethodPathAndQuery | `w2_import_har` "har with redaction", entry `/users?page=1&limit=10` |
| firstEntryFiltersVolatileRequestHeaders | same step (Date, User-Agent, Accept dropped; X-Api-Key redacted) |
| firstEntryHasCorrectResponseStatusAndBody | same step |
| firstEntryFiltersVolatileResponseHeaders | same step (Date, X-Request-Id, Set-Cookie dropped) |
| secondEntryHasPostBodyAndCorrectResponse | same step, entry `POST /users` |
| decodesBase64ResponseBody | same step, entry `/search` (`encoding: base64`), and the data-plane step that answers `hello world` |
| usesHarQueryStringArrayWhenPresent | same step, entry `/search` (`queryString` replaces the URL's query) |
| toleratesMissingOptionalFields | same step, entries without method, without response, without status |
| throwsOnNullInput | HTTP n/a; `w2_import_har_errors` "empty body", "blank body" |
| throwsOnBlankInput | `w2_import_har_errors` "blank body" |
| throwsOnMalformedJson | `w2_import_malformed` "malformed har" (three documents) |
| throwsOnMissingLogObject | `w2_import_har_errors` "not an object" |
| returnsEmptyListForEmptyEntriesArray | `w2_import_har_errors` "empty entries" |

## PostmanCollectionImporterTest (14)

| Test | Where |
|---|---|
| importsCorrectNumberOfExpectations | `w2_import_postman` "postman" (fixture `import/postman.json`) |
| everyExpectationHasAUniqueId | same step (`postman-<index>-<slug>`, two examples of one request) |
| firstExampleHasCorrectRequestMatcher | same step, and the data-plane step that matches it |
| firstExampleHasCorrectResponse | same step |
| secondExampleIs404Response | same step, example `missing` |
| healthCheckRequestUsesUrlAsString | same step, item "Create order" (string `url`) |
| skipsRequestsWithoutExamplesWithCount | same step, item "No examples" (the count is only logged upstream, at debug) |
| handlesUrlAsObjectWithPathArray | same step, item "Get User (by id)" |
| handlesRequestWithBodyInPostRequest | same step, item "Create order" (`body.raw`) |
| throwsOnNullInput | HTTP n/a; `w2_import_har_errors` "empty body" |
| throwsOnBlankInput | `w2_import_har_errors` "blank body" |
| throwsOnMalformedJson | `w2_import_malformed` "malformed postman" |
| throwsOnMissingInfoObject | `w2_import_har_errors` "postman without info" |
| returnsEmptyForCollectionWithNoExamples | `w2_import_har_errors` "auto-detect postman" |

## WireMockImporterTest (13)

| Test | Where |
|---|---|
| importsExactPathMethodHeadersQueryAndJsonBody | `w2_import_wiremock` "wiremock mappings" (upstream `WIREMOCK_MAPPINGS`, `import/wiremock_mappings.json`) |
| mapsScenarioAndInvertedPriority | same step, stub `get-user` |
| priorityOneStubOutranksUnspecifiedPriorityStub | `w2_import_upstream_fixtures` "WireMockImporterTest.priorityOneStubOutranksUnspecifiedPriorityStub" and its two data-plane steps |
| mapsUrlPatternToPathRegexDroppingQueryPortionWithWarning | `w2_import_wiremock` "wiremock mappings", stub 1 |
| mapsFaultToConnectionDrop | same step, stub `/api/flaky` |
| mapsProxyBaseUrlToForward | same step, stub `/api/legacy` |
| warnsOnMatchesXPathBodyAndResponseTransformers | same step, stub `/api/xml` |
| supportsSingleStubForm | `w2_import_upstream_fixtures` "…supportsSingleStubForm" |
| supportsBareArrayForm | `w2_import_upstream_fixtures` "…supportsBareArrayForm" |
| decodesBase64Body | `w2_import_upstream_fixtures` "…decodesBase64Body" |
| dropsAnyMethodMatcher | `w2_import_upstream_fixtures` "…dropsAnyMethodMatcher" |
| cleanImportHasNoWarnings | `w2_import_upstream_fixtures` "…cleanImportHasNoWarnings" |
| rejectsBlankAndInvalidInput | `w2_import_har_errors` "wiremock nothing"; `w2_import_malformed` "malformed wiremock" |

## MountebankImporterTest (13)

| Test | Where |
|---|---|
| skipsNonHttpImposterWithWarning | `w2_import_mountebank` "mountebank imposters" (upstream `MOUNTEBANK`, the tcp imposter) |
| mapsEqualsAndDeepEqualsAndMatchesPredicates | same step, stub 0 |
| mapsIsResponseWithWaitDelayAndDropsSingleResponseRepeat | same step, stub 0 (`wait`, `repeat`) |
| mapsContainsBodyAndProxyResponse | same step, stub 1 |
| mapsMultipleIsResponsesToSequentialCycle | same step, stub 2, and the two `/cycle` data-plane steps |
| mapsFaultToConnectionDrop | same step, stub 3 |
| warnsAndPlaceholdsInjectResponse | same step, stub 4 |
| mapsExistsHeaderPredicateToPresenceMatcher | same step, stub 1 (`exists`) |
| producesFiveExpectationsFromHttpImposter | same step |
| warnsThatExactPredicatesBecomeCaseSensitiveAndMakesRegexPredicatesCaseInsensitive | `w2_import_upstream_fixtures`, both fixtures of that test |
| warnsOnCompoundPredicate | `w2_import_upstream_fixtures` "…warnsOnCompoundPredicate" |
| supportsSingleImposterForm | `w2_import_upstream_fixtures` "…supportsSingleImposterForm" |
| rejectsBlankAndInvalidInput | `w2_import_har_errors` "mountebank nothing"; `w2_import_malformed` "malformed mountebank" |

## MockoonImporterTest (11)

| Test | Where |
|---|---|
| mapsSingleResponseRouteWithParamPathHeadersBodyLatency | `w2_import_mockoon` "mockoon environment" (upstream `MOCKOON`), route `route-user`, and `GET /users/7` |
| escapesLiteralPathSegmentsSoDotDoesNotMatchAnyCharacter | `w2_import_upstream_fixtures` "…escapesLiteralPathSegments…" and its two data-plane steps |
| warnsWhenQueryRuleHasNoModifier | `w2_import_upstream_fixtures` "…warnsWhenQueryRuleHasNoModifier" |
| rulesBasedRouteEmitsOneExpectationPerResponseWithPriority | `w2_import_mockoon` "mockoon environment", route `route-search`, and the two `/search` data-plane steps |
| mapsSequentialResponseMode | same step, route `route-seq` |
| mapsRandomResponseMode | same step, route `route-rand` |
| warnsOnCookieRuleNullOperatorAndCrudRoute | same step, routes `route-warn`, `route-crud` |
| crudRouteProducesNoExpectation | same step, route `route-crud` |
| warnsOnHandlebarsTemplateBody | `w2_import_upstream_fixtures` "…warnsOnHandlebarsTemplateBody" |
| cleanSingleRouteHasNoWarnings | `w2_import_upstream_fixtures` "…cleanSingleRouteHasNoWarnings" |
| rejectsBlankAndInvalidInput | `w2_import_har_errors` "mockoon nothing"; `w2_import_malformed` "malformed mockoon" |

## RecordedTrafficImporterTest (8)

| Test | Where |
|---|---|
| shouldParseMultipleNdjsonPairsForwardedAndMocked | `w2_import_recording` "recording archive" |
| shouldSkipBlankLines | `w2_import_recording_lines` "shouldSkipBlankLines" |
| shouldRedactSensitiveDataByDefault | `w2_import_recording` "recording archive" (Authorization, `key`, `token`, Set-Cookie) |
| shouldReturnEmptyForBlankArchive | port `recorded_traffic_reimport.rs::should_return_empty_for_empty_disk_archive` (a blank body reads the disk archive: `w2_import_recording_lines` "blank archive in the body reads the disk archive") |
| shouldSkipTruncatedTrailingLineAndImportTheRest | `w2_import_recording` "recording archive" (truncated last line, skipped-lines header) |
| shouldSkipMalformedLineInTheMiddleAndImportTheRest | `w2_import_recording_lines` "shouldSkipMalformedLineInTheMiddleAndImportTheRest"; logged skips in `w2_import_recording_logs` |
| shouldThrowWhenNoLineParses | `w2_import_har_errors` "recording garbage" |
| shouldRoundTripFromPersistenceSerializer | `w2_import_recording_lines` "shouldRoundTripFromPersistenceSerializer" |

## RecordedTrafficReimportHttpStateTest (6)

Ports in `tests/upstream/recorded_traffic_reimport.rs` (in-process server with its own `persistedRecordedRequestsPath`,
which a scenario cannot give the oracle container):

| Test | Port |
|---|---|
| shouldReimportArchiveFromRequestBodyAndMakeItRetrievable | `should_reimport_archive_from_request_body_and_make_it_retrievable` |
| shouldReimportArchiveFromDiskWhenSourceIsDisk | `should_reimport_archive_from_disk_when_source_is_disk` |
| shouldRedactSensitiveDataOnReimportByDefault | `should_redact_sensitive_data_on_reimport_by_default` |
| shouldReturnBadRequestWhenDiskArchiveMissing | `should_return_bad_request_when_disk_archive_missing` (also scenario `w2_import_har_errors`) |
| shouldReturnEmptyForEmptyDiskArchive | `should_return_empty_for_empty_disk_archive` |
| shouldRecoverIntactExchangesFromTruncatedDiskArchive | `should_recover_intact_exchanges_from_truncated_disk_archive` |

## ImportRedactionTest (15)

| Test | Where |
|---|---|
| harRedactsSensitiveRequestHeaderByDefault | `w2_import_har` "har with redaction" (X-Api-Key) |
| harRedactsSensitiveRequestBodyFieldByDefault | same step (`access_token` nested in the POST body) |
| harRedactsSensitiveResponseHeaderByDefault | `w2_import_har` "auto-detected, extra redaction" (Set-Cookie is volatile for HAR, so an added header shows the masking) |
| harRedactsSensitiveResponseBodyFieldByDefault | `w2_import_har` "har with redaction" (`password`, SSE `token`, the fail-closed truncated body) |
| harPreservesNonSensitiveHeader | same step (X-Custom, X-Tenant) |
| harPreservesExpectationIdAfterRedaction | same step (`har-N`), and "upsert by id keeps har-N" |
| harOptOutKeepsOriginalSecrets | `w2_import_har` "har verbatim" |
| harHonoursAdditionalSensitiveHeaderAndBodyField | `w2_import_har` "auto-detected, extra redaction" |
| postmanRedactsSensitiveRequestHeaderByDefault | `w2_import_postman` "postman" (X-Api-Key) |
| postmanRedactsSensitiveRequestBodyFieldByDefault | same step (`clientSecret`) |
| postmanRedactsSensitiveResponseHeaderByDefault | same step (Set-Cookie) |
| postmanRedactsSensitiveResponseBodyFieldByDefault | same step (`apiKey`) |
| postmanPreservesNonSensitiveHeader | same step (Accept, X-Name) |
| postmanPreservesExpectationIdAfterRedaction | same step |
| postmanOptOutKeepsOriginalSecrets | `w2_import_postman` "postman verbatim" |

## PactImporterTest (19)

| Test | Where |
|---|---|
| importsTwoInteractionsAsTwoExpectations | `w2_import_pact` "pact" (fixture `import/pact.json`) |
| importedExpectationMatchesDocumentedRequest | `w2_import_pact_unit` "importedExpectationMatchesDocumentedRequest" and the `GET /users/1` step |
| regexMatchingRuleOnPathMapsToRegexMatcherValue | `w2_import_pact_unit` step of that name |
| typeMatchingRuleOnHeaderRelaxesToPresenceRegex | `w2_import_pact_unit` step of that name |
| includeMatchingRuleOnQueryMapsToSubstringRegex | `w2_import_pact_unit` step of that name |
| redactionMasksSensitiveHeadersByDefault | `w2_import_pact_unit` step of that name |
| roundTripExportThenImportYieldsMatchingExpectations | `w2_import_pact_round_trip` (export captured, imported, then matched) |
| regexAndSchemaMatchersRoundTripThroughExportThenImport | `w2_import_pact_round_trip` (numeric id matches, non-numeric does not) |
| jsonRequestBodyMatchesRegardlessOfKeyOrder | `w2_import_pact_unit` step of that name and the reordered-body request |
| stringRequestBodyKeptAsExactStringMatch | `w2_import_pact_unit` step of that name |
| shortFieldNameDoesNotFalseMatchLongerRuleKey | `w2_import_pact_unit` step of that name |
| rejectsContractWithNoInteractions | `w2_import_har_errors` "pact without interactions", "pact empty interactions" |
| rejectsBlankBody | `w2_import_pact` "pact import empty" |
| rejectsMalformedJson | `w2_import_malformed` "malformed pact", "pact import malformed" |
| importsV3ProviderStateAsScenarioGate | `w2_import_pact` "pact" and the gated / activated requests |
| importsV2ProviderStateAsScenarioGate | `w2_import_pact_unit` step of that name |
| statelessInteractionHasNoScenarioGate | `w2_import_pact_unit` step of that name |
| providerStatePreservedThroughRedaction | `w2_import_pact_unit` step of that name |
| providerStateRoundTripsThroughExportThenImport | `w2_import_pact_round_trip` (gated until the state is set) |

## RecordedExpectationPostProcessorTest (23)

`consolidate` (import `?consolidate`/`?parameterize`, promotion, and `retrieve?type=RECORDED_EXPECTATIONS&consolidate=true`
or `&parameterize=true`: `recorded_expectations_consolidate`):

| Test | Where |
|---|---|
| shouldConsolidateFiftyIdenticalHitsToOneUnlimitedExpectation | `w2_import_consolidate_equality` "shouldConsolidateFiftyIdenticalHitsToOneUnlimitedExpectation" |
| shouldParameterizeVaryingPathSegmentAcrossManyIds | `w2_import_consolidate` "har consolidated"; `w2_import_recording` "promote consolidated and parameterized" |
| shouldStripVolatileRequestHeaders | `w2_import_consolidate` "har consolidated" (Accept); `w2_import_promote` |
| shouldSequenceDifferingResponsesForSameRequestShape | `w2_import_consolidate` "har consolidated" (`/users/1` twice); `w2_import_consolidate_equality` |
| shouldParameterizeVolatileValuesWhenFlagSet | `w2_import_consolidate` "har parameterized" |
| shouldPassThroughIneligibleAndReturnEmptyForNull | `w2_import_consolidate` "migration import consolidated" (forward and error actions pass through); an empty list: `w2_import_recording` "promote with filter matching nothing" |

`deduplicateAndTemplatize` (`retrieve?type=RECORDED_EXPECTATIONS` under the startup properties
`deduplicateRecordedExpectations` / `templatizeRecordedValues`). Each test is ported as the unit
`import::consolidate::tests::<name>`; the scenarios import `import/recording_dedup.ndjson` and retrieve it in JSON,
Java, HAR, OpenAPI and Postman:

| Test | Scenario | Unit |
|---|---|---|
| shouldTemplatizeNumericIdSegmentsToSingleExpectation | `recorded_expectations_dedup` "deduplicated" (`/users/1..3` → `/users/{id}`) | `should_templatize_numeric_id_segments_to_single_expectation` |
| shouldTemplatizeUuidSegments | `recorded_expectations_dedup` "deduplicated" (`/orders/<uuid>` twice) | `should_templatize_uuid_segments` |
| shouldNotMergeGenuinelyDifferentPaths | `recorded_expectations_dedup` "deduplicated" (`/users`, `/orders`, `/accounts`, …) | `should_not_merge_genuinely_different_paths` |
| shouldNotMergeDifferentMethodsUnderSameTemplate | `recorded_expectations_dedup` "deduplicated" (`DELETE /users/9`) | `should_not_merge_different_methods_under_same_template` |
| shouldNotCollapseDifferingResponsesUnderOneTemplate | `recorded_expectations_dedup` "deduplicated" (`/items/1..3`, three responses) | `should_not_collapse_differing_responses_under_one_template` |
| shouldPreserveOriginalOrderWithMixedEligibleAndIneligible | `recorded_expectations_dedup` "deduplicated" (`/forward/path`, no response, after `/users/{id}`) | `should_preserve_original_order_with_mixed_eligible_and_ineligible` |
| shouldNotOverWidenSingleIdPartitionWhenGroupSpansMultipleIds | `recorded_expectations_dedup` "deduplicated" (`/carts/{id}` 200, `/carts/1` 404) | `should_not_over_widen_single_id_partition_when_group_spans_multiple_ids` |
| shouldDeduplicateExactDuplicatesToOne | `recorded_expectations_dedup` "deduplicated" (`/health` three times) | `should_deduplicate_exact_duplicates_to_one` |
| shouldNotTemplatizeSingleRecordedIdWithNoOtherIds | `recorded_expectations_dedup` "deduplicated" (`/accounts/1`) | `should_not_templatize_single_recorded_id_with_no_other_ids` |
| shouldPassThroughNonHttpRequestExpectationsUnchanged | `recorded_expectations_dedup` "deduplicated" (`/forward/path`) | `should_pass_through_non_http_request_expectations_unchanged` |
| shouldReturnEmptyListForNullOrEmptyInput | HTTP n/a (`null`); an empty list: unit | `should_return_empty_list_for_null_or_empty_input` |
| shouldNotTemplatizeValuesWhenFlagOff | `recorded_expectations_dedup` "deduplicated" (`/widgets?traceId=<uuid>` kept) | `should_not_templatize_values_when_flag_off` |
| shouldTemplatizeVolatileQueryParameterValue | `recorded_expectations_dedup_values` "deduplicated and templatized" (`traceId` → `.+`, `page` kept) | `should_templatize_volatile_query_parameter_value` |
| shouldTemplatizeVolatileHeaderValuesAndByVolatileHeaderName | `recorded_expectations_dedup_values` "deduplicated and templatized" (Authorization, X-Request-Id → `.+`; Accept kept) | `should_templatize_volatile_header_values_and_by_volatile_header_name` |
| shouldTemplatizeVolatileJsonBodyLeavesAndPreserveStableOnes | `recorded_expectations_dedup_values` "deduplicated and templatized" (`POST /orders`, `POST /raw`) | `should_templatize_volatile_json_body_leaves_and_preserve_stable_ones` |
| shouldLeaveStableValuesAndNonJsonBodyUntouched | `recorded_expectations_dedup_values` "deduplicated and templatized" (`POST /notes`) | `should_leave_stable_values_and_non_json_body_untouched` |
| volatilityHeuristicClassifiesValuesConservatively | unit only (a pure predicate) | `volatility_heuristic_classifies_values_conservatively` |

Response equality (`LinkedHashSet<HttpResponse>`) and binary request bodies that never group are checked in
`w2_import_consolidate_equality`.
