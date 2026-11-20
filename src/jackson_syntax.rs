//! Jackson's wording for JSON that `ObjectMapperFactory`'s mapper cannot read.
//!
//! [`syntax_error`] / [`map_failure`] are `ObjectMapper.readValue(bytes, Map.class)`, as
//! `ConfigurationProperties.readJsonPropertyFile` reads a JSON property file: a port of the byte parser
//! (`utf8`), with Jackson's class, message and `[Source: REDACTED ..; line: L, column: C]` location.
//! Text Jackson reads from a `String` (`readTree(String)`, `ReaderBasedJsonParser`) is worded by the ported parser
//! (`crate::jnode::syntax_failure`). The mapper accepts comments, single quotes, unquoted names, trailing commas,
//! leading zeros and anything after the root value (`crate::json::parse_lenient`). Lines count only the newlines the
//! parser skips as white space, so one inside a string does not move the line; columns count bytes.

mod utf8;

/// The exception text `readValue(bytes, Map.class)` logs for `bytes` (`class: message`, a newline, then
/// ` at <location>`), or `None` when they read as a map or as a root `null`.
pub fn map_failure(bytes: &[u8]) -> Option<String> {
    utf8::map_failure(bytes).map(|f| f.render())
}

/// [`map_failure`] for text.
pub fn syntax_error(text: &str) -> Option<String> {
    map_failure(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::syntax_error;

    #[test]
    fn names_the_recorded_failures() {
        let at = |l: usize, c: usize| format!("[Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {l}, column: {c}]");
        assert_eq!(
            syntax_error("{\"a\": [1,2}\n").unwrap(),
            format!("shaded_package.com.fasterxml.jackson.core.JsonParseException: Unexpected close marker '}}': expected ']' (for Array starting at {})\n at {}", at(1, 7), at(1, 11))
        );
        assert_eq!(
            syntax_error("\n  {\"a\" 1}\n").unwrap(),
            format!("shaded_package.com.fasterxml.jackson.core.JsonParseException: Unexpected character ('1' (code 49)): was expecting a colon to separate field name and value\n at {}", at(2, 8))
        );
        assert_eq!(
            syntax_error("{\"a\": \"x\"\n").unwrap(),
            format!("shaded_package.com.fasterxml.jackson.core.io.JsonEOFException: Unexpected end-of-input: expected close marker for Object (start marker at {})\n at {}", at(1, 1), at(2, 1))
        );
        assert!(syntax_error("{\"a\": 1}").is_none());
    }

    #[test]
    fn names_the_shapes_the_oracle_recorded() {
        // each recorded on the oracle (tests/process_scenarios/propfile3_json_error_*.json)
        let message = |text: &str| syntax_error(text).unwrap();
        assert!(message("{").contains("JsonEOFException: Unexpected end-of-input: expected close marker for Object (start marker at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 1])\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 2]"));
        assert!(message("{\"a\": [").contains("close marker for Array") && message("{\"a\": [").ends_with("column: 8]"));
        assert!(message("{\"abc").contains("JsonEOFException: Unexpected end-of-input in field name") && message("{'abc").ends_with("column: 6]"));
        assert!(message("{\"a\": [1,}").contains("Unexpected close marker '}': expected ']' (for Array starting at") && message("{\"a\": [1,}").ends_with("column: 10]"));
        assert!(message("'x'").contains("String value ('x')"));
        for root in ["+Infinity", "-Infinity", "NaN", "Infinity"] {
            assert!(message(root).contains("from Floating-point value (token `JsonToken.VALUE_NUMBER_FLOAT`)"), "{root}");
        }
    }
}


/// The differential vectors recorded from the oracle image (`conformance/jackson-syntax/JacksonSyntaxVectors.java`): each input read as a JSON property file (`map`) and as a `mockserver import` file (`tree`).
#[cfg(test)]
mod vectors {
    /// A vector: its name, its input, and what each reader makes of it.
    type Vector = (String, Vec<u8>, Option<String>, Option<String>);

    fn vectors() -> Vec<Vector> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/jackson-syntax");
        let inputs = std::fs::read_to_string(format!("{dir}/inputs.txt")).unwrap();
        let recorded: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/vectors.json")).unwrap()).unwrap();
        let hex = |h: &str| (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>();
        let lines: Vec<&str> = inputs.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), recorded.len(), "vectors.json is stale: re-record it from inputs.txt");
        lines
            .iter()
            .zip(recorded)
            .map(|(line, v)| {
                let (name, bytes) = line.split_once(' ').unwrap_or((line, ""));
                assert_eq!(v["name"], *name, "vectors.json is stale: re-record it from inputs.txt");
                (name.to_string(), hex(bytes), v["map"].as_str().map(str::to_string), v["tree"].as_str().map(str::to_string))
            })
            .collect()
    }

    #[test]
    fn a_json_property_file_fails_as_the_oracle_words_it() {
        let wrong: Vec<String> = vectors()
            .into_iter()
            .filter_map(|(name, bytes, map, _)| {
                let ours = crate::property_file::read_json(&bytes).err();
                (ours != map).then(|| format!("{name}:\n  oracle: {map:?}\n  ours:   {ours:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{} of the vectors differ:\n{}", wrong.len(), wrong.join("\n"));
    }

    #[test]
    fn an_import_file_fails_as_the_oracle_words_it() {
        let wrong: Vec<String> = vectors()
            .into_iter()
            .filter_map(|(name, bytes, _, tree)| {
                let ours = crate::cli::import_syntax_error(&String::from_utf8_lossy(&bytes));
                (ours != tree).then(|| format!("{name}:\n  oracle: {tree:?}\n  ours:   {ours:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{} of the vectors differ:\n{}", wrong.len(), wrong.join("\n"));
    }
}
