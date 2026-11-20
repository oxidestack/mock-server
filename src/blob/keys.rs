//! `org.mockserver.state.BlobKeys`: the object-store key conventions of the cloud stores that apply a
//! `blobStoreKeyPrefix`. Prefix and key are joined with exactly one `/`, never a leading or doubled one (MinIO rejects
//! `//` with HTTP 400, and a leading `/` names a different object).

const SEPARATOR: char = '/';

/// `BlobKeys.join(keyPrefix, key)`: `("mockserver/", "/x.json")` is `mockserver/x.json`; an empty key keeps the
/// trailing separator, so `list("")` is scoped to the prefix.
pub fn join(key_prefix: &str, key: &str) -> String {
    let prefix = normalize_prefix(key_prefix);
    let key = normalize(key);
    if prefix.is_empty() {
        key
    } else if key.is_empty() {
        format!("{prefix}{SEPARATOR}")
    } else {
        format!("{prefix}{SEPARATOR}{key}")
    }
}

/// `BlobKeys.stripPrefix(keyPrefix, storeKey)`: the blob key of an object-store key; one without the prefix unchanged.
pub fn strip_prefix(key_prefix: &str, store_key: &str) -> String {
    let prefix = normalize_prefix(key_prefix);
    if prefix.is_empty() {
        return store_key.to_string();
    }
    if let Some(rest) = store_key.strip_prefix(&format!("{prefix}{SEPARATOR}")) {
        return rest.to_string();
    }
    if store_key == prefix {
        return String::new();
    }
    store_key.to_string()
}

/// `BlobKeys.forPersistedFile` for a store that is not the `FilesystemBlobStore`: the file name alone, normalised.
pub fn for_persisted_file(path: &str) -> String {
    let path = std::path::Path::new(path);
    normalize(&path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |n| n.to_string_lossy().into_owned()))
}

/// `BlobKeys.normalize`: drops a leading separator and collapses runs of them; a trailing one stays.
pub fn normalize(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    for c in key.chars() {
        if c == SEPARATOR && (normalized.is_empty() || normalized.ends_with(SEPARATOR)) {
            continue;
        }
        normalized.push(c);
    }
    normalized
}

/// `BlobKeys.normalizePrefix`: [`normalize`] without the trailing separators.
pub fn normalize_prefix(key_prefix: &str) -> String {
    normalize(key_prefix).trim_end_matches(SEPARATOR).to_string()
}

#[cfg(test)]
mod tests {
    //! `BlobKeysTest` (mockserver-core); a Java `null` prefix or key is the empty string here.

    use super::*;

    #[test]
    fn should_return_the_key_unchanged_when_no_prefix_is_configured() {
        assert_eq!(join("", "persistedExpectations.json"), "persistedExpectations.json");
    }

    #[test]
    fn should_insert_the_separator_when_the_prefix_has_no_trailing_slash() {
        assert_eq!(join("mockserver", "persistedExpectations.json"), "mockserver/persistedExpectations.json");
    }

    #[test]
    fn should_not_double_the_separator_when_the_prefix_ends_in_a_slash() {
        assert_eq!(join("mockserver/", "persistedExpectations.json"), "mockserver/persistedExpectations.json");
    }

    #[test]
    fn should_drop_a_leading_slash_on_the_prefix() {
        assert_eq!(join("/mockserver/", "persistedExpectations.json"), "mockserver/persistedExpectations.json");
        assert_eq!(join("/mockserver", "persistedExpectations.json"), "mockserver/persistedExpectations.json");
    }

    #[test]
    fn should_collapse_repeated_separators_inside_the_prefix() {
        assert_eq!(join("mockserver//nested///", "persistedExpectations.json"), "mockserver/nested/persistedExpectations.json");
    }

    #[test]
    fn should_keep_a_multi_segment_prefix_intact() {
        assert_eq!(join("team/mockserver/ci", "persistedExpectations.json"), "team/mockserver/ci/persistedExpectations.json");
    }

    #[test]
    fn should_drop_a_leading_slash_on_the_key() {
        assert_eq!(join("mockserver/", "/var/folders/tmp/persistedExpectations.json"), "mockserver/var/folders/tmp/persistedExpectations.json");
        assert_eq!(join("", "/var/folders/tmp/persistedExpectations.json"), "var/folders/tmp/persistedExpectations.json");
    }

    #[test]
    fn should_never_produce_a_leading_or_doubled_separator_for_any_prefix_shape() {
        for prefix in ["", "mockserver", "mockserver/", "/mockserver", "/mockserver/", "//mockserver//"] {
            for key in ["persistedExpectations.json", "/persistedExpectations.json", "/var/tmp/persistedExpectations.json", "a//b"] {
                let joined = join(prefix, key);
                assert!(!joined.starts_with('/'), "prefix={prefix} key={key}: {joined}");
                assert!(!joined.contains("//"), "prefix={prefix} key={key}: {joined}");
            }
        }
    }

    #[test]
    fn should_scope_an_empty_key_to_the_prefix_folder() {
        assert_eq!(join("mockserver", ""), "mockserver/");
        assert_eq!(join("mockserver/", ""), "mockserver/");
        assert_eq!(join("", ""), "");
    }

    #[test]
    fn should_preserve_a_trailing_separator_on_a_listing_prefix() {
        assert_eq!(join("mockserver", "expectations/"), "mockserver/expectations/");
    }

    #[test]
    fn should_strip_the_prefix_whatever_its_shape() {
        assert_eq!(strip_prefix("mockserver/", "mockserver/persistedExpectations.json"), "persistedExpectations.json");
        assert_eq!(strip_prefix("mockserver", "mockserver/persistedExpectations.json"), "persistedExpectations.json");
        assert_eq!(strip_prefix("/mockserver/", "mockserver/persistedExpectations.json"), "persistedExpectations.json");
        assert_eq!(strip_prefix("", "persistedExpectations.json"), "persistedExpectations.json");
    }

    #[test]
    fn should_round_trip_every_joined_key_back_to_the_original_key() {
        for prefix in ["", "mockserver", "mockserver/", "/mockserver/", "team/ci/"] {
            let joined = join(prefix, "expectations/persistedExpectations.json");
            assert_eq!(strip_prefix(prefix, &joined), "expectations/persistedExpectations.json", "prefix={prefix}");
        }
    }

    #[test]
    fn should_leave_a_key_that_does_not_carry_the_prefix_unchanged() {
        assert_eq!(strip_prefix("mockserver/", "somethingelse/persistedExpectations.json"), "somethingelse/persistedExpectations.json");
    }

    #[test]
    fn should_use_the_file_name_alone_as_the_key_for_a_cloud_store() {
        assert_eq!(for_persisted_file("/var/mockserver/persistedExpectations.json"), "persistedExpectations.json");
    }

    #[test]
    fn should_use_the_file_name_alone_even_for_a_relative_persistence_path() {
        assert_eq!(for_persisted_file("target/persistedExpectations.json"), "persistedExpectations.json");
    }
}
