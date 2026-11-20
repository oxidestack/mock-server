//! Expectations recorded from `Pattern.compile` on the oracle's JDK 26 (through MCP `create_llm_conversation`).

use super::{check, compile, translate};

fn message(pattern: &str) -> String {
    check(pattern).err().map(|e| e.to_string()).unwrap_or_else(|| "OK".into())
}

#[test]
fn syntax_errors_are_worded_and_placed_as_pattern_does() {
    let cases = [
        ("a{2,1}", "Illegal repetition range near index 5\na{2,1}\n     ^"),
        ("a{2", "Unclosed counted closure near index 3\na{2"),
        ("a{", "Illegal repetition near index 2\na{"),
        ("{a}", "Illegal repetition near index 1\n{a}\n ^"),
        ("a{,3}", "Illegal repetition near index 2\na{,3}\n  ^"),
        ("a{99999999999}", "Illegal repetition range near index 11\na{99999999999}\n           ^"),
        ("\\y", "Illegal/unsupported escape sequence near index 1\n\\y\n ^"),
        ("a\\", "Unescaped trailing backslash near index 2\na\\"),
        ("(?y)", "Unknown inline modifier near index 2\n(?y)\n  ^"),
        ("(?<x", "named capturing group is missing trailing '>' near index 4\n(?<x"),
        ("(?<x>a)(?<x>b)", "Named capturing group <x> is already defined near index 11\n(?<x>a)(?<x>b)\n           ^"),
        ("\\k<y>", "named capturing group <y> does not exist near index 4\n\\k<y>\n    ^"),
        ("\\k", "\\k is not followed by '<' for named capturing group near index 2\n\\k"),
        ("(?<1x>a)", "capturing group name does not start with a Latin letter near index 3\n(?<1x>a)\n   ^"),
        ("\\p{L", "Unclosed character family near index 4\n\\p{L"),
        ("\\p{Foo}", "Unknown character property name {Foo} near index 6\n\\p{Foo}\n      ^"),
        ("\\p{IsFoo}", "Unknown character property name {IsFoo} near index 8\n\\p{IsFoo}\n        ^"),
        ("\\p{InFoo}", "Unknown character property name {InFoo} near index 8\n\\p{InFoo}\n        ^"),
        ("\\p{javaFoo}", "Unknown character property name {javaFoo} near index 10\n\\p{javaFoo}\n          ^"),
        ("\\p{gc=Foo}", "Unknown Unicode property {name=<gc>, value=<Foo>} near index 9\n\\p{gc=Foo}\n         ^"),
        ("\\p{block=Foo}", "Unknown Unicode property {name=<block>, value=<Foo>} near index 12\n\\p{block=Foo}\n            ^"),
        ("\\x{110000}", "Hexadecimal codepoint is too big near index 8\n\\x{110000}\n        ^"),
        ("\\x{12", "Unclosed hexadecimal escape sequence near index 5\n\\x{12"),
        ("\\xZ1", "Illegal hexadecimal escape sequence near index 2\n\\xZ1\n  ^"),
        ("\\0", "Illegal octal escape sequence near index 2\n\\0"),
        ("\\08", "Illegal octal escape sequence near index 2\n\\08\n  ^"),
        ("\\c", "Illegal control escape sequence near index 1\n\\c\n ^"),
        ("\\u12", "Illegal Unicode escape sequence near index 4\n\\u12"),
        ("\\N{FOO}", "Unknown character name [FOO] near index 6\n\\N{FOO}\n      ^"),
        ("[a-", "Illegal character range near index 3\n[a-"),
        ("[a-\\d]", "Illegal character range near index 4\n[a-\\d]\n    ^"),
        ("[z-a]", "Illegal character range near index 3\n[z-a]\n   ^"),
        ("x[b-a]y", "Illegal character range near index 4\nx[b-a]y\n    ^"),
        ("\u{e9}[z-a]", "Illegal character range near index 4\n\u{e9}[z-a]\n    ^"),
        ("(?", "Unknown inline modifier near index 2\n(?"),
        ("(?<", "capturing group name does not start with a Latin letter near index 3\n(?<"),
        ("(?P<x>a)", "Unknown inline modifier near index 2\n(?P<x>a)\n  ^"),
        ("(?i", "Unknown inline modifier near index 3\n(?i"),
        ("\\b{x}", "Illegal repetition near index 3\n\\b{x}\n   ^"),
        (")", "Unmatched closing ')'\n)"),
        ("a)b)", "Unmatched closing ')' near index 0\na)b)\n^"),
        ("?", "Dangling meta character '?' near index 0\n?\n^"),
        ("+a", "Dangling meta character '+' near index 0\n+a\n^"),
        ("*a", "Dangling meta character '*' near index 0\n*a\n^"),
        ("a**", "Dangling meta character '*' near index 2\na**\n  ^"),
        ("([", "Unclosed character class near index 1\n([\n ^"),
        ("(", "Unclosed group near index 1\n("),
        ("[a", "Unclosed character class near index 1\n[a\n ^"),
        ("[a-z&&[^e]", "Unclosed character class near index 9\n[a-z&&[^e]\n         ^"),
        ("[a&&", "Unclosed character class near index 3\n[a&&\n   ^"),
        ("(?<=a(b|c)*)", "Look-behind group does not have an obvious maximum length near index 10\n(?<=a(b|c)*)\n          ^"),
        ("a{1}{", "Illegal repetition near index 5\na{1}{"),
    ];
    for (pattern, expected) in cases {
        assert_eq!(message(pattern), expected, "{pattern}");
    }
}

#[test]
fn java_only_syntax_compiles() {
    for pattern in [
        "a*+", "a++b", "a?+", "a{2}+", "a{2,3}+", "\\p{javaLowerCase}", "\\p{javaUpperCase}+", "\\p{IsjavaLowerCase}", "\\p{javaWhitespace}",
        "\\p{javaMirrored}", "[a-z&&[^e]]", "[a-z&&[def]]", "[a-z&&]", "[&&a]", "[a&&&b]", "[[a-c][x-z]]", "[a-c[x-z]]", "(?<=a*)", "(?<=a+b)",
        "(?<=a{1,3})", "\\N{LATIN SMALL LETTER A}", "[]a]", "[^]a]", "(?i)a", "(?u)(?U)(?d)(?x)(?s)(?m)(?c)", "\\R\\h\\H\\v\\V", "\\Ga",
        "a||b", "(a)\\2", "\\1", "x{1}{2}", "[\\Q]\\E]", "\\Qabc", "\\cA\\ca", "\\e\\a", "\\u0041", "\\uD83D\\uDE00", "[\\p{L}&&\\p{Lu}]",
        "\\p{Lu}\\p{IsLu}\\p{gc=Lu}\\p{general_category=Lu}\\p{IsLatin}\\p{script=Latin}\\p{InBasicLatin}\\p{block=BasicLatin}\\p{IsAlphabetic}\\p{Alpha}\\p{Punct}\\p{XDigit}\\p{L}\\P{L}\\pL",
        "\\p{IsEmoji}", "\\N{cjk unified ideographs 4E00}",
    ] {
        assert_eq!(message(pattern), "OK", "{pattern}");
        assert!(compile(pattern).is_ok_and(|r| r.regex.is_some()), "{pattern}: {:?}", translate(pattern));
    }
}

#[test]
fn grapheme_clusters_and_boundaries_are_walked() {
    // JDK 26's `Grapheme`: GB9c joins a conjunct, and `\b{g}` reads the cluster after `Matcher.last`.
    assert_eq!(message("\\R\\X\\b{g}"), "OK");
    let r = compile("^\\X$").expect("compiles");
    assert!(r.walk.is_some() && r.regex.is_none());
    assert!(r.find("\u{915}\u{94D}\u{937}"));
    assert!(compile("ab\\b{g}\u{301}").expect("compiles").find("ab\u{301}"));
    assert!(!compile("x{1}a\\b{g}\u{301}").expect("compiles").find("xa\u{301}"));
}

#[test]
fn every_construct_translates_to_a_buildable_regex() {
    for pattern in [
        "(?<=\\ba)b", "(?<!\\Bx)y", "(\\b)*a", "(?:\\b)+a", "(?=a)*a", "(?>a|b)*+c", "(a|b){2,3}?\\1", "(?i)(a)\\1", "(?x)[a #b\n c]+ # x",
        "(?m)^a$", "(?d)^a$.", "(?md)^a$", "\\Z\\z\\A", "\\b{g}a\\b{g}", "[\\x{1F600}-\\x{1F64F}&&[^\\x{1F610}]]", "\\P{javaLetter}", "[\\v-\\x{D}]",
        "(?U)\\p{Lower}\\p{Upper}\\p{Punct}\\p{Print}\\p{Graph}\\p{Blank}\\p{XDigit}\\B", "(?iu)[\\x{100}-\\x{17F}]ſ", "\\N{LINE FEED (LF)}",
    ] {
        assert_eq!(message(pattern), "OK", "{pattern}");
        // A case-insensitive back reference is walked (`engine`), not translated.
        assert!(compile(pattern).is_ok_and(|r| r.regex.is_some() || r.walk.is_some()), "{pattern}: {:?}", translate(pattern));
    }
}

#[test]
fn matching_follows_pattern_semantics() {
    let cases: &[(&str, &str, bool)] = &[
        ("a*+a", "aaa", false),
        ("^a++b$", "aab", true),
        ("^a?+a$", "a", false),
        ("^a{2,3}+a$", "aaaa", true),
        ("^x{1}{2}$", "x", true),
        ("^x{1}{2}$", "xx", false),
        ("^\\p{javaLowerCase}+$", "aBc", false),
        ("\\p{javaWhitespace}", "a\u{a0}b", false),
        ("\\p{javaWhitespace}", "a\u{2028}b", true),
        ("^[a-z&&[^e]]+$", "abe", false),
        ("^[a-z&&[def]]$", "e", true),
        ("^[a-z&&]$", "a", true),
        ("^[&&a]$", "&", false),
        ("^[a-c[x-z]&&[^b]]+$", "acx", true),
        ("(?<=a{1,3})b", "aab", true),
        ("^\\N{LATIN SMALL LETTER A}$", "a", true),
        ("^(?<x>a)\\k<x>(?<y>b)\\2$", "aabb", true),
        ("(a)\\2", "aa", false),
        ("^[]a]+$", "]a", true),
        ("^\\Qa(b\\E+$", "a(bb", true),
        ("^\\w+$", "\u{e9}", false),
        ("(?U)^\\w+$", "\u{e9}", true),
        ("^\\d$", "\u{663}", false),
        ("^.$", "\u{85}", false),
        ("(?s)^.$", "\n", true),
        ("^ab$", "ab\n", true),
        ("^ab$", "ab\n\n", false),
        ("(?m)^b$", "a\r\nb", true),
        ("(?i)^\u{e9}$", "\u{c9}", false),
        ("(?iu)^\u{e9}$", "\u{c9}", true),
        ("(?i)^[a-c]\\p{Lu}\\p{Lower}K$", "Bab\u{212a}", false),
        ("(?iu)^[a-c]K$", "b\u{212a}", true),
        ("^\\R$", "\u{2028}", true),
        ("\\bb", "\u{e9}b", true),
        ("\\bb", "ab", false),
        ("^\\p{InGreek}\\p{IsGreek}\\p{block=Latin-1 Supplement}\\p{sc=Latn}\\p{IsAlphabetic}\\p{Lower}$", "\u{3b1}\u{3b2}\u{e9}\u{e9}\u{e9}a", true),
        ("(?<=\\b)\\X$", "e\u{301}", true),
        ("^\\x{1F600}\\u0041\\0101\\cA\\e$", "\u{1F600}AA\u{1}\u{1b}", true),
        ("(?x) a b # comment", "a b", false),
        ("^(?>a|ab)c$", "abc", false),
        ("^(?<!x)y\\Z", "y\n", true),
        ("\\Ga", "ba", false),
        ("a||b", "c", true),
        ("(?i)(a)\\1", "aA", true),
        ("(?<=\\ba)b", "ab", true),
        ("(?<=\\ba)b", "cab", false),
        ("(?m)^", "", false),
        ("^", "", true),
        ("(?x)[a #b\n c]+ # x", "c", true),
        ("(?x)[a #b\n c]+ # x", "b", false),
        ("^\\N{LINE FEED (LF)}$", "\n", true),
    ];
    for (pattern, input, expected) in cases {
        let regex = compile(pattern).unwrap_or_else(|e| panic!("{pattern}: {e}"));
        assert_eq!(regex.find(input), *expected, "{pattern} over {input:?}: {:?}", translate(pattern));
    }
}

/// `Pattern.compile(p, flags)` and `matcher(input).matches()` as the matcher sites call them.
#[test]
fn flags_and_whole_input_matching() {
    use super::{compile_with_flags, CASE_INSENSITIVE, DOTALL, UNICODE_CASE};
    let ci = DOTALL | CASE_INSENSITIVE | UNICODE_CASE;
    assert!(compile_with_flags("a|ab", 0).unwrap().matches("ab"));
    assert!(!compile_with_flags("a", 0).unwrap().matches("ab"));
    assert!(compile_with_flags("a", 0).unwrap().find("ab"));
    assert!(compile_with_flags("a.b", DOTALL).unwrap().matches("a\nb"));
    assert!(!compile_with_flags("a.b", 0).unwrap().matches("a\nb"));
    assert!(compile_with_flags("\u{e9}x", ci).unwrap().matches("\u{c9}X"));
    assert!(!compile_with_flags("\u{e9}x", DOTALL | CASE_INSENSITIVE).unwrap().matches("\u{c9}X"));
    assert!(compile_with_flags("a++b", 0).unwrap().matches("aab"));
    assert!(compile_with_flags("[a-z&&[^m]]+", 0).unwrap().matches("abc"));
    assert!(!compile_with_flags("[a-z&&[^m]]+", 0).unwrap().matches("am"));
    assert!(compile_with_flags("x$", 0).unwrap().find("x\n"));
    assert!(!compile_with_flags("x$", 0).unwrap().matches("x\n"));
    let named = compile_with_flags("(?<word>[a-z]+)-(\\d)", 0).unwrap();
    let caps = named.captures("ab-1").unwrap();
    assert_eq!((&*caps.name("word").unwrap().as_str(), &*caps.get(2).unwrap().as_str()), ("ab", "1"));
}

/// The oracle runs Temurin 26.0.2, whose `Pattern` folds `ß` with `ẞ` and closes class ranges over
/// `CaseFolding` (observed on 8.0.0 through body `REGEX` matchers).
#[test]
fn jdk26_case_folding() {
    use super::{compile_with_flags, CASE_INSENSITIVE, DOTALL, UNICODE_CASE};
    let ci = DOTALL | CASE_INSENSITIVE | UNICODE_CASE;
    for (pattern, input) in [("\u{df}", "\u{1e9e}"), ("[\u{df}]", "\u{1e9e}"), ("\u{df}.", "\u{1e9e}x"), ("\u{df}a", "\u{1e9e}a"), ("\u{130}", "i"), ("\u{131}", "I")] {
        assert!(compile_with_flags(pattern, ci).unwrap().matches(input), "{pattern} {input}");
    }
    assert!(!compile_with_flags("\u{df}.", DOTALL | CASE_INSENSITIVE).unwrap().matches("\u{1e9e}x"));
    assert!(compile_with_flags("[\u{131}-\u{131}]", ci).unwrap().matches("i"));
}
/// `Character.toUpperCase`/`toLowerCase` are UnicodeData's simple mappings, never a full one.
#[test]
fn simple_case_mappings() {
    use super::{java_lower, java_upper, tables};
    for table in [tables::SIMPLE_UPPERCASE, tables::SIMPLE_LOWERCASE] {
        assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
    }
    for (c, upper) in [(0x61, 0x41), (0xDF, 0xDF), (0x149, 0x149), (0x1F80, 0x1F88), (0x1FB3, 0x1FBC), (0x1FB2, 0x1FB2), (0x17F, 0x53)] {
        assert_eq!(java_upper(c), upper, "{c:X}");
    }
    for (c, lower) in [(0x41, 0x61), (0x130, 0x69), (0x1E9E, 0xDF), (0x1F88, 0x1F80), (0x212A, 0x6B)] {
        assert_eq!(java_lower(c), lower, "{c:X}");
    }
}

/// `\G` holds where the previous match ended, and `find_all` walks matches as `Matcher.find()` does.
#[test]
fn last_match_and_find_loop() {
    let all = |pattern: &str, input: &str| -> Vec<(usize, usize)> {
        compile(pattern).unwrap().find_all(input).unwrap().iter().map(|c| (c.get(0).unwrap().start(), c.get(0).unwrap().end())).collect()
    };
    assert_eq!(all("\\Ga", "aab"), [(0, 1), (1, 2)]);
    assert_eq!(all("\\G|b", "ab"), [(0, 0), (1, 2), (2, 2)]);
    assert_eq!(all("x*", "xxa"), [(0, 2), (2, 2), (3, 3)]);
    assert!(!compile("\\Gab").unwrap().find("zab"));
}

/// A repetition count past `fancy_regex`'s size limit is matched through a translation sized to the input.
#[test]
fn repetitions_past_the_size_limit() {
    assert!(compile("a{2147483647}|a").unwrap().find("aaa"));
    assert!(!compile("a{2147483647}").unwrap().find("aaa"));
    assert!(compile("(?:a|b){0,99999}c").unwrap().matches("ababc"));
    let groups = compile("(a{0,100000})(b)").unwrap();
    let caps = groups.captures("aaab").unwrap();
    assert_eq!(caps.get(1).unwrap().as_str(), "aaa");
}

/// A case-insensitive back reference compares as `Pattern.CIBackRef` (observed on the oracle through
/// `$regex` helpers, scenario `w4_java_pattern_ci_backref`).
#[test]
fn case_insensitive_back_references_compare_as_ci_back_ref() {
    let find = |pattern: &str, input: &str| compile(pattern).unwrap().find(input);
    assert!(!find(r"(?i)(é)\1", "éÉ"));
    assert!(find(r"(?i)(Äa)\1", "ÄaÄA"));
    assert!(find(r"(?iu)(ß)\1", "ßẞ"));
    assert!(find(r"(?iu)(k)\1", "k\u{212A}"));
    assert!(!find(r"(?i)(k)\1", "k\u{212A}"));
    assert!(find(r"(?iu)(é)\1", "éÉ"));
    let groups = compile(r"(?i)(x)(y)\1\2").unwrap();
    assert_eq!(groups.captures("XyXYxy").unwrap().get(0).unwrap().as_str(), "XyXY");
    let all: Vec<String> =
        compile(r"(?i)(ab)\1").unwrap().find_all("xAbaBy abAB").unwrap().iter().map(|g| g.expand("[$1]").unwrap()).collect();
    assert_eq!(all, ["[Ab]", "[ab]"]);
    assert!(super::compile_with_flags(r"(é)\1", super::CASE_INSENSITIVE | super::UNICODE_CASE).unwrap().matches("éÉ"));
    assert!(!super::compile_with_flags(r"(é)\1", super::CASE_INSENSITIVE).unwrap().matches("éÉ"));
}

/// An inline `(?c)` makes classes and `\p`/`\P` `NFCCharProperty`s (observed on the oracle through
/// `$regex` helpers and body matchers, scenario `w4_java_pattern_canon_eq`); literals are left as they are.
#[test]
fn inline_canon_eq_normalises_the_grapheme_cluster_for_classes() {
    let find = |pattern: &str, input: &str| compile(pattern).unwrap().find(input);
    let replace = |pattern: &str, input: &str| -> String {
        let compiled = compile(pattern).unwrap();
        let (mut out, mut last) = (String::new(), 0);
        for caps in compiled.find_all(input).unwrap() {
            let m = caps.get(0).unwrap();
            out.push_str(&input[last..m.start()]);
            out.push_str(&format!("<{}>", m.as_str()));
            last = m.end();
        }
        out + &input[last..]
    };
    assert!(find("(?c)[\u{e1}]", "a\u{301}"));
    assert!(!find("(?c)\u{e1}", "a\u{301}"));
    assert!(find("(?c)\u{e1}", "\u{e1}"));
    assert!(!find("(?c)a\u{301}", "\u{e1}"));
    assert_eq!(replace("(?c)[a]", "a\u{301}"), "<a>\u{301}");
    assert_eq!(replace("(?c)\\p{L}+", "a\u{301}e\u{301}x"), "<a\u{301}e\u{301}x>");
    assert_eq!(replace("(?c)[\u{e1}]", "a\u{301}\u{302}"), "<a\u{301}>\u{302}");
    assert_eq!(replace("(?c)[\u{c5}]", "\u{212b}"), "\u{212b}");
    assert_eq!(replace("(?c)[\u{1f468}]", "\u{1f468}\u{200d}\u{1f469}"), "<\u{1f468}>\u{200d}\u{1f469}");
    assert_eq!(replace("(?c)(?-c)[\u{e1}]", "a\u{301}"), "a\u{301}");
    assert_eq!(replace("(?<=(?c)[\u{e1}])x", "a\u{301}x"), "a\u{301}x");
    assert!(!compile("(?c)^\u{e1}$").unwrap().matches("a\u{301}"));
    assert!(compile("(?c)[\u{e1}]+").unwrap().matches("a\u{301}a\u{301}"));
}

/// `replaceAll` over `find_all`, as the `$regex` template helper writes it (lone surrogate halves as `?`).
fn replace_all(input: &str, pattern: &str, replacement: &str) -> String {
    let mut out = String::new();
    let mut last = 0;
    for caps in compile(pattern).unwrap().find_all(input).unwrap() {
        let m = caps.get(0).unwrap();
        out.push_str(&super::slice(input, last, m.start()));
        out.push_str(&caps.expand(replacement).unwrap());
        last = m.end();
    }
    out.push_str(&super::slice(input, last, input.len()));
    out
}

/// After an empty match right before a supplementary character, the next search starts between its
/// surrogates, where the pattern reads a lone low surrogate (oracle answers, scenario `w4_java_pattern_utf16_positions`).
#[test]
fn searches_start_between_surrogates_after_an_empty_match() {
    let cases = [
        ("x\u{1F600}y", "", "-", "-x-?-?-y-"),
        ("\u{1F600}", "x*", "-", "-?-?-"),
        ("\u{1F600}", "(?=.)", "-", "-?-?"),
        ("a\u{1F600}", "(?<=a)|\\W", "-", "a-?-"),
        ("a\u{1F600}", "(?<=a)|\\w", "-", "--\u{1F600}"),
        ("a\u{1F600}", "(?<=a)|\\p{Cs}", "-", "a-?-"),
        ("a\u{1F600}", "(?<=a)|\\p{Co}", "-", "a-\u{1F600}"),
        ("a\u{1F600}", "(?<=a)|\\p{Graph}", "-", "--\u{1F600}"),
        ("a\u{1F600}", "(?<=a)|[\\x{DC00}-\\x{DFFF}]", "-", "a-?-"),
        ("a\u{1F600}", "(?<=a)|(?i)\\x{DE00}", "-", "a-?-"),
        ("a\u{1F600}\u{301}", "(?<=a)|\\X", "-", "--?--"),
        ("a\u{1F600}", "(?<=a)|(?<=\\x{D83D})", "-", "a-\u{1F600}"),
        ("a\u{1F600}", "(?<=a)|(?<!a)", "-", "-a-?-?-"),
        ("a\u{1F600}", "(?<=a)|\\B", "-", "a-?-?-"),
        ("a\u{1F600}", "(?<=a)|\\b{g}", "-", "-a-\u{1F600}-"),
        ("a\u{1F600}", "(?<=a)|(.)", "[$1]", "[a][]?[?]"),
        ("a\u{1F600}b", "(?<=a)|.b", "-", "a-?-"),
    ];
    for (input, pattern, replacement, expected) in cases {
        assert_eq!(replace_all(input, pattern, replacement), expected, "{pattern} over {input}");
    }
}

/// A pattern whose counts keep it past `fancy_regex`'s size limit even sized to the input is walked.
#[test]
fn repetitions_past_the_size_limit_after_sizing_are_walked() {
    let a = "a".repeat(100_000);
    assert!(compile("^a{100000}$").unwrap().find(&a));
    assert!(!compile("a{100000}").unwrap().find(&a[1..]));
    assert_eq!(replace_all(&"a".repeat(200_000), "a{100000}", "X"), "XX");
    assert_eq!(replace_all("ab", "(?:a?){100000}", "-"), "--b-");
    assert_eq!(replace_all("ab", "(a?){100000}", "[$1]"), "[][]b[]");
    assert!(compile("(?:a?){2147483647}b").unwrap().matches("b"));
    assert_eq!(replace_all("aab", "(?:a|b){100000}", "-"), "aab");
    // On a thread with as little stack as a runtime worker's.
    let ab = "ab".repeat(100_000);
    let deep = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || (compile("^(ab){100000}$").unwrap().try_find(&ab), compile("^(ab){30000}").unwrap().try_find(&ab)))
        .unwrap();
    // `GroupCurly` iterates: no depth limit is reached.
    assert_eq!(deep.join().unwrap(), (Some(true), Some(true)));
}

#[test]
fn grapheme_bound_after_a_look_ahead_to_the_end_throws_as_pattern_does() {
    // `Matcher.last` at the input end, `Grapheme.nextBoundary` reads the code point there.
    let re = compile("a(?=bc)\\b{g}b").expect("compiles");
    let thrown = re.find_or_throw("abc").unwrap_err();
    assert_eq!((thrown.class, thrown.message.as_str()), ("java.lang.StringIndexOutOfBoundsException", "Index 3 out of bounds for length 3"));
    assert!(re.captures_or_throw("abc").is_err());
    assert!(re.find_all("abc").is_err());
    assert_eq!(re.find_or_throw("abcd"), Ok(false));
}

/// A walk is bounded by the bytes of stack it takes, on the caller's thread and on its large one: a
/// walk deeper than the stack allows ends as `Stop::Depth` (a `StackOverflowError`), never as a stack overflow.
#[test]
fn walk_depth_is_bounded_by_stack_bytes() {
    use super::engine::{Program, Stop};
    let re = compile("^(?:a|b){20000}$").unwrap();
    let (node, groups) = re.tree.as_ref().expect("a counted pattern keeps its tree");
    let program = Program::new(node, *groups);
    let input = "ab".repeat(10_000);
    // 20,000 counts take two levels each, at well over 1 KiB a level: 1 MiB is far too little.
    assert_eq!(program.matches_sized(64 << 10, 1 << 20, &input).err(), Some(Stop::Depth));
    // The same walk with room for it matches.
    assert!(program.matches_sized(64 << 10, 256 << 20, &input).unwrap().is_some());
}

/// `ExpectationLinter.RegexBudget` counts each `charAt` of a match (the oracle's 100,000 per match): `/a*`
/// over `/` and 99,999 `a` reads 100,000 characters and matches, one more `a` runs out (checked on the oracle).
#[test]
fn budgeted_match_counts_character_reads_as_the_linters_char_sequence_does() {
    use super::{compile_with_flags, DOTALL};
    let re = compile_with_flags("/a*", DOTALL).unwrap();
    assert_eq!(re.matches_budgeted(&format!("/{}", "a".repeat(99_999)), 100_000, usize::MAX), (Some(true), 100_000));
    // `charAt` counts before it throws, so the read that ran out is counted.
    assert_eq!(re.matches_budgeted(&format!("/{}", "a".repeat(100_000)), 100_000, usize::MAX), (None, 100_001));
    // A mismatch reads the character it stops at.
    assert_eq!(re.matches_budgeted("/aab", 100_000, usize::MAX), (Some(false), 4));
}

/// `java.util.regex` recurses once per repetition of a group, so `/(a|b)*` over a long input ends in
/// `StackOverflowError`, which the linter reads as "does not cover". The cold JVM of the oracle matches 3,993
/// characters and overflows on 3,995.
#[test]
fn budgeted_match_stops_where_the_jvm_stack_does() {
    use super::{compile_with_flags, DOTALL};
    let re = compile_with_flags("/(a|b)*", DOTALL).unwrap();
    let input = |n: usize| format!("/{}", "ab".repeat(n / 2 + 1))[..n].to_string();
    let levels = crate::lint::REGEX_STACK_LEVELS;
    assert_eq!(re.matches_budgeted(&input(3_993), 100_000, levels).0, Some(true));
    assert_eq!(re.matches_budgeted(&input(3_995), 100_000, levels).0, None);
    // 12,001 characters: the process scenario `cli_lint_deep_regex`.
    assert_eq!(re.matches_budgeted(&input(12_001), 100_000, levels).0, None);
}
