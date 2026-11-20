//! The syntax check of a `pattern` facet as Xerces' `ParserForXMLSchema` (over `RegexParser`) parses an XML Schema
//! regular expression: [`check`] gives the `ParseException` message the `InvalidRegex` error quotes. Only the
//! syntax is ported; matching goes through the `regex` crate (`types::pattern`).

/// The Unicode blocks `\p{Is…}` names (`Token.blockNames`, Unicode 3.1) and their ranges (`blockRanges`,
/// `nonBMPBlockRanges`, and the ranges Xerces adds by hand to Specials and Private Use).
pub(super) const BLOCKS: &[(&str, &[(u32, u32)])] = &[
    ("Basic Latin", &[(0x0000, 0x007F)]),
    ("Latin-1 Supplement", &[(0x0080, 0x00FF)]),
    ("Latin Extended-A", &[(0x0100, 0x017F)]),
    ("Latin Extended-B", &[(0x0180, 0x024F)]),
    ("IPA Extensions", &[(0x0250, 0x02AF)]),
    ("Spacing Modifier Letters", &[(0x02B0, 0x02FF)]),
    ("Combining Diacritical Marks", &[(0x0300, 0x036F)]),
    ("Greek", &[(0x0370, 0x03FF)]),
    ("Cyrillic", &[(0x0400, 0x04FF)]),
    ("Armenian", &[(0x0530, 0x058F)]),
    ("Hebrew", &[(0x0590, 0x05FF)]),
    ("Arabic", &[(0x0600, 0x06FF)]),
    ("Syriac", &[(0x0700, 0x074F)]),
    ("Thaana", &[(0x0780, 0x07BF)]),
    ("Devanagari", &[(0x0900, 0x097F)]),
    ("Bengali", &[(0x0980, 0x09FF)]),
    ("Gurmukhi", &[(0x0A00, 0x0A7F)]),
    ("Gujarati", &[(0x0A80, 0x0AFF)]),
    ("Oriya", &[(0x0B00, 0x0B7F)]),
    ("Tamil", &[(0x0B80, 0x0BFF)]),
    ("Telugu", &[(0x0C00, 0x0C7F)]),
    ("Kannada", &[(0x0C80, 0x0CFF)]),
    ("Malayalam", &[(0x0D00, 0x0D7F)]),
    ("Sinhala", &[(0x0D80, 0x0DFF)]),
    ("Thai", &[(0x0E00, 0x0E7F)]),
    ("Lao", &[(0x0E80, 0x0EFF)]),
    ("Tibetan", &[(0x0F00, 0x0FFF)]),
    ("Myanmar", &[(0x1000, 0x109F)]),
    ("Georgian", &[(0x10A0, 0x10FF)]),
    ("Hangul Jamo", &[(0x1100, 0x11FF)]),
    ("Ethiopic", &[(0x1200, 0x137F)]),
    ("Cherokee", &[(0x13A0, 0x13FF)]),
    ("Unified Canadian Aboriginal Syllabics", &[(0x1400, 0x167F)]),
    ("Ogham", &[(0x1680, 0x169F)]),
    ("Runic", &[(0x16A0, 0x16FF)]),
    ("Khmer", &[(0x1780, 0x17FF)]),
    ("Mongolian", &[(0x1800, 0x18AF)]),
    ("Latin Extended Additional", &[(0x1E00, 0x1EFF)]),
    ("Greek Extended", &[(0x1F00, 0x1FFF)]),
    ("General Punctuation", &[(0x2000, 0x206F)]),
    ("Superscripts and Subscripts", &[(0x2070, 0x209F)]),
    ("Currency Symbols", &[(0x20A0, 0x20CF)]),
    ("Combining Marks for Symbols", &[(0x20D0, 0x20FF)]),
    ("Letterlike Symbols", &[(0x2100, 0x214F)]),
    ("Number Forms", &[(0x2150, 0x218F)]),
    ("Arrows", &[(0x2190, 0x21FF)]),
    ("Mathematical Operators", &[(0x2200, 0x22FF)]),
    ("Miscellaneous Technical", &[(0x2300, 0x23FF)]),
    ("Control Pictures", &[(0x2400, 0x243F)]),
    ("Optical Character Recognition", &[(0x2440, 0x245F)]),
    ("Enclosed Alphanumerics", &[(0x2460, 0x24FF)]),
    ("Box Drawing", &[(0x2500, 0x257F)]),
    ("Block Elements", &[(0x2580, 0x259F)]),
    ("Geometric Shapes", &[(0x25A0, 0x25FF)]),
    ("Miscellaneous Symbols", &[(0x2600, 0x26FF)]),
    ("Dingbats", &[(0x2700, 0x27BF)]),
    ("Braille Patterns", &[(0x2800, 0x28FF)]),
    ("CJK Radicals Supplement", &[(0x2E80, 0x2EFF)]),
    ("Kangxi Radicals", &[(0x2F00, 0x2FDF)]),
    ("Ideographic Description Characters", &[(0x2FF0, 0x2FFF)]),
    ("CJK Symbols and Punctuation", &[(0x3000, 0x303F)]),
    ("Hiragana", &[(0x3040, 0x309F)]),
    ("Katakana", &[(0x30A0, 0x30FF)]),
    ("Bopomofo", &[(0x3100, 0x312F)]),
    ("Hangul Compatibility Jamo", &[(0x3130, 0x318F)]),
    ("Kanbun", &[(0x3190, 0x319F)]),
    ("Bopomofo Extended", &[(0x31A0, 0x31BF)]),
    ("Enclosed CJK Letters and Months", &[(0x3200, 0x32FF)]),
    ("CJK Compatibility", &[(0x3300, 0x33FF)]),
    ("CJK Unified Ideographs Extension A", &[(0x3400, 0x4DB5)]),
    ("CJK Unified Ideographs", &[(0x4E00, 0x9FFF)]),
    ("Yi Syllables", &[(0xA000, 0xA48F)]),
    ("Yi Radicals", &[(0xA490, 0xA4CF)]),
    ("Hangul Syllables", &[(0xAC00, 0xD7A3)]),
    ("Private Use", &[(0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD)]),
    ("CJK Compatibility Ideographs", &[(0xF900, 0xFAFF)]),
    ("Alphabetic Presentation Forms", &[(0xFB00, 0xFB4F)]),
    ("Arabic Presentation Forms-A", &[(0xFB50, 0xFDFF)]),
    ("Combining Half Marks", &[(0xFE20, 0xFE2F)]),
    ("CJK Compatibility Forms", &[(0xFE30, 0xFE4F)]),
    ("Small Form Variants", &[(0xFE50, 0xFE6F)]),
    ("Arabic Presentation Forms-B", &[(0xFE70, 0xFEFE)]),
    ("Specials", &[(0xFEFF, 0xFEFF), (0xFFF0, 0xFFFD)]),
    ("Halfwidth and Fullwidth Forms", &[(0xFF00, 0xFFEF)]),
    ("Old Italic", &[(0x10300, 0x1032F)]),
    ("Gothic", &[(0x10330, 0x1034F)]),
    ("Deseret", &[(0x10400, 0x1044F)]),
    ("Byzantine Musical Symbols", &[(0x1D000, 0x1D0FF)]),
    ("Musical Symbols", &[(0x1D100, 0x1D1FF)]),
    ("Mathematical Alphanumeric Symbols", &[(0x1D400, 0x1D7FF)]),
    ("CJK Unified Ideographs Extension B", &[(0x20000, 0x2A6D6)]),
    ("CJK Compatibility Ideographs Supplement", &[(0x2F800, 0x2FA1F)]),
    ("Tags", &[(0xE0000, 0xE007F)]),
];

/// The general categories `\p{…}` names (`Token.categoryNames`).
const CATEGORIES: &[&str] = &[
    "Cn", "Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Me", "Mc", "Nd", "Nl", "No", "Zs", "Zl", "Zp", "Cc", "Cf", "Co", "Cs", "Pd", "Ps", "Pe", "Pc", "Po", "Sm", "Sc",
    "Sk", "So", "Pi", "Pf", "L", "M", "N", "Z", "C", "P", "S",
];

/// The block a property name names: `Basic Latin` as written, or `IsBasicLatin` (spaces dropped).
pub(super) fn block(name: &str) -> Option<&'static [(u32, u32)]> {
    BLOCKS.iter().find(|(block, _)| *block == name || name.strip_prefix("Is").is_some_and(|n| n == block.replace(' ', ""))).map(|(_, ranges)| *ranges)
}

/// Whether `\p{name}` is known in XML Schema mode (`Token.getRange` without the names `registerNonXS` marks).
fn known_property(name: &str) -> bool {
    CATEGORIES.contains(&name) || block(name).is_some()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Char,
    Eof,
    Or,
    Star,
    Plus,
    Question,
    LParen,
    RParen,
    Dot,
    LBracket,
    Backslash,
    /// `-[` inside a character class.
    Subtraction,
    /// `(?#…)`.
    Comment,
    /// `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, `(?[`, `(?>`, `(?(` and `(?flags`: none is supported here.
    Unsupported,
}

struct Parser {
    re: Vec<char>,
    offset: usize,
    in_brackets: bool,
    tok: Tok,
    ch: char,
}

/// `RegexParser.ex`: the message of the key's `ParseException`.
fn ex(key: &str) -> String {
    match key {
        "parser.atom.2" => "A '{' is required before a character category.",
        "parser.atom.3" => "A property name is not closed by '}'.",
        "parser.atom.4" => "Unexpected meta character.",
        "parser.atom.5" => "Unknown property.",
        "parser.cc.2" => "Unexpected end of the pattern in a character class.",
        "parser.cc.5" => "']' is expected.",
        "parser.cc.6" => "'[' is invalid in a character class.  Write '\\['.",
        "parser.cc.7" => "']' is invalid in a character class.  Write '\\]'.",
        "parser.cc.8" => "'-' is an invalid character range. Write '\\-'.",
        "parser.factor.1" => "')' is expected.",
        "parser.next.1" => "A character is required after \\.",
        "parser.next.2" => "'?' is not expected.  '(?:' or '(?=' or '(?!' or '(?<' or '(?#' or '(?>'?",
        "parser.next.3" => "'(?<=' or '(?<!' is expected.",
        "parser.next.4" => "A comment is not terminated.",
        "parser.ope.3" => "The range end code point is less than the start code point.",
        "parser.parse.1" => "Wrong character.",
        "parser.process.1" => "This expression is not supported in the current option setting.",
        "parser.quantifier.1" => "Invalid quantifier. A digit is expected.",
        "parser.quantifier.2" => "Invalid quantifier. Invalid quantity or a '}' is missing.",
        "parser.quantifier.3" => "Invalid quantifier. A digit or '}' is expected.",
        "parser.quantifier.4" => "Invalid quantifier. A min quantity must be <= a max quantity.",
        "parser.quantifier.5" => "Invalid quantifier. A quantity value overflow.",
        other => other,
    }
    .to_string()
}

type Parsed<T> = Result<T, String>;

/// Why Xerces refuses `pattern` as an XML Schema regular expression, in its words; `Ok` for one it accepts.
pub fn check(pattern: &str) -> Result<(), String> {
    let mut p = Parser { re: pattern.chars().collect(), offset: 0, in_brackets: false, tok: Tok::Eof, ch: '\0' };
    p.next()?;
    p.regex()?;
    if p.offset != p.re.len() || p.tok != Tok::Eof {
        return Err(ex("parser.parse.1"));
    }
    Ok(())
}

impl Parser {
    fn at(&self, i: usize) -> Option<char> {
        self.re.get(i).copied()
    }

    /// `RegexParser.next`.
    fn next(&mut self) -> Parsed<()> {
        let Some(c) = self.at(self.offset) else {
            self.tok = Tok::Eof;
            return Ok(());
        };
        self.offset += 1;
        self.ch = c;
        if self.in_brackets {
            self.tok = match c {
                '\\' => {
                    let Some(e) = self.at(self.offset) else { return Err(ex("parser.next.1")) };
                    self.offset += 1;
                    self.ch = e;
                    Tok::Backslash
                }
                '-' if self.at(self.offset) == Some('[') => {
                    self.offset += 1;
                    Tok::Subtraction
                }
                _ => Tok::Char,
            };
            return Ok(());
        }
        self.tok = match c {
            '|' => Tok::Or,
            '*' => Tok::Star,
            '+' => Tok::Plus,
            '?' => Tok::Question,
            ')' => Tok::RParen,
            '.' => Tok::Dot,
            '[' => Tok::LBracket,
            '(' => {
                if self.at(self.offset) != Some('?') {
                    self.tok = Tok::LParen;
                    return Ok(());
                }
                self.offset += 1;
                let Some(c) = self.at(self.offset) else { return Err(ex("parser.next.2")) };
                self.offset += 1;
                match c {
                    ':' | '=' | '!' | '[' | '>' => Tok::Unsupported,
                    '<' => {
                        let Some(c) = self.at(self.offset) else { return Err(ex("parser.next.2")) };
                        self.offset += 1;
                        if c != '=' && c != '!' {
                            return Err(ex("parser.next.3"));
                        }
                        Tok::Unsupported
                    }
                    '#' => {
                        let mut last = c;
                        while let Some(c) = self.at(self.offset) {
                            self.offset += 1;
                            last = c;
                            if c == ')' {
                                break;
                            }
                        }
                        if last != ')' {
                            return Err(ex("parser.next.4"));
                        }
                        Tok::Comment
                    }
                    c if c == '-' || c.is_ascii_alphabetic() => {
                        self.offset -= 1;
                        Tok::Unsupported
                    }
                    '(' => Tok::Unsupported,
                    _ => return Err(ex("parser.next.2")),
                }
            }
            '\\' => {
                let Some(e) = self.at(self.offset) else { return Err(ex("parser.next.1")) };
                self.offset += 1;
                self.ch = e;
                Tok::Backslash
            }
            _ => Tok::Char,
        };
        Ok(())
    }

    fn regex(&mut self) -> Parsed<()> {
        self.term()?;
        while self.tok == Tok::Or {
            self.next()?;
            self.term()?;
        }
        Ok(())
    }

    fn term(&mut self) -> Parsed<()> {
        while !matches!(self.tok, Tok::Or | Tok::RParen | Tok::Eof) {
            self.factor()?;
        }
        Ok(())
    }

    fn factor(&mut self) -> Parsed<()> {
        match self.tok {
            Tok::Comment => return self.next(),
            Tok::Backslash if matches!(self.ch, 'A' | 'Z' | 'z' | 'b' | 'B' | '<' | '>') => return Err(ex("parser.process.1")),
            _ => {}
        }
        self.atom()?;
        match self.tok {
            Tok::Star | Tok::Plus | Tok::Question => self.next()?,
            Tok::Char if self.ch == '{' && self.offset < self.re.len() => self.quantifier()?,
            _ => {}
        }
        Ok(())
    }

    /// `{min}`, `{min,}` or `{min,max}` after an atom.
    fn quantifier(&mut self) -> Parsed<()> {
        let mut off = self.offset;
        // Java `int` arithmetic: a value that wraps negative is the overflow Xerces notices.
        let digit = |c: Option<char>| c.filter(char::is_ascii_digit).map(|c| c as i32 - '0' as i32);
        let mut c = self.at(off);
        off += 1;
        let Some(mut min) = digit(c) else { return Err(ex("parser.quantifier.1")) };
        while off < self.re.len() {
            c = self.at(off);
            off += 1;
            let Some(d) = digit(c) else { break };
            min = min.wrapping_mul(10).wrapping_add(d);
            if min < 0 {
                return Err(ex("parser.quantifier.5"));
            }
        }
        if c == Some(',') {
            if off >= self.re.len() {
                return Err(ex("parser.quantifier.3"));
            }
            c = self.at(off);
            off += 1;
            if let Some(mut max) = digit(c) {
                while off < self.re.len() {
                    c = self.at(off);
                    off += 1;
                    let Some(d) = digit(c) else { break };
                    max = max.wrapping_mul(10).wrapping_add(d);
                    if max < 0 {
                        return Err(ex("parser.quantifier.5"));
                    }
                }
                if min > max {
                    return Err(ex("parser.quantifier.4"));
                }
            }
        }
        if c != Some('}') {
            return Err(ex("parser.quantifier.2"));
        }
        self.offset = off;
        self.next()
    }

    fn atom(&mut self) -> Parsed<()> {
        match self.tok {
            Tok::LParen => {
                self.next()?;
                self.regex()?;
                if self.tok != Tok::RParen {
                    return Err(ex("parser.factor.1"));
                }
                self.next()
            }
            Tok::Unsupported => Err(ex("parser.process.1")),
            Tok::Dot => self.next(),
            Tok::LBracket => self.class(),
            Tok::Backslash => {
                match self.ch {
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'c' | 'C' | 'i' | 'I' => {}
                    'e' | 'f' | 'n' | 'r' | 't' | 'u' | 'v' | 'x' => {
                        self.escaped()?;
                    }
                    'g' | 'X' | '1'..='9' => return Err(ex("parser.process.1")),
                    'p' | 'P' => self.property()?,
                    _ => {}
                }
                self.next()
            }
            Tok::Char if matches!(self.ch, ']' | '{' | '}') => Err(ex("parser.atom.4")),
            Tok::Char => self.next(),
            _ => Err(ex("parser.atom.4")),
        }
    }

    /// `processBacksolidus_pP`: `{name}` after `\p` or `\P`, a name Xerces knows; leaves the offset after `}`.
    fn property(&mut self) -> Parsed<()> {
        self.next()?;
        if self.tok != Tok::Char || self.ch != '{' {
            return Err(ex("parser.atom.2"));
        }
        let start = self.offset;
        let Some(end) = self.re[start..].iter().position(|c| *c == '}').map(|i| start + i) else { return Err(ex("parser.atom.3")) };
        let name: String = self.re[start..end].iter().collect();
        self.offset = end + 1;
        if !known_property(&name) {
            return Err(ex("parser.atom.5"));
        }
        Ok(())
    }

    /// `ParserForXMLSchema.decodeEscaped`: the escapes a character class (or `\n`, `\r`, `\t`) may use.
    fn escaped(&self) -> Parsed<char> {
        if self.tok != Tok::Backslash {
            return Err(ex("parser.next.1"));
        }
        match self.ch {
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            c @ ('\\' | '|' | '.' | '^' | '-' | '?' | '*' | '+' | '{' | '}' | '(' | ')' | '[' | ']') => Ok(c),
            _ => Err(ex("parser.process.1")),
        }
    }

    /// `ParserForXMLSchema.parseCharacterClass`, entered at `[` (or after `-[`).
    fn class(&mut self) -> Parsed<()> {
        self.in_brackets = true;
        self.next()?;
        if self.tok == Tok::Char && self.ch == '^' {
            self.next()?;
        }
        let mut first = true;
        while self.tok != Tok::Eof {
            let mut decoded = false;
            if self.tok == Tok::Char && self.ch == ']' && !first {
                break;
            }
            let kind = self.tok;
            let mut c = self.ch;
            let mut end = false;
            if kind == Tok::Backslash {
                match c {
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'i' | 'I' | 'c' | 'C' => end = true,
                    'p' | 'P' => {
                        self.property()?;
                        end = true;
                    }
                    '-' => {
                        c = self.escaped()?;
                        decoded = true;
                    }
                    _ => c = self.escaped()?,
                }
            } else if kind == Tok::Subtraction && !first {
                self.class()?;
                if self.tok != Tok::Char || self.ch != ']' {
                    return Err(ex("parser.cc.5"));
                }
                break;
            }
            self.next()?;
            if !end {
                if kind == Tok::Char {
                    if c == '[' {
                        return Err(ex("parser.cc.6"));
                    }
                    if c == ']' {
                        return Err(ex("parser.cc.7"));
                    }
                    if c == '-' && self.ch != ']' && !first {
                        return Err(ex("parser.cc.8"));
                    }
                }
                let single = self.tok != Tok::Char || self.ch != '-' || (c == '-' && !decoded && first);
                if !single {
                    self.next()?;
                    match self.tok {
                        Tok::Eof => return Err(ex("parser.cc.2")),
                        Tok::Char if self.ch == ']' => {}
                        Tok::Subtraction => return Err(ex("parser.cc.8")),
                        kind => {
                            let mut range_end = self.ch;
                            if kind == Tok::Char {
                                if range_end == '[' {
                                    return Err(ex("parser.cc.6"));
                                }
                                if range_end == ']' {
                                    return Err(ex("parser.cc.7"));
                                }
                                if range_end == '-' {
                                    return Err(ex("parser.cc.8"));
                                }
                            } else if kind == Tok::Backslash {
                                range_end = self.escaped()?;
                            }
                            self.next()?;
                            if c > range_end {
                                return Err(ex("parser.ope.3"));
                            }
                        }
                    }
                }
            }
            first = false;
        }
        if self.tok == Tok::Eof {
            return Err(ex("parser.cc.2"));
        }
        self.in_brackets = false;
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn xerces_messages() {
        assert_eq!(check("[a"), Err("Unexpected end of the pattern in a character class.".into()));
        assert_eq!(check("a)"), Err("Wrong character.".into()));
        assert_eq!(check("(a"), Err("')' is expected.".into()));
        assert_eq!(check("a{2,1}"), Err("Invalid quantifier. A min quantity must be <= a max quantity.".into()));
        assert_eq!(check("\\p{Foo}"), Err("Unknown property.".into()));
        assert_eq!(check("(?:a)"), Err("This expression is not supported in the current option setting.".into()));
        assert_eq!(check("[z-a]"), Err("The range end code point is less than the start code point.".into()));
        assert_eq!(check("*a"), Err("Unexpected meta character.".into()));
        for ok in ["[a-z]+", "\\p{IsBasicLatin}", "\\p{Basic Latin}", "\\p{Lu}*", "[a-z-[aeiou]]", "a{2,}", "(a|b)?", "\\d{3}-\\d{4}", "[\\-a]", "[-a]", "[a-]"] {
            assert_eq!(check(ok), Ok(()), "{ok}");
        }
    }
}
