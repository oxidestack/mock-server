//! A line scanner for the block YAML that deployment files use (compose, Kubernetes manifests, Helm values). It does
//! not build a document: it lists each key and sequence item with its path and the byte span of its value, which is
//! what the rewrites need to edit the file textually and keep its comments and layout. It understands
//! block mappings and sequences (also zero-indented ones), plain, quoted, flow and block scalars, comments and `---`
//! document separators; anchors, tags and multi-line flow collections are read as plain text.

/// How a scalar was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Plain,
    Single,
    Double,
    /// `[...]` or `{...}` on one line; `text` is the raw inside.
    Flow,
    /// `|` or `>`: `text` is the content lines, dedented.
    Block,
}

/// A value: its text (unquoted) and the span of its raw form in the file, quotes included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub style: Style,
    /// For a block scalar, the 1-based line of its first content line.
    pub first_line: usize,
}

impl Scalar {
    /// Where `text` sits in the file when the file holds it verbatim (no escapes, not a block scalar).
    pub fn text_span(&self, source: &str) -> Option<(usize, usize)> {
        let (start, end) = match self.style {
            Style::Plain => (self.start, self.end),
            Style::Single | Style::Double => (self.start + 1, self.end.saturating_sub(1)),
            Style::Flow | Style::Block => return None,
        };
        (source.get(start..end) == Some(self.text.as_str())).then_some((start, end))
    }

    /// The items of a flow sequence (`["a", "b"]`), each with its span.
    pub fn flow_items(&self, source: &str) -> Vec<Scalar> {
        if self.style != Style::Flow || !source[self.start..].starts_with('[') {
            return Vec::new();
        }
        let inner_start = self.start + 1;
        let inner_end = self.end.saturating_sub(1);
        let inner = &source[inner_start..inner_end];
        let mut items = Vec::new();
        let mut item_start = 0;
        let mut quote = None;
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i <= bytes.len() {
            let c = bytes.get(i).copied();
            match (quote, c) {
                (Some(q), Some(b)) if b == q => quote = None,
                (Some(b'"'), Some(b'\\')) => i += 1,
                (Some(_), Some(_)) => {}
                (None, Some(b'"' | b'\'')) => quote = c,
                (None, Some(b',')) | (_, None) => {
                    let raw = &inner[item_start..i.min(inner.len())];
                    let lead = raw.len() - raw.trim_start().len();
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        let at = inner_start + item_start + lead;
                        if let Some(scalar) = scalar_at(source, at, at + trimmed.len()) {
                            items.push(scalar);
                        }
                    }
                    item_start = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        items
    }
}

/// One key or sequence item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The document's index in a multi-document stream.
    pub doc: usize,
    /// Keys and `[i]` item indexes from the root, this entry's own last.
    pub path: Vec<String>,
    /// 1-based.
    pub line: usize,
    /// Byte offsets of the entry's first line and past its last line (past the newline).
    pub start: usize,
    pub end: usize,
    /// The column of the key, or of the item's content for a bare item.
    pub indent: usize,
    /// The column of the `-` when this line opened a sequence item.
    pub item_indent: Option<usize>,
    pub key: Option<String>,
    pub value: Option<Scalar>,
}

impl Entry {
    pub fn path_string(&self) -> String {
        let mut out = String::new();
        for segment in &self.path {
            if !segment.starts_with('[') && !out.is_empty() {
                out.push('.');
            }
            out.push_str(segment);
        }
        out
    }

    /// The value's text, empty when there is none.
    pub fn text(&self) -> &str {
        self.value.as_ref().map_or("", |v| v.text.as_str())
    }
}

#[derive(Debug)]
struct Frame {
    indent: usize,
    segment: String,
    item: Option<usize>,
}

/// Every entry of `source`, in file order.
pub fn scan(source: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut doc = 0;
    let lines: Vec<(usize, &str)> = line_offsets(source);
    let mut n = 0;
    while n < lines.len() {
        let (offset, raw) = lines[n];
        let line_end = lines.get(n + 1).map_or(source.len(), |(o, _)| *o);
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        n += 1;
        let this_line = n;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "---" || trimmed.starts_with("--- ") || trimmed == "..." {
            if trimmed != "..." {
                doc += usize::from(!entries.is_empty() || doc > 0);
            }
            stack.clear();
            continue;
        }
        if line.starts_with('%') {
            continue;
        }
        let mut col = line.len() - trimmed.len();
        let mut rest = trimmed;
        let mut item_indent = None;
        while rest == "-" || rest.starts_with("- ") {
            let mut index = 0;
            while let Some(top) = stack.last() {
                if top.indent > col {
                    stack.pop();
                } else if top.indent == col && top.item.is_some() {
                    index = top.item.unwrap_or(0) + 1;
                    stack.pop();
                } else {
                    break;
                }
            }
            stack.push(Frame { indent: col, segment: format!("[{index}]"), item: Some(index) });
            item_indent.get_or_insert(col);
            let after = &rest[1..];
            let spaces = after.len() - after.trim_start().len();
            col += 1 + spaces;
            rest = after.trim_start();
        }
        let path_of = |stack: &[Frame]| stack.iter().map(|f| f.segment.clone()).collect::<Vec<_>>();
        if rest.is_empty() || rest.starts_with('#') {
            entries.push(Entry { doc, path: path_of(&stack), line: this_line, start: offset, end: line_end, indent: col, item_indent, key: None, value: None });
            continue;
        }
        let at = offset + col;
        if let Some((key, value_at)) = split_key(rest) {
            while stack.last().is_some_and(|top| top.indent >= col) {
                stack.pop();
            }
            stack.push(Frame { indent: col, segment: key.clone(), item: None });
            let mut end = line_end;
            let value = match value_at {
                Some(v) => {
                    let start = at + v;
                    let text_end = offset + line.len();
                    match source.as_bytes()[start] {
                        b'|' | b'>' => {
                            let (scalar, last) = block_scalar(source, &lines, n, col, start);
                            n = last;
                            end = lines.get(n).map_or(source.len(), |(o, _)| *o);
                            scalar
                        }
                        _ => scalar_at(source, start, value_end(source, start, text_end)),
                    }
                }
                None => None,
            };
            entries.push(Entry { doc, path: path_of(&stack), line: this_line, start: offset, end, indent: col, item_indent, key: Some(key), value });
        } else if item_indent.is_some() {
            let text_end = offset + line.len();
            let value = scalar_at(source, at, value_end(source, at, text_end));
            entries.push(Entry { doc, path: path_of(&stack), line: this_line, start: offset, end: line_end, indent: col, item_indent, key: None, value });
        }
    }
    entries
}

fn line_offsets(source: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut at = 0;
    for line in source.split_inclusive('\n') {
        out.push((at, line));
        at += line.len();
    }
    out
}

/// `key: value` or `key:` at the start of `rest`: the key and the offset of the value within `rest`.
fn split_key(rest: &str) -> Option<(String, Option<usize>)> {
    let bytes = rest.as_bytes();
    let (key, after) = match bytes[0] {
        q @ (b'"' | b'\'') => {
            let close = rest[1..].find(q as char)? + 1;
            let after = &rest[close + 1..];
            let colon = after.len() - after.trim_start().len();
            if !after[colon..].starts_with(':') {
                return None;
            }
            (rest[1..close].to_string(), close + 1 + colon + 1)
        }
        b'[' | b'{' | b'&' | b'*' | b'!' | b'|' | b'>' => return None,
        _ => {
            let mut found = None;
            for (i, c) in rest.char_indices() {
                if c == '#' && i > 0 && rest.as_bytes()[i - 1] == b' ' {
                    break;
                }
                if c == ':' && rest[i + 1..].chars().next().is_none_or(|n| n == ' ' || n == '\t') {
                    found = Some(i);
                    break;
                }
            }
            let i = found?;
            (rest[..i].trim_end().to_string(), i + 1)
        }
    };
    let tail = &rest[after..];
    let lead = tail.len() - tail.trim_start().len();
    let value = &tail[lead..];
    if value.is_empty() || value.starts_with('#') {
        return Some((key, None));
    }
    Some((key, Some(after + lead)))
}

/// Where a one-line value starting at `start` ends: past its closing quote or bracket, or before a ` #` comment.
fn value_end(source: &str, start: usize, line_end: usize) -> usize {
    let text = &source[start..line_end];
    let bytes = text.as_bytes();
    match bytes.first() {
        Some(&q @ (b'"' | b'\'')) => {
            let mut i = 1;
            while i < bytes.len() {
                if q == b'"' && bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    if q == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    return start + i + 1;
                }
                i += 1;
            }
            line_end
        }
        Some(&open @ (b'[' | b'{')) => {
            let close = if open == b'[' { b']' } else { b'}' };
            let (mut depth, mut quote) = (0usize, None);
            for (i, &b) in bytes.iter().enumerate() {
                match quote {
                    Some(q) if b == q => quote = None,
                    Some(_) => {}
                    None if b == b'"' || b == b'\'' => quote = Some(b),
                    None if b == open => depth += 1,
                    None if b == close => {
                        depth -= 1;
                        if depth == 0 {
                            return start + i + 1;
                        }
                    }
                    None => {}
                }
            }
            line_end
        }
        _ => {
            let cut = text.find(" #").or_else(|| text.find("\t#")).unwrap_or(text.len());
            start + text[..cut].trim_end().len()
        }
    }
}

/// The scalar written at `start..end`.
fn scalar_at(source: &str, start: usize, end: usize) -> Option<Scalar> {
    let raw = source.get(start..end)?;
    let (text, style) = match raw.as_bytes().first()? {
        b'"' if raw.len() >= 2 && raw.ends_with('"') => (unescape_double(&raw[1..raw.len() - 1]), Style::Double),
        b'\'' if raw.len() >= 2 && raw.ends_with('\'') => (raw[1..raw.len() - 1].replace("''", "'"), Style::Single),
        b'[' | b'{' => (raw[1..raw.len().saturating_sub(1).max(1)].to_string(), Style::Flow),
        _ => (raw.to_string(), Style::Plain),
    };
    Some(Scalar { text, start, end, style, first_line: 0 })
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// A `|`/`>` block scalar whose indicator is at `start`: the scalar and the index of the first line after it.
fn block_scalar(source: &str, lines: &[(usize, &str)], next: usize, key_indent: usize, start: usize) -> (Option<Scalar>, usize) {
    let folded = source.as_bytes()[start] == b'>';
    let mut n = next;
    let mut content: Vec<&str> = Vec::new();
    let mut indent = None;
    let mut last_content = next;
    while n < lines.len() {
        let line = lines[n].1.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        let col = line.len() - trimmed.len();
        if trimmed.is_empty() {
            content.push("");
            n += 1;
            continue;
        }
        if col <= key_indent {
            break;
        }
        let block_indent = *indent.get_or_insert(col);
        content.push(line.get(block_indent.min(col)..).unwrap_or(""));
        n += 1;
        last_content = n;
    }
    content.truncate(last_content - next);
    let text = if folded { content.join(" ") } else { content.iter().map(|l| format!("{l}\n")).collect() };
    let end = lines.get(last_content).map_or(source.len(), |(o, _)| *o);
    (Some(Scalar { text, start, end, style: Style::Block, first_line: next + 1 }), last_content)
}

/// The entries one level below `parent` (its direct keys and items), in file order.
pub fn children<'a>(entries: &'a [Entry], parent: &Entry) -> impl Iterator<Item = &'a Entry> + 'a {
    let path = parent.path.clone();
    let doc = parent.doc;
    entries.iter().filter(move |e| e.doc == doc && e.path.len() == path.len() + 1 && e.path[..path.len()] == path[..])
}

/// The entry at exactly this path in this document.
pub fn find<'a>(entries: &'a [Entry], doc: usize, path: &[&str]) -> Option<&'a Entry> {
    entries.iter().find(|e| e.doc == doc && e.path.len() == path.len() && e.path.iter().zip(path).all(|(a, b)| a == b))
}

/// The end offset of the last entry below `parent` (or of `parent` itself), where a new child goes.
pub fn subtree_end(entries: &[Entry], parent: &Entry) -> usize {
    entries
        .iter()
        .filter(|e| e.doc == parent.doc && e.path.len() > parent.path.len() && e.path[..parent.path.len()] == parent.path[..])
        .map(|e| e.end)
        .chain(std::iter::once(parent.end))
        .max()
        .unwrap_or(parent.end)
}

/// The items of a sequence value: the block items below `entry`, or a one-line flow sequence; `None` for a scalar.
pub fn sequence(entries: &[Entry], entry: &Entry, source: &str) -> Option<Vec<Scalar>> {
    if let Some(value) = &entry.value {
        return (value.style == Style::Flow && source[value.start..].starts_with('[')).then(|| value.flow_items(source));
    }
    let items: Vec<Scalar> = children(entries, entry).filter(|e| e.key.is_none() && e.path.last().is_some_and(|s| s.starts_with('['))).filter_map(|e| e.value.clone()).collect();
    Some(items)
}

/// Whether a plain YAML scalar holding `value` reads back as that same string.
pub fn plain_safe(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(": ")
        && !value.contains(" #")
        && !value.ends_with(':')
        && !value.starts_with(|c: char| "!&*-?:,[]{}#|>@`\"'%= ".contains(c))
        && !matches!(value.to_ascii_lowercase().as_str(), "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~")
        && value.parse::<f64>().is_err()
}

/// `value` as a YAML double-quoted scalar.
pub fn double_quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(source: &str) -> Vec<(String, usize, Option<String>)> {
        scan(source).into_iter().map(|e| (e.path_string(), e.line, e.value.map(|v| v.text))).collect()
    }

    #[test]
    fn mappings_sequences_and_scalars() {
        let source = "services:\n  mock:   # the server\n    image: \"mockserver/mockserver:8.0.0\"\n    environment:\n      - A=1\n      - 'B=x y'\n    command: [\"-serverPort\", '1080']\n    ports:\n    - 1080:1080\n  other:\n    image: nginx # proxy\n";
        assert_eq!(paths(source), [
            ("services".into(), 1, None),
            ("services.mock".into(), 2, None),
            ("services.mock.image".into(), 3, Some("mockserver/mockserver:8.0.0".into())),
            ("services.mock.environment".into(), 4, None),
            ("services.mock.environment[0]".into(), 5, Some("A=1".into())),
            ("services.mock.environment[1]".into(), 6, Some("B=x y".into())),
            ("services.mock.command".into(), 7, Some("\"-serverPort\", '1080'".into())),
            ("services.mock.ports".into(), 8, None),
            ("services.mock.ports[0]".into(), 9, Some("1080:1080".into())),
            ("services.other".into(), 10, None),
            ("services.other.image".into(), 11, Some("nginx".into())),
        ]);
        let entries = scan(source);
        let image = &entries[2];
        let value = image.value.as_ref().unwrap();
        assert_eq!(&source[value.start..value.end], "\"mockserver/mockserver:8.0.0\"");
        assert_eq!(value.text_span(source).map(|(s, e)| &source[s..e]), Some("mockserver/mockserver:8.0.0"));
        let command = &entries[6];
        let items: Vec<String> = command.value.as_ref().unwrap().flow_items(source).into_iter().map(|s| s.text).collect();
        assert_eq!(items, ["-serverPort", "1080"]);
        assert_eq!(sequence(&entries, &entries[3], source).unwrap().len(), 2);
    }

    #[test]
    fn kubernetes_env_lists_and_documents() {
        let source = "kind: Service\n---\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: mock\n        image: mockserver/mockserver\n        env:\n        - name: JAVA_TOOL_OPTIONS\n          value: \"-Xmx64m\"\n        - name: B\n          value: '2'\n";
        let entries = scan(source);
        assert_eq!(entries[0].doc, 0);
        let env: Vec<(String, usize)> = entries.iter().filter(|e| e.doc == 1).map(|e| (e.path_string(), e.line)).collect();
        assert_eq!(env, [
            ("kind".to_string(), 3),
            ("spec".into(), 4),
            ("spec.template".into(), 5),
            ("spec.template.spec".into(), 6),
            ("spec.template.spec.containers".into(), 7),
            ("spec.template.spec.containers[0].name".into(), 8),
            ("spec.template.spec.containers[0].image".into(), 9),
            ("spec.template.spec.containers[0].env".into(), 10),
            ("spec.template.spec.containers[0].env[0].name".into(), 11),
            ("spec.template.spec.containers[0].env[0].value".into(), 12),
            ("spec.template.spec.containers[0].env[1].name".into(), 13),
            ("spec.template.spec.containers[0].env[1].value".into(), 14),
        ]);
        assert_eq!(entries.iter().find(|e| e.line == 11).unwrap().item_indent, Some(8));
    }

    #[test]
    fn block_scalars_span_their_lines() {
        let source = "app:\n  config:\n    properties: |\n      mockserver.logLevel=DEBUG\n\n      mockserver.maxExpectations=5\n  jvmOptions: \"-Xmx1g\"\n";
        let entries = scan(source);
        let properties = entries.iter().find(|e| e.key.as_deref() == Some("properties")).unwrap();
        let value = properties.value.as_ref().unwrap();
        assert_eq!(value.text, "mockserver.logLevel=DEBUG\n\nmockserver.maxExpectations=5\n");
        assert_eq!(value.first_line, 4);
        let jvm = entries.iter().find(|e| e.key.as_deref() == Some("jvmOptions")).unwrap();
        assert_eq!((jvm.path_string(), jvm.line), ("app.jvmOptions".to_string(), 7));
    }

    #[test]
    fn colons_inside_values_and_quoted_keys() {
        let source = "\"quoted key\": http://host:80/x\nurl: a:b\nlist:\n- http://x:1\n";
        assert_eq!(paths(source), [
            ("quoted key".into(), 1, Some("http://host:80/x".into())),
            ("url".into(), 2, Some("a:b".into())),
            ("list".into(), 3, None),
            ("list[0]".into(), 4, Some("http://x:1".into())),
        ]);
    }

    #[test]
    fn plain_safety() {
        assert!(plain_safe("INFO"));
        assert!(!plain_safe("true"));
        assert!(!plain_safe("5"));
        assert!(!plain_safe("-Xmx"));
        assert_eq!(double_quoted("a\"b"), "\"a\\\"b\"");
    }
}
