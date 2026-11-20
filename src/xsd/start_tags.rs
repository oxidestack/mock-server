//! Xerces' namespace checks of a start tag (`XMLNSDocumentScannerImpl.scanStartElement`), in its order and words.
//! roxmltree makes the same checks in another order, reports them without the element, and takes a repeated default
//! namespace declaration for a redefinition; this reads the start tags as written to say what Xerces says.

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A start tag as written: its name, its attributes (raw name, value as written, byte offset just past the value's
/// closing quote), the byte offset just past its `>`, and whether it is an empty-element tag.
struct StartTag<'a> {
    name: &'a str,
    attributes: Vec<(&'a str, &'a str, usize)>,
    end: usize,
    empty: bool,
}

fn is_declaration(raw: &str) -> bool {
    raw == "xmlns" || raw.starts_with("xmlns:")
}

/// The first start tag beginning before `limit` that Xerces' namespace binding rejects: its message and the byte
/// offset its `SAXParseException` points at. Meaningful only for text roxmltree has read as well-formed up to `limit`
/// (markup is skipped, not checked).
pub(super) fn first_error(text: &str, limit: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let skip_to = |from: usize, close: &str| text.get(from..).and_then(|t| t.find(close)).map_or(text.len(), |p| from + p + close.len());
    // the namespace declarations of each open element
    let mut scopes: Vec<Vec<(&str, &str)>> = Vec::new();
    let mut i = 0;
    while i < limit.min(text.len()) {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("<!--") {
            i = skip_to(i + 4, "-->");
        } else if rest.starts_with("<![CDATA[") {
            i = skip_to(i + 9, "]]>");
        } else if rest.starts_with("<?") {
            i = skip_to(i + 2, "?>");
        } else if rest.starts_with("<!") {
            i = skip_declaration(text, i);
        } else if rest.starts_with("</") {
            scopes.pop();
            i = skip_to(i + 2, ">");
        } else {
            let tag = start_tag(text, i)?;
            if let Some(error) = check(&tag, &scopes) {
                return Some(error);
            }
            i = tag.end;
            if !tag.empty {
                scopes.push(declarations(&tag));
            }
        }
    }
    None
}

/// Past a `<!DOCTYPE …>` declaration, internal subset and quoted literals included.
fn skip_declaration(text: &str, start: usize) -> usize {
    let (mut quote, mut depth) = (None, 0usize);
    for (i, c) in text[start..].char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '[') => depth += 1,
            (None, ']') => depth = depth.saturating_sub(1),
            (None, '>') if depth == 0 => return start + i + 1,
            _ => {}
        }
    }
    text.len()
}

fn start_tag(text: &str, start: usize) -> Option<StartTag<'_>> {
    let bytes = text.as_bytes();
    let skip_space = |mut j: usize| {
        while bytes.get(j).is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
            j += 1;
        }
        j
    };
    let name_start = start + 1;
    let name_end = name_start + text[name_start..].find([' ', '\t', '\r', '\n', '/', '>'])?;
    let name = &text[name_start..name_end];
    let mut attributes = Vec::new();
    let mut j = name_end;
    loop {
        j = skip_space(j);
        match *bytes.get(j)? {
            b'>' => return Some(StartTag { name, attributes, end: j + 1, empty: false }),
            b'/' => return Some(StartTag { name, attributes, end: j + 2, empty: true }),
            _ => {}
        }
        let attribute_end = j + text[j..].find([' ', '\t', '\r', '\n', '='])?;
        let attribute = &text[j..attribute_end];
        j = skip_space(attribute_end);
        if bytes.get(j) != Some(&b'=') {
            return None;
        }
        j = skip_space(j + 1);
        let quote = *bytes.get(j)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let close = j + 1 + text[j + 1..].find(quote as char)?;
        attributes.push((attribute, &text[j + 1..close], close + 1));
        j = close + 1;
    }
}

/// The prefixes a start tag declares (`""` for the default namespace).
fn declarations<'a>(tag: &StartTag<'a>) -> Vec<(&'a str, &'a str)> {
    tag.attributes
        .iter()
        .filter_map(|(raw, value, _)| if *raw == "xmlns" { Some(("", *value)) } else { raw.strip_prefix("xmlns:").map(|p| (p, *value)) })
        .collect()
}

/// `scanStartElement`'s checks: a repeated namespace declaration as soon as `scanAttribute` reads it, then the
/// element's prefix, the attributes' prefixes, and `checkDuplicatesNS` (each attribute against the later ones).
fn check(tag: &StartTag, scopes: &[Vec<(&str, &str)>]) -> Option<(String, usize)> {
    let element = tag.name;
    let mut declared: Vec<&str> = Vec::new();
    for (raw, _, after) in &tag.attributes {
        if is_declaration(raw) {
            if declared.contains(raw) {
                return Some((format!("Attribute \"{raw}\" was already specified for element \"{element}\"."), *after));
            }
            declared.push(raw);
        }
    }
    let own = declarations(tag);
    let resolve = |prefix: &str| -> Option<String> {
        if prefix == "xml" {
            return Some(XML_NS.to_string());
        }
        own.iter().chain(scopes.iter().rev().flatten()).find(|(p, _)| *p == prefix).map(|(_, uri)| uri.to_string())
    };
    if let Some((prefix, _)) = element.split_once(':')
        && resolve(prefix).is_none()
    {
        return Some((format!("The prefix \"{prefix}\" for element \"{element}\" is not bound."), tag.end));
    }
    let mut names: Vec<(Option<String>, &str, &str)> = Vec::new();
    for (raw, _, _) in tag.attributes.iter().filter(|(raw, ..)| !is_declaration(raw)) {
        match raw.split_once(':') {
            Some((prefix, local)) => match resolve(prefix) {
                Some(uri) => names.push((Some(uri), local, raw)),
                None => {
                    let message = format!("The prefix \"{prefix}\" for attribute \"{raw}\" associated with an element type \"{element}\" is not bound.");
                    return Some((message, tag.end));
                }
            },
            None => names.push((None, raw, raw)),
        }
    }
    for (i, (uri, local, _)) in names.iter().enumerate() {
        if let Some((_, _, raw)) = names[i + 1..].iter().find(|(u, l, _)| u == uri && l == local) {
            let message = match uri {
                Some(uri) => format!("Attribute \"{local}\" bound to namespace \"{uri}\" was already specified for element \"{element}\"."),
                None => format!("Attribute \"{raw}\" was already specified for element \"{element}\"."),
            };
            return Some((message, tag.end));
        }
    }
    None
}
