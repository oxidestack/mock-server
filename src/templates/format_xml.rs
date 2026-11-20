//! `XmlXPathTemplateHelper.formatXml`: the XML re-indented by the JDK's identity transform (`INDENT=yes`,
//! `indent-amount=2`, no declaration), after MockServer drops the whitespace-only text between elements, with the
//! input's own declaration put back in front.
//!
//! The transform's layout, as the oracle shows it: an element whose children are only text and CDATA stays on one
//! line; any other element puts each child on a line of its own, indented two spaces a level, text included and
//! written as it is; nodes outside the root element are not separated. A namespace-aware Xerces DOM keeps attributes
//! sorted by name, and the serialiser writes the element's own prefix's declaration first, then the other
//! declarations, then the attributes. Supplementary characters are written as character references.

use java_compat::lang::JError;
use xmlparser::{ElementEnd, Token, Tokenizer};

/// `MAX_FORMAT_DEPTH`.
const MAX_DEPTH: usize = 256;
/// `MIN_FORMAT_OUTPUT_CHARS`.
const MIN_OUTPUT_CHARS: usize = 64 * 1024;

fn illegal(message: String) -> JError {
    JError::new("java.lang.IllegalArgumentException", message)
}

enum Node {
    Element { name: String, prefix: String, attributes: Vec<(String, String)>, children: Vec<Node> },
    Text(String),
    Cdata(String),
    Comment(String),
    Instruction(String, Option<String>),
}

/// `String.isBlank()`: only `Character.isWhitespace` characters.
fn is_blank(text: &str) -> bool {
    text.chars().all(java_whitespace)
}

fn java_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1c}'..='\u{1f}') || (c.is_whitespace() && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}'))
}

/// `formatXml(xml)`.
pub fn format_xml(xml: Option<&str>) -> Result<String, JError> {
    let xml = match xml {
        Some(xml) if !is_blank(xml) => xml,
        _ => return Err(illegal("xpath.formatXml: there is no XML to format".into())),
    };
    if let Err(because) = well_formed(xml) {
        let hint = if xml.contains("&lt;") { "; in Mustache read the value with triple braces, such as {{{ request.body }}}, so it is not HTML-escaped" } else { "" };
        return Err(illegal(format!("xpath.formatXml: the text is not well-formed XML ({because}){hint}")));
    }
    let mut nodes = parse(xml).map_err(|e| illegal(format!("xpath.formatXml: the text is not well-formed XML ({e})")))?;
    for node in &mut nodes {
        remove_indentation(node, 1)?;
    }
    let mut out = String::new();
    for node in &nodes {
        write(node, 0, &mut out);
    }
    let limit = MIN_OUTPUT_CHARS.max(xml.encode_utf16().count() * 4);
    if out.encode_utf16().count() > limit {
        return Err(illegal(format!("xpath.formatXml: the formatted XML would be over {limit} characters")));
    }
    let trimmed = xml.trim_start_matches(java_whitespace);
    let declaration = match (trimmed.starts_with("<?xml"), trimmed.find("?>")) {
        (true, Some(end)) => format!("{}\n", &trimmed[..end + 2]),
        _ => String::new(),
    };
    Ok(format!("{declaration}{}", out.trim_matches(java_whitespace)))
}

/// Why Xerces (DOCTYPE refused) rejects `xml`, in its words.
fn well_formed(xml: &str) -> Result<(), String> {
    let text = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let start = text.trim_start_matches([' ', '\t', '\n', '\r']);
    if start.starts_with('&') {
        return Err("Reference is not allowed in prolog.".into());
    }
    let declaration = start.get(..5).is_some_and(|t| t.eq_ignore_ascii_case("<?xml")) && start[5..].starts_with([' ', '\t', '\n', '\r', '?']);
    if declaration && start.len() != text.len() {
        return Err("The processing instruction target matching \"[xX][mM][lL]\" is not allowed.".into());
    }
    match roxmltree::Document::parse(xml) {
        Ok(_) => Ok(()),
        Err(roxmltree::Error::DtdDetected) => {
            let before = xml.split("<!DOCTYPE").next().unwrap_or_default();
            match crate::xsd::well_formedness_error(before).filter(|_| !is_blank(before) && !before.trim_start().starts_with("<?xml")) {
                // an error before the DOCTYPE is met first
                Some(because) if !because.starts_with("XML document structures must start and end") && !because.starts_with("Premature end of file") => Err(because),
                _ => Err("DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.".into()),
            }
        }
        Err(e) => Err(crate::xsd::well_formedness_error(xml).unwrap_or_else(|| e.to_string())),
    }
}

fn parse(xml: &str) -> Result<Vec<Node>, xmlparser::Error> {
    // the open elements, each with the children read so far; the bottom entry holds the document's nodes
    // an element's start tag: prefix, local name and attributes
    type Start = (String, String, Vec<(String, String)>);
    let mut stack: Vec<(Option<Start>, Vec<Node>)> = vec![(None, Vec::new())];
    let mut start: Option<Start> = None;
    for token in Tokenizer::from(xml) {
        match token? {
            Token::ElementStart { prefix, local, .. } => {
                let name = if prefix.is_empty() { local.to_string() } else { format!("{prefix}:{local}") };
                start = Some((name, prefix.to_string(), Vec::new()));
            }
            Token::Attribute { prefix, local, value, .. } => {
                let name = if prefix.is_empty() { local.to_string() } else { format!("{prefix}:{local}") };
                if let Some((_, _, attributes)) = start.as_mut() {
                    attributes.push((name, attribute_value(value.as_str())));
                }
            }
            Token::ElementEnd { end: ElementEnd::Open, .. } => stack.push((start.take(), Vec::new())),
            Token::ElementEnd { end: ElementEnd::Empty, .. } => {
                if let Some((name, prefix, attributes)) = start.take() {
                    stack.last_mut().expect("document level").1.push(Node::Element { name, prefix, attributes, children: Vec::new() });
                }
            }
            Token::ElementEnd { end: ElementEnd::Close(..), .. } => {
                if let Some((Some((name, prefix, attributes)), children)) = stack.pop() {
                    stack.last_mut().expect("document level").1.push(Node::Element { name, prefix, attributes, children });
                }
            }
            Token::Text { text } => {
                // outside the root element only whitespace can appear, which the DOM does not keep
                if stack.len() > 1 {
                    stack.last_mut().expect("document level").1.push(Node::Text(text_value(text.as_str())));
                }
            }
            Token::Cdata { text, .. } => stack.last_mut().expect("document level").1.push(Node::Cdata(line_ends(text.as_str()))),
            Token::Comment { text, .. } => stack.last_mut().expect("document level").1.push(Node::Comment(line_ends(text.as_str()))),
            Token::ProcessingInstruction { target, content, .. } => {
                stack.last_mut().expect("document level").1.push(Node::Instruction(target.to_string(), content.map(|c| line_ends(c.as_str()))))
            }
            _ => {}
        }
    }
    Ok(stack.pop().map(|(_, nodes)| nodes).unwrap_or_default())
}

/// XML's line-end normalisation: `\r\n` and a lone `\r` become `\n`.
fn line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn text_value(raw: &str) -> String {
    resolve(&line_ends(raw))
}

/// Attribute-value normalisation: each literal whitespace character becomes a space; references are resolved after.
fn attribute_value(raw: &str) -> String {
    resolve(&line_ends(raw).replace(['\n', '\t'], " "))
}

/// The predefined entities and character references.
fn resolve(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let Some(semi) = after.find(';') else {
            out.push_str(&rest[amp..]);
            return out;
        };
        let name = &after[..semi];
        let resolved = match name {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "apos" => Some('\''),
            "quot" => Some('"'),
            _ => name
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| name.strip_prefix('#').map(|d| d.parse().ok()))
                .flatten()
                .and_then(char::from_u32),
        };
        match resolved {
            Some(c) => out.push(c),
            None => out.push_str(&rest[amp..amp + 2 + semi]),
        }
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    out
}

/// `removeIndentation`: whitespace-only text between elements goes; deeper than [`MAX_DEPTH`] elements fails.
fn remove_indentation(node: &mut Node, depth: usize) -> Result<(), JError> {
    let Node::Element { children, .. } = node else { return Ok(()) };
    if depth > MAX_DEPTH {
        return Err(illegal(format!("xpath.formatXml: the XML is nested more than {MAX_DEPTH} elements deep")));
    }
    if children.iter().any(|c| matches!(c, Node::Element { .. })) {
        children.retain(|c| !matches!(c, Node::Text(t) if is_blank(t)));
    }
    for child in children.iter_mut() {
        remove_indentation(child, depth + 1)?;
    }
    Ok(())
}

fn indent(out: &mut String, depth: usize) {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', depth * 2));
}

fn write(node: &Node, depth: usize, out: &mut String) {
    match node {
        Node::Text(text) => escape(text, false, out),
        Node::Cdata(text) => {
            out.push_str("<![CDATA[");
            out.push_str(text);
            out.push_str("]]>");
        }
        Node::Comment(text) => {
            out.push_str("<!--");
            out.push_str(text);
            out.push_str("-->");
        }
        Node::Instruction(target, content) => {
            out.push_str("<?");
            out.push_str(target);
            if let Some(content) = content {
                out.push(' ');
                out.push_str(content);
            }
            out.push_str("?>");
        }
        Node::Element { name, prefix, attributes, children } => {
            out.push('<');
            out.push_str(name);
            for (attribute, value) in ordered(prefix, attributes) {
                out.push(' ');
                out.push_str(attribute);
                out.push_str("=\"");
                escape(value, true, out);
                out.push('"');
            }
            if children.is_empty() {
                out.push_str("/>");
                return;
            }
            out.push('>');
            let block = children.iter().any(|c| matches!(c, Node::Element { .. } | Node::Comment(_) | Node::Instruction(..)));
            for child in children {
                if block {
                    if matches!(child, Node::Text(t) if is_blank(t)) {
                        continue;
                    }
                    indent(out, depth + 1);
                }
                write(child, depth + 1, out);
            }
            if block {
                indent(out, depth);
            }
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
    }
}

/// The element's own prefix's declaration, the other declarations, then the attributes, each group by name.
fn ordered<'a>(prefix: &str, attributes: &'a [(String, String)]) -> Vec<&'a (String, String)> {
    let own = if prefix.is_empty() { "xmlns".to_string() } else { format!("xmlns:{prefix}") };
    let declaration = |name: &str| name == "xmlns" || name.starts_with("xmlns:");
    let mut sorted: Vec<&(String, String)> = attributes.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
    let mut ordered: Vec<&(String, String)> = sorted.iter().copied().filter(|(n, _)| *n == own).collect();
    ordered.extend(sorted.iter().copied().filter(|(n, _)| *n != own && declaration(n)));
    ordered.extend(sorted.iter().copied().filter(|(n, _)| !declaration(n)));
    ordered
}

fn escape(text: &str, attribute: bool, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            '\n' if attribute => out.push_str("&#10;"),
            '\t' if attribute => out.push_str("&#9;"),
            '\r' => out.push_str("&#13;"),
            c if c as u32 > 0xFFFF => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
}
