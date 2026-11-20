//! `ExpectationExportSerializer.serializeAsBrunoCollection`: expectations as a Bruno collection ZIP — `bruno.json`,
//! `environments/local.bru` and one `.bru` file per expectation.

use std::io::Write;

use serde_json::{Value, json};

use super::{Expectation, entries, plain};

pub fn serialize(expectations: &[Expectation]) -> Vec<u8> {
    let mut files: Vec<(String, String)> = Vec::new();
    let manifest = json!({"version": "1", "name": super::COLLECTION_NAME, "type": "collection"});
    files.push(("bruno.json".into(), crate::json::pretty(&manifest)));
    files.push(("environments/local.bru".into(), "vars {\n  baseUrl: http://localhost:1080\n}\n".into()));
    let mut names: Vec<(String, usize)> = Vec::new();
    for (i, e) in expectations.iter().enumerate() {
        files.push((filename(e, &mut names), request_file(e, i + 1)));
    }
    zip(&files)
}

fn method_and_path(e: &Expectation, default_path: &str) -> (String, String) {
    let empty = json!({});
    let request = e.request.as_ref().unwrap_or(&empty);
    let method = match e.request.as_ref() {
        Some(r) => r.get("method").and_then(plain).unwrap_or_default(),
        None => "GET".into(),
    };
    let path = request.get("path").and_then(plain).unwrap_or_else(|| default_path.into());
    (method, path)
}

/// `brunoFilename`: the method and path, non-alphanumerics as dashes, numbered when repeated.
fn filename(e: &Expectation, names: &mut Vec<(String, usize)>) -> String {
    let (method, path) = method_and_path(e, "root");
    let base = sanitise(&format!("{}{path}", method.to_lowercase()));
    let count = match names.iter_mut().find(|(n, _)| *n == base) {
        Some((_, c)) => {
            *c += 1;
            *c
        }
        None => {
            names.push((base.clone(), 1));
            1
        }
    };
    if count == 1 { format!("{base}.bru") } else { format!("{base}-{count}.bru") }
}

fn sanitise(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    // `replaceAll("^-|-$", "")`: one dash at each end.
    let out = out.strip_prefix('-').unwrap_or(&out);
    let out = out.strip_suffix('-').unwrap_or(out).to_string();
    let out = if out.is_empty() { "request".to_string() } else { out };
    out.chars().take(80).collect()
}

fn request_file(e: &Expectation, seq: usize) -> String {
    let (method, path) = method_and_path(e, "/");
    let method = if method.is_empty() { "get".to_string() } else { method.to_lowercase() };
    let empty = json!({});
    let request = e.request.as_ref().unwrap_or(&empty);
    let slashed = if path.starts_with('/') { path.clone() } else { format!("/{path}") };
    let mut out = format!("meta {{\n  name: {} {path}\n  type: http\n  seq: {seq}\n}}\n\n", method.to_uppercase());
    out.push_str(&format!("{method} {{\n  url: {{{{baseUrl}}}}{slashed}"));
    let query = entries(request.get("queryStringParameters"));
    if !query.is_empty() {
        out.push('?');
        let parts: Vec<String> = query.iter().map(|(k, vs)| format!("{}={}", plain(k).unwrap_or_default(), vs.first().and_then(plain).unwrap_or_default())).collect();
        out.push_str(&parts.join("&"));
    }
    out.push_str("\n}\n");
    let headers = entries(request.get("headers"));
    if !headers.is_empty() {
        out.push_str("\nheaders {\n");
        for (k, vs) in &headers {
            out.push_str(&format!("  {}: {}\n", plain(k).unwrap_or_default(), vs.first().and_then(plain).unwrap_or_default()));
        }
        out.push_str("}\n");
    }
    let content_type = super::first_header_value(request.get("headers"), "content-type");
    let body = request.get("body").filter(|b| !b.is_null()).map(|b| super::body_text(b, content_type.as_deref())).filter(|b| !b.is_empty());
    if let Some(body) = body {
        let mode = if super::detect_content_type(&body).contains("json") { "json" } else { "text" };
        out.push_str(&format!("\nbody:{mode} {{\n"));
        for line in body.split('\n') {
            out.push_str(&format!("  {line}\n"));
        }
        out.push_str("}\n");
    }
    if let Some(response) = &e.response {
        let code = response.get("statusCode").and_then(Value::as_i64).unwrap_or(200);
        out.push_str(&format!("\ndocs {{\n  Expected response: {code}\n"));
        let content_type = super::first_header_value(response.get("headers"), "content-type");
        let body = response.get("body").filter(|b| !b.is_null()).map(|b| super::body_text(b, content_type.as_deref())).filter(|b| !b.is_empty());
        if let Some(body) = body {
            out.push_str(&format!("  Body: {}\n", body.replace('\n', " ")));
        }
        out.push_str("}\n");
    }
    out
}

/// A ZIP archive of `files`, deflated, as `ZipOutputStream` writes one (entries stamped with the current time).
fn zip(files: &[(String, String)]) -> Vec<u8> {
    let now = chrono::Local::now().naive_local();
    use chrono::{Datelike, Timelike};
    let time = ((now.hour() << 11) | (now.minute() << 5) | (now.second() / 2)) as u16;
    let date = (((now.year() - 1980).max(0) as u32) << 9 | (now.month() << 5) | now.day()) as u16;
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, content) in files {
        let data = content.as_bytes();
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("in-memory deflate");
        let compressed = encoder.finish().expect("in-memory deflate");
        let offset = out.len() as u32;
        let header = |signature: u32, central_entry: bool| {
            let mut h: Vec<u8> = Vec::new();
            h.extend_from_slice(&signature.to_le_bytes());
            if central_entry {
                h.extend_from_slice(&20u16.to_le_bytes());
            }
            h.extend_from_slice(&20u16.to_le_bytes());
            h.extend_from_slice(&0x0800u16.to_le_bytes());
            h.extend_from_slice(&8u16.to_le_bytes());
            h.extend_from_slice(&time.to_le_bytes());
            h.extend_from_slice(&date.to_le_bytes());
            h.extend_from_slice(&crc.sum().to_le_bytes());
            h.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes());
            if central_entry {
                h.extend_from_slice(&0u16.to_le_bytes());
                h.extend_from_slice(&0u16.to_le_bytes());
                h.extend_from_slice(&0u16.to_le_bytes());
                h.extend_from_slice(&0u32.to_le_bytes());
                h.extend_from_slice(&offset.to_le_bytes());
            }
            h.extend_from_slice(name.as_bytes());
            h
        };
        out.extend(header(0x0403_4b50, false));
        out.extend_from_slice(&compressed);
        central.extend(header(0x0201_4b50, true));
    }
    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend(central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}
