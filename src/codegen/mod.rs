//! Code formats of `retrieve` (§1.4): Java builder code, and the other languages, which embed each expectation's
//! JSON in a client call (`org.mockserver.serialization.code`).

pub mod java;

/// A code format other than Java: its content type and how it wraps each expectation's JSON.
#[derive(Clone, Copy)]
pub enum Language {
    JavaScript,
    Python,
    Go,
    CSharp,
    Ruby,
    Rust,
    Php,
}

impl Language {
    pub fn parse(format: &str) -> Option<Language> {
        Some(match format {
            "JAVASCRIPT" => Language::JavaScript,
            "PYTHON" => Language::Python,
            "GO" => Language::Go,
            "CSHARP" => Language::CSharp,
            "RUBY" => Language::Ruby,
            "RUST" => Language::Rust,
            "PHP" => Language::Php,
            _ => return None,
        })
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Language::JavaScript => "application/javascript",
            Language::Python => "text/x-python",
            Language::Go => "text/x-go",
            Language::CSharp => "text/x-csharp",
            Language::Ruby => "text/x-ruby",
            Language::Rust => "text/x-rust",
            Language::Php => "application/x-httpd-php",
        }
    }

    /// `ExpectationTo<Language>Serializer.serialize`, given each expectation's JSON (see [`default_values`]).
    pub fn serialize(self, expectations: &[String]) -> String {
        let mut out = String::new();
        match self {
            Language::JavaScript => {
                out.push_str("const { mockServerClient } = require('mockserver-client');\n");
                for json in expectations {
                    out.push_str(&format!("\nmockServerClient(\"localhost\", 1080).mockAnyResponse({json});\n"));
                }
            }
            Language::Python => {
                out.push_str("import json\nfrom mockserver import MockServerClient, Expectation\n\nclient = MockServerClient(\"localhost\", 1080)\n");
                for json in expectations {
                    out.push_str(&format!("\nclient.upsert(Expectation.from_dict(json.loads(\"\"\"{json}\"\"\")))\n"));
                }
            }
            Language::Go => {
                out.push_str("package main\n\nimport (\n\t\"encoding/json\"\n\n\tmockserver \"github.com/mock-server/mockserver-monorepo/mockserver-client-go/v9\"\n)\n\nfunc main() {\n\tclient := mockserver.New(\"localhost\", 1080)\n");
                for json in expectations {
                    out.push_str(&format!("\n\tvar e mockserver.Expectation\n\t_ = json.Unmarshal([]byte({}), &e)\n\tclient.Upsert(e)\n", go_literal(json)));
                }
                out.push_str("}\n");
            }
            Language::CSharp => {
                out.push_str("using System.Text.Json;\nusing System.Text.Json.Serialization;\nusing MockServer.Client;\nusing MockServer.Client.Models;\n\nvar jsonOptions = new JsonSerializerOptions\n{\n    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,\n    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull\n};\n\nvar client = new MockServerClient(\"localhost\", 1080);\n");
                for json in expectations {
                    out.push_str(&format!("\nclient.Upsert(JsonSerializer.Deserialize<Expectation>(@\"{}\", jsonOptions));\n", json.replace('"', "\"\"")));
                }
            }
            Language::Ruby => {
                out.push_str("require 'mockserver-client'\nrequire 'json'\n\nclient = MockServer::Client.new('localhost', 1080)\n");
                for json in expectations {
                    out.push_str(&format!("\nclient.upsert(MockServer::Expectation.from_hash(JSON.parse(<<JSON)))\n{json}\nJSON\n"));
                }
            }
            Language::Rust => {
                out.push_str("use mockserver_client::{ClientBuilder, Expectation};\n\nfn main() -> Result<(), Box<dyn std::error::Error>> {\n    let client = ClientBuilder::new(\"localhost\", 1080).build()?;\n");
                for json in expectations {
                    let hashes = raw_string_hashes(json);
                    out.push_str(&format!("\n    client.upsert(&[serde_json::from_str::<Expectation>(r{hashes}\"{json}\"{hashes})?])?;\n"));
                }
                out.push_str("\n    Ok(())\n}\n");
            }
            Language::Php => {
                out.push_str("<?php\n\nuse MockServer\\MockServerClient;\nuse MockServer\\Expectation;\n\n$client = new MockServerClient('localhost', 1080);\n");
                for json in expectations {
                    out.push_str(&format!("\n$client->upsertExpectation(Expectation::fromArray(json_decode(<<<'JSON'\n{json}\nJSON, true)));\n"));
                }
            }
        }
        out
    }
}

/// A raw string literal when the JSON has no backtick, else an interpreted string with Go escapes.
fn go_literal(json: &str) -> String {
    if !json.contains('`') {
        return format!("`{json}`");
    }
    let mut out = String::from("\"");
    for c in json.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The fewest `#`s such that no `"` in the JSON is followed by that many.
fn raw_string_hashes(json: &str) -> String {
    let longest = json
        .match_indices('"')
        .map(|(i, _)| json[i + 1..].chars().take_while(|c| *c == '#').count())
        .max()
        .unwrap_or(0);
    "#".repeat(longest + 1)
}
