//! Compiles the Public Suffix List into Guava's `PublicSuffixPatterns.TRIE` form (`trieData`, `stringPool`), the trie
//! `InternetDomainName.isPublicSuffix` reads (`PublicSuffixTrie`). `build.rs` runs it over the unmodified list in
//! `third_party/publicsuffix/public_suffix_list.dat`, and `cors_origin` embeds the two arrays it writes.
//!
//! The output is byte for byte the trie of Guava 33.7.2, the version shaded into the oracle's mockserver-deps.jar: the
//! list at publicsuffix/list e1b8015c (2026-07-25, the list's head when Guava last synced it, 2026-08-11) with
//! `GUAVA_EXTRA_RULES` gives exactly the arrays dumped from the oracle before this generator existed. The layout of
//! Guava's (unpublished) generator, read back from those arrays:
//! - every rule with a non-ASCII label is also added with each such label in Punycode (`xn--`, RFC 3492);
//! - nodes are numbered breadth first from the root (node 0), each node's children in UTF-16 order (the order
//!   `PublicSuffixTrie.findChild`'s binary search compares in); a leaf's first-child field is 0;
//! - a node's flags are its child count (bits 0-10), an exclusion `!rule` (bit 11), a wildcard `*.rule` type (bits
//!   12-13) and an exact rule type (bits 14-15), the types 1 for the ICANN section and 2 for the private one;
//! - the string pool holds each distinct label once, length-prefixed, in the order nodes first use them, the labels
//!   with Latin-1 characters only before the others (Guava's "Compact Strings" arrangement).
//!
//! Included by `build.rs` with `#[path]`; it uses nothing but std.

use std::collections::{BTreeMap, HashMap, VecDeque};

/// Rules Guava 33.7.2's trie holds that the public list it was built from does not: `pp.ni` and the retired TLDs
/// `pramerica` and `wolterskluwer` (the last left the public list in early 2026), all as ICANN rules. They come from
/// Guava's own copy of the list; the oracle answers them as public suffixes, so we do too.
pub const GUAVA_EXTRA_RULES: [&str; 3] = ["pp.ni", "pramerica", "wolterskluwer"];

const ICANN: u16 = 1;
const PRIVATE: u16 = 2;

#[derive(Default)]
struct Node {
    children: BTreeMap<Vec<u16>, usize>,
    exact: u16,
    wildcard: u16,
    exclusion: u16,
}

/// The trie of `list` (the text of `public_suffix_list.dat`) and `extra` (ICANN rules), as `(trie_data, string_pool)`.
pub fn generate(list: &str, extra: &[&str]) -> (Vec<u16>, Vec<u16>) {
    let mut nodes = vec![Node::default()];
    let mut section = ICANN;
    for line in list.lines() {
        let line = line.trim();
        if line.contains("===BEGIN ICANN DOMAINS===") {
            section = ICANN;
        } else if line.contains("===BEGIN PRIVATE DOMAINS===") {
            section = PRIVATE;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        add_with_punycode(&mut nodes, line.split_whitespace().next().unwrap(), section);
    }
    for rule in extra {
        add_with_punycode(&mut nodes, rule, ICANN);
    }

    let mut order = Vec::with_capacity(nodes.len());
    let mut labels: Vec<Option<&[u16]>> = vec![None; nodes.len()];
    let mut queue = VecDeque::from([0usize]);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for (label, &child) in &nodes[node].children {
            labels[child] = Some(label.as_slice());
            queue.push_back(child);
        }
    }
    let mut first_use: Vec<&[u16]> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for &node in &order[1..] {
        let label = labels[node].unwrap();
        if seen.insert(label) {
            first_use.push(label);
        }
    }
    let latin1 = |label: &[u16]| label.iter().all(|&unit| unit < 256);
    let mut pool = Vec::new();
    let mut offsets: HashMap<&[u16], u16> = HashMap::new();
    for label in first_use.iter().filter(|l| latin1(l)).chain(first_use.iter().filter(|l| !latin1(l))) {
        offsets.insert(*label, unit(pool.len()));
        pool.push(unit(label.len()));
        pool.extend_from_slice(label);
    }

    let mut index = vec![0usize; nodes.len()];
    for (i, &node) in order.iter().enumerate() {
        index[node] = i;
    }
    let mut trie = Vec::with_capacity(order.len() * 3);
    for &node in &order {
        let n = &nodes[node];
        trie.push(labels[node].map_or(0, |label| offsets[label]));
        trie.push(n.children.values().next().map_or(0, |&first| unit(index[first])));
        let count = n.children.len();
        assert!(count <= 0x7ff, "a public-suffix node has more children than Guava's trie can hold");
        trie.push(unit(count) | n.exclusion << 11 | n.wildcard << 12 | n.exact << 14);
    }
    (trie, pool)
}

fn unit(value: usize) -> u16 {
    u16::try_from(value).expect("the public-suffix trie outgrew Guava's 16-bit layout")
}

fn add_with_punycode(nodes: &mut Vec<Node>, rule: &str, section: u16) {
    add(nodes, rule, section);
    let (prefix, name) = split_rule(rule);
    if !name.is_ascii() {
        let ascii: Vec<String> =
            name.split('.').map(|label| if label.is_ascii() { label.to_string() } else { format!("xn--{}", punycode(label)) }).collect();
        add(nodes, &format!("{prefix}{}", ascii.join(".")), section);
    }
}

fn split_rule(rule: &str) -> (&str, &str) {
    if let Some(name) = rule.strip_prefix('!') {
        ("!", name)
    } else if let Some(name) = rule.strip_prefix("*.") {
        ("*.", name)
    } else {
        ("", rule)
    }
}

fn add(nodes: &mut Vec<Node>, rule: &str, section: u16) {
    let (prefix, name) = split_rule(rule);
    let mut node = 0;
    for label in name.rsplit('.') {
        let key: Vec<u16> = label.encode_utf16().collect();
        node = match nodes[node].children.get(&key) {
            Some(&child) => child,
            None => {
                nodes.push(Node::default());
                let child = nodes.len() - 1;
                nodes[node].children.insert(key, child);
                child
            }
        };
    }
    match prefix {
        "!" => nodes[node].exclusion = 1,
        "*." => nodes[node].wildcard = section,
        _ => nodes[node].exact = section,
    }
}

/// RFC 3492 Punycode of one label (without the `xn--` prefix).
fn punycode(label: &str) -> String {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    let digit = |d: u32| char::from(if d < 26 { b'a' + d as u8 } else { b'0' + (d - 26) as u8 });
    let adapt = |delta: u32, points: u32, first: bool| {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    };
    let points: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = out.len() as u32;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias, mut handled) = (128u32, 0u32, 72u32, basic);
    while (handled as usize) < points.len() {
        let m = points.iter().copied().filter(|&c| c >= n).min().unwrap();
        delta += (m - n) * (handled + 1);
        n = m;
        for &c in &points {
            if c < n {
                delta += 1;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias { TMIN } else if k >= bias + TMAX { TMAX } else { k - bias };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    out
}
