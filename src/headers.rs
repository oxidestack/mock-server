//! A request's headers as one text buffer and one index of offsets: what a parsed request carries and the event log
//! retains. A `Vec<(String, Vec<String>)>` took three allocations a header (its name, its value list, its value),
//! and as many frees when the log let the request go; this takes two for the whole map, however many headers it holds.
//!
//! The entries keep [`crate::request::MultiMap`]'s shape: each a name with its values, in first-occurrence order, a
//! name with no values allowed, and two entries may carry the same name (as `Vec::push` made them).

use crate::request::MultiMap;

/// The headers of a request: names and values back to back in `text`, one [`Pair`] per value in `pairs`.
#[derive(Clone)]
pub struct Headers {
    text: String,
    /// One per value, grouped by entry: the first pair of an entry carries [`FIRST`] in `name_len`; an entry without
    /// values is one pair whose value is [`NO_VALUE`].
    pairs: Vec<Pair>,
    /// The first pair of the first `Content-Type` entry, or [`NONE`]: the header every body matcher reads, once for
    /// each expectation it is tried against, found without comparing names.
    content_type: u32,
}

impl Default for Headers {
    fn default() -> Headers {
        Headers::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Pair {
    name: u32,
    /// The name's length, with [`FIRST`] on an entry's first pair.
    name_len: u32,
    value: u32,
    value_len: u32,
}

const FIRST: u32 = 1 << 31;
const NO_VALUE: u32 = u32::MAX;
const NONE: u32 = u32::MAX;

impl Pair {
    fn first(&self) -> bool {
        self.name_len & FIRST != 0
    }

    fn name<'a>(&self, text: &'a str) -> &'a str {
        let start = self.name as usize;
        &text[start..start + (self.name_len & !FIRST) as usize]
    }

    fn value<'a>(&self, text: &'a str) -> &'a str {
        let start = self.value as usize;
        &text[start..start + self.value_len as usize]
    }
}

/// An offset into the text: header blocks are bounded far below 4 GiB (`maxHeaderSize`), a request built from JSON too.
fn offset(n: usize) -> u32 {
    u32::try_from(n).expect("headers under 2 GiB")
}

impl Headers {
    pub fn new() -> Headers {
        Headers { text: String::new(), pairs: Vec::new(), content_type: NONE }
    }

    /// Room for `text` bytes of names and values and `values` values without growing.
    pub fn with_capacity(text: usize, values: usize) -> Headers {
        Headers { text: String::with_capacity(text), pairs: Vec::with_capacity(values), content_type: NONE }
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.pairs.iter().filter(|p| p.first()).count()
    }

    /// The entries, each a name and its values, in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter { text: &self.text, pairs: &self.pairs }
    }

    /// Every (name, value) pair, in order.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> + Clone + '_ {
        self.pairs.iter().filter(|p| p.value != NO_VALUE).map(|p| (p.name(&self.text), p.value(&self.text)))
    }

    /// The values of the first entry named `name` in any case; `None` when there is none.
    pub fn get(&self, name: &str) -> Option<Values<'_>> {
        let at = self.find(name)?;
        let values = if self.pairs[at].value == NO_VALUE { &self.pairs[at..at] } else { &self.pairs[at..self.entry_end(at)] };
        Some(Values::Packed { text: &self.text, pairs: values })
    }

    /// The first value of the first entry named `name` in any case ([`crate::request::first`]).
    pub fn first(&self, name: &str) -> Option<&str> {
        let head = self.pairs[self.find(name)?];
        (head.value != NO_VALUE).then(|| head.value(&self.text))
    }

    /// The first value of the first `Content-Type` entry: [`Headers::first`] of `content-type`, without a search.
    pub fn content_type(&self) -> Option<&str> {
        let head = self.pairs.get(self.content_type as usize)?;
        (head.value != NO_VALUE).then(|| head.value(&self.text))
    }

    /// Notes the entry head just pushed last when it is the first `Content-Type`.
    fn noted(&mut self, name: &str) {
        if self.content_type == NONE && name.eq_ignore_ascii_case("content-type") {
            self.content_type = offset(self.pairs.len() - 1);
        }
    }

    /// Whether an entry is named `name` in any case.
    pub fn contains(&self, name: &str) -> bool {
        self.find(name).is_some()
    }

    /// The first pair of the first entry named `name` in any case: the names compared as bytes, a length first, with
    /// no entry walked whole (a JSON body matcher asks for the content type once per expectation it is tried against).
    fn find(&self, name: &str) -> Option<usize> {
        let (text, name) = (self.text.as_bytes(), name.as_bytes());
        self.pairs.iter().position(|p| {
            let start = p.name as usize;
            p.name_len == (name.len() as u32 | FIRST) && text[start..start + name.len()].eq_ignore_ascii_case(name)
        })
    }

    /// The bytes the map holds on the heap.
    pub fn heap_bytes(&self) -> usize {
        self.text.capacity() + self.pairs.capacity() * std::mem::size_of::<Pair>()
    }

    fn push_text(&mut self, s: &str) -> (u32, u32) {
        let start = offset(self.text.len());
        self.text.push_str(s);
        (start, offset(s.len()))
    }

    /// A new entry `name` with `values` at the end, whatever entries are named so already (`Vec::push`).
    pub fn push_entry<'v>(&mut self, name: &str, values: impl IntoIterator<Item = &'v str>) {
        let (n, n_len) = self.push_text(name);
        let head = self.pairs.len();
        let mut first = FIRST;
        for v in values {
            let (value, value_len) = self.push_text(v);
            self.pairs.push(Pair { name: n, name_len: n_len | first, value, value_len });
            first = 0;
        }
        if first != 0 {
            self.pairs.push(Pair { name: n, name_len: n_len | FIRST, value: NO_VALUE, value_len: 0 });
        }
        if self.content_type == NONE && name.eq_ignore_ascii_case("content-type") {
            self.content_type = offset(head);
        }
    }

    /// A new entry `name` with the one value `value` writes, at the end (`Vec::push`): a number without a `String`.
    pub fn push_entry_display(&mut self, name: &str, value: impl std::fmt::Display) {
        use std::fmt::Write;
        let (n, n_len) = self.push_text(name);
        let start = self.text.len();
        let _ = write!(self.text, "{value}");
        let value_len = offset(self.text.len() - start);
        self.pairs.push(Pair { name: n, name_len: n_len | FIRST, value: offset(start), value_len });
        self.noted(name);
    }

    /// The index of the pair after entry `at`'s last.
    fn entry_end(&self, at: usize) -> usize {
        at + 1 + self.pairs[at + 1..].iter().take_while(|p| !p.first()).count()
    }

    /// Appends `value` to the first entry `same` accepts the name of, else to a new entry `name`.
    fn add(&mut self, name: &str, value: &str, same: impl Fn(&str, &str) -> bool) {
        self.add_with(name, |text| text.push_str(value), same);
    }

    /// [`Headers::add`] of the value `write` appends to the text.
    fn add_with(&mut self, name: &str, write: impl FnOnce(&mut String), same: impl Fn(&str, &str) -> bool) {
        let found = (0..self.pairs.len()).find(|&i| self.pairs[i].first() && same(self.pairs[i].name(&self.text), name));
        let written = |h: &mut Headers| {
            let start = h.text.len();
            write(&mut h.text);
            (offset(start), offset(h.text.len() - start))
        };
        let Some(at) = found else {
            let (n, n_len) = self.push_text(name);
            let (value, value_len) = written(self);
            self.pairs.push(Pair { name: n, name_len: n_len | FIRST, value, value_len });
            self.noted(name);
            return;
        };
        let (v, v_len) = written(self);
        let head = self.pairs[at];
        if head.value == NO_VALUE {
            self.pairs[at] = Pair { value: v, value_len: v_len, ..head };
            return;
        }
        let end = self.entry_end(at);
        self.pairs.insert(end, Pair { name: head.name, name_len: head.name_len & !FIRST, value: v, value_len: v_len });
        if self.content_type != NONE && end as u32 <= self.content_type {
            self.content_type += 1;
        }
    }

    /// Appends `value` under `name`, merging with an entry of the same name in any case ([`crate::request::push`]).
    pub fn push_merged(&mut self, name: &str, value: &str) {
        self.add(name, value, |a, b| a.eq_ignore_ascii_case(b));
    }

    /// Appends `value` under `name`, merging only with an entry of exactly that name ([`crate::request::append`]).
    pub fn append(&mut self, name: &str, value: &str) {
        self.add(name, value, |a, b| a == b);
    }

    /// [`Headers::append`] of a value as Netty reads one off the wire: one char per byte ([`crate::request::header_text`]).
    pub fn append_wire(&mut self, name: &str, value: &[u8]) {
        self.add_with(
            name,
            |text| match value.is_ascii() {
                true => text.push_str(std::str::from_utf8(value).unwrap_or_default()),
                false => text.extend(value.iter().map(|b| *b as char)),
            },
            |a, b| a == b,
        );
    }

    /// [`Headers::append_wire`] of a name read off the wire too.
    pub fn append_wire_pair(&mut self, name: &[u8], value: &[u8]) {
        match std::str::from_utf8(name) {
            Ok(name) if name.is_ascii() => self.append_wire(name, value),
            _ => self.append_wire(&crate::request::header_text(name), value),
        }
    }

    /// `entry` at the end, as `Vec::push` adds one to a [`MultiMap`].
    pub fn push(&mut self, (name, values): (String, Vec<String>)) {
        self.push_entry(&name, values.iter().map(String::as_str));
    }

    /// `entry` at `index` among the entries, as `Vec::insert`.
    pub fn insert(&mut self, index: usize, (name, values): (String, Vec<String>)) {
        let mut out = Headers::with_capacity(self.text.len() + name.len() + values.iter().map(String::len).sum::<usize>(), self.pairs.len() + values.len().max(1));
        for (i, (k, v)) in self.iter().enumerate() {
            if i == index {
                out.push_entry(&name, values.iter().map(String::as_str));
            }
            out.push_entry(k, v);
        }
        if index >= self.len() {
            out.push_entry(&name, values.iter().map(String::as_str));
        }
        *self = out;
    }

    /// No entries left.
    pub fn clear(&mut self) {
        self.text.clear();
        self.pairs.clear();
        self.content_type = NONE;
    }

    /// Keeps the entries `keep` accepts, in order; each is asked once.
    pub fn retain(&mut self, mut keep: impl FnMut(&(&str, Values<'_>)) -> bool) {
        let mut out: Option<Headers> = None;
        for (i, entry) in self.iter().enumerate() {
            let kept = keep(&entry);
            match &mut out {
                Some(out) if kept => out.push_entry(entry.0, entry.1),
                Some(_) => {}
                None if kept => {}
                None => {
                    let mut built = Headers::with_capacity(self.text.len(), self.pairs.len());
                    for (k, v) in self.iter().take(i) {
                        built.push_entry(k, v);
                    }
                    out = Some(built);
                }
            }
        }
        if let Some(out) = out {
            *self = out;
        }
    }

    /// Removes every entry named `name` in any case.
    pub fn remove(&mut self, name: &str) {
        self.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Rewrites the entries through a [`MultiMap`]: for the rare edit in place (redaction, sorting, renaming).
    pub fn edit<R>(&mut self, f: impl FnOnce(&mut MultiMap) -> R) -> R {
        let mut map = self.to_multimap();
        let r = f(&mut map);
        *self = Headers::from(&map);
        r
    }

    /// The entries as a [`MultiMap`], for code that rewrites them in place.
    pub fn to_multimap(&self) -> MultiMap {
        self.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
    }
}

impl From<&MultiMap> for Headers {
    fn from(map: &MultiMap) -> Headers {
        let text = map.iter().map(|(k, vs)| k.len() + vs.iter().map(String::len).sum::<usize>()).sum();
        let mut out = Headers::with_capacity(text, map.iter().map(|(_, vs)| vs.len().max(1)).sum());
        for (k, vs) in map {
            out.push_entry(k, vs.iter().map(String::as_str));
        }
        out
    }
}

impl From<MultiMap> for Headers {
    fn from(map: MultiMap) -> Headers {
        Headers::from(&map)
    }
}

impl FromIterator<(String, Vec<String>)> for Headers {
    fn from_iter<I: IntoIterator<Item = (String, Vec<String>)>>(iter: I) -> Headers {
        let mut out = Headers::new();
        for (k, vs) in iter {
            out.push_entry(&k, vs.iter().map(String::as_str));
        }
        out
    }
}

impl Extend<(String, Vec<String>)> for Headers {
    fn extend<I: IntoIterator<Item = (String, Vec<String>)>>(&mut self, iter: I) {
        for entry in iter {
            self.push(entry);
        }
    }
}

impl PartialEq for Headers {
    fn eq(&self, other: &Headers) -> bool {
        self.pairs.len() == other.pairs.len() && self.iter().eq(other.iter())
    }
}

impl Eq for Headers {}

impl PartialEq<MultiMap> for Headers {
    fn eq(&self, other: &MultiMap) -> bool {
        self.iter().eq(other.iter().map(|(k, vs)| (k.as_str(), Values::Strings(vs))))
    }
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a str, Values<'a>);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// The entries of [`Headers`].
#[derive(Clone)]
pub struct Iter<'a> {
    text: &'a str,
    pairs: &'a [Pair],
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, Values<'a>);

    fn next(&mut self) -> Option<(&'a str, Values<'a>)> {
        let (head, rest) = self.pairs.split_first()?;
        let len = 1 + rest.iter().take_while(|p| !p.first()).count();
        let (entry, rest) = self.pairs.split_at(len);
        self.pairs = rest;
        let values = if head.value == NO_VALUE { &entry[..0] } else { entry };
        Some((head.name(self.text), Values::Packed { text: self.text, pairs: values }))
    }
}

/// The values of one entry.
#[derive(Clone, Copy)]
pub enum Values<'a> {
    Packed { text: &'a str, pairs: &'a [Pair] },
    /// A [`MultiMap`] entry's, to compare with.
    Strings(&'a [String]),
}

impl<'a> Values<'a> {
    pub fn len(&self) -> usize {
        match self {
            Values::Packed { pairs, .. } => pairs.len(),
            Values::Strings(s) => s.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, i: usize) -> Option<&'a str> {
        match *self {
            Values::Packed { text, pairs } => pairs.get(i).map(|p| p.value(text)),
            Values::Strings(s) => s.get(i).map(String::as_str),
        }
    }

    pub fn first(&self) -> Option<&'a str> {
        self.get(0)
    }

    pub fn last(&self) -> Option<&'a str> {
        self.len().checked_sub(1).and_then(|i| self.get(i))
    }

    pub fn iter(&self) -> ValueIter<'a> {
        ValueIter { values: *self, at: 0 }
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.iter().map(str::to_string).collect()
    }

    /// The values joined by `separator`.
    pub fn join(&self, separator: &str) -> String {
        let mut out = String::new();
        for (i, v) in self.iter().enumerate() {
            if i > 0 {
                out.push_str(separator);
            }
            out.push_str(v);
        }
        out
    }

    pub fn contains(&self, value: &str) -> bool {
        self.iter().any(|v| v == value)
    }
}

impl PartialEq for Values<'_> {
    fn eq(&self, other: &Values<'_>) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl std::fmt::Debug for Values<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for Values<'a> {
    type Item = &'a str;
    type IntoIter = ValueIter<'a>;
    fn into_iter(self) -> ValueIter<'a> {
        self.iter()
    }
}

/// The values of one entry, in order.
#[derive(Clone)]
pub struct ValueIter<'a> {
    values: Values<'a>,
    at: usize,
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let v = self.values.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.values.len() - self.at;
        (left, Some(left))
    }
}

impl ExactSizeIterator for ValueIter<'_> {}

/// What a request matcher's map reads: [`Headers`] or a [`MultiMap`] (query, path and body parameters), each an
/// ordered list of names with their values, borrowed.
pub trait Entries {
    fn entries(&self) -> impl Iterator<Item = (&str, Values<'_>)> + Clone;
}

impl Entries for Headers {
    fn entries(&self) -> impl Iterator<Item = (&str, Values<'_>)> + Clone {
        self.iter()
    }
}

impl Entries for MultiMap {
    fn entries(&self) -> impl Iterator<Item = (&str, Values<'_>)> + Clone {
        self.iter().map(|(k, vs)| (k.as_str(), Values::Strings(vs)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(h: &Headers) -> MultiMap {
        h.to_multimap()
    }

    #[test]
    fn entries_group_values_in_first_occurrence_order() {
        let mut h = Headers::new();
        h.append("Host", "a");
        h.append("Accept", "x");
        h.append("Host", "b");
        h.append("host", "c");
        h.push_merged("ACCEPT", "y");
        assert_eq!(map(&h), vec![("Host".into(), vec!["a".into(), "b".into()]), ("Accept".into(), vec!["x".into(), "y".into()]), ("host".into(), vec!["c".into()])]);
        assert_eq!(h.first("HOST"), Some("a"));
        assert_eq!(h.content_type(), None);
        h.append("X", "1");
        h.append("Content-Type", "text/plain");
        h.append("CONTENT-TYPE", "application/json");
        h.append("Accept", "z");
        assert_eq!(h.content_type(), Some("text/plain"));
        h.remove("content-type");
        assert_eq!(h.content_type(), None);
        h.insert(0, ("content-type".into(), vec![]));
        assert_eq!(h.content_type(), None);
        h.push_merged("Content-type", "a/b");
        assert_eq!(h.content_type(), Some("a/b"));
        assert_eq!(h.first("content-type"), h.content_type());
        assert_eq!(h.len(), 5);
        // a value added to an entry before it moves the content type's pair along
        let mut h = Headers::new();
        h.append("A", "1");
        h.append("Content-Type", "t");
        h.append("A", "2");
        assert_eq!(h.content_type(), Some("t"));
        assert_eq!(h.get("a").map(|v| v.to_vec()), Some(vec!["1".to_string(), "2".to_string()]));
    }

    #[test]
    fn an_entry_without_values_and_empty_strings_stay_apart() {
        let m: MultiMap = vec![("".into(), vec!["".into()]), ("".into(), vec![]), ("a".into(), vec![]), ("b".into(), vec!["".into(), "1".into()])];
        let mut h = Headers::from(&m);
        assert_eq!(map(&h), m);
        assert!(h == m);
        assert_eq!(h.first("a"), None);
        h.push_merged("a", "v");
        assert_eq!(h.get("a").unwrap().to_vec(), vec!["v".to_string()]);
        h.retain(|(k, _)| *k != "b");
        assert_eq!(h.len(), 3);
        h.remove("A");
        assert_eq!(h.len(), 2);
    }

    /// What the event log keeps of every request: its rare parts boxed, so they cost nothing when absent.
    #[test]
    fn retained_types_stay_small() {
        assert!(size_of::<Headers>() <= 56, "{}", size_of::<Headers>());
        assert!(size_of::<crate::request::HttpRequest>() <= 384, "{}", size_of::<crate::request::HttpRequest>());
        assert!(size_of::<crate::recorded::Exchange>() <= 112, "{}", size_of::<crate::recorded::Exchange>());
    }
}
