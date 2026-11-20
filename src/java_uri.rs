//! The parts of a URI as `java.net.URI` reads them (RFC 2396, with Java's fallback to a registry-based authority
//! whose host is `null`), for the code paths that read one: the AMQP client's `ConnectionFactory.setUri`, the
//! Schema Registry client's `URI.create`, the importers' `new URI(url)`, X.509 `URIName`s. Only the parts they read
//! are kept.

/// A parsed URI: `getScheme`, `getRawUserInfo`, `getHost`, `getPort`, `getRawPath`, `getRawQuery`.
#[derive(Debug, Default, PartialEq)]
pub struct JavaUri {
    pub scheme: Option<String>,
    pub raw_user_info: Option<String>,
    /// `getRawAuthority`: everything between `//` and the path, `None` without one.
    pub raw_authority: Option<String>,
    pub host: Option<String>,
    pub port: i32,
    /// `None` for an opaque URI.
    pub raw_path: Option<String>,
    pub raw_query: Option<String>,
}

const MARK: &str = "-_.!~*'()";

fn unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || MARK.contains(c)
}

/// Java's "other" category: non-ASCII characters that are not controls or spaces.
fn other(c: char) -> bool {
    !c.is_ascii() && !c.is_control() && !c.is_whitespace()
}

fn user_info_char(c: char) -> bool {
    unreserved(c) || ";:&=+$,".contains(c) || other(c)
}

fn reg_name_char(c: char) -> bool {
    unreserved(c) || "$,;:@&=+".contains(c) || other(c)
}

fn server_char(c: char) -> bool {
    user_info_char(c) || c.is_ascii_alphanumeric() || "-.:@[]".contains(c)
}

fn path_char(c: char) -> bool {
    unreserved(c) || ":@&=+$,;/".contains(c) || other(c)
}

fn uric(c: char) -> bool {
    unreserved(c) || ";/?:@&=+$,[]".contains(c) || other(c)
}

fn syntax(reason: &str, input: &str, index: usize) -> String {
    format!("{reason} at index {index}: {input}")
}

/// Checks `chars` (starting at `offset` in `input`) against `allowed`, with `%XX` escapes.
fn check(input: &str, offset: usize, part: &str, allowed: fn(char) -> bool, component: &str) -> Result<(), String> {
    let chars: Vec<(usize, char)> = part.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        if c == '%' {
            let hex = |k: usize| chars.get(i + k).is_some_and(|(_, h)| h.is_ascii_hexdigit());
            if !(hex(1) && hex(2)) {
                return Err(syntax("Malformed escape pair", input, input[..offset].chars().count() + part[..at].chars().count()));
            }
            i += 3;
            continue;
        }
        if !allowed(c) {
            return Err(syntax(&format!("Illegal character in {component}"), input, input[..offset].chars().count() + part[..at].chars().count()));
        }
        i += 1;
    }
    Ok(())
}

/// A server-based authority's `getRawUserInfo`, `getHost` and `getPort`.
type Server = (Option<String>, String, i32);

/// `URI.Parser`'s authority methods (`parseAuthority`, `parseServer`, `parseIPv6Reference`, ...) over the input's
/// chars, with positions and error indices as Java reports them.
struct Parser<'a> {
    input: &'a str,
    c: Vec<char>,
    ipv6_bytes: std::cell::Cell<u32>,
}

fn hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn digit(c: char) -> bool {
    c.is_ascii_digit()
}

impl Parser<'_> {
    fn fail<T>(&self, reason: &str, p: usize) -> Result<T, String> {
        Err(syntax(reason, self.input, p))
    }

    fn at(&self, p: usize, n: usize, ch: char) -> bool {
        p < n && self.c[p] == ch
    }

    fn at_str(&self, p: usize, n: usize, s: &str) -> bool {
        let s: Vec<char> = s.chars().collect();
        s.len() <= n.saturating_sub(p) && self.c[p..p + s.len()] == s[..]
    }

    fn text(&self, p: usize, q: usize) -> String {
        self.c[p..q].iter().collect()
    }

    /// `scan(start, end, stop)`: the first `stop`, or `n`.
    fn find(&self, p: usize, n: usize, stop: char) -> usize {
        (p..n).find(|&i| self.c[i] == stop).unwrap_or(n)
    }

    /// `scan(start, n, lowMask, highMask)`; `escaped` is the `L_ESCAPED` bit (escape pairs and visible non-ASCII).
    fn scan(&self, mut p: usize, n: usize, ok: fn(char) -> bool, escaped: bool) -> Result<usize, String> {
        while p < n {
            let c = self.c[p];
            if ok(c) {
                p += 1;
            } else if escaped && c == '%' {
                if p + 3 <= n && hex(self.c[p + 1]) && hex(self.c[p + 2]) {
                    p += 3;
                } else {
                    return self.fail("Malformed escape pair", p);
                }
            } else if escaped && other(c) {
                p += 1;
            } else {
                break;
            }
        }
        Ok(p)
    }

    fn check(&self, p: usize, q: usize, ok: fn(char) -> bool, escaped: bool, what: &str) -> Result<(), String> {
        match self.scan(p, q, ok, escaped)? {
            r if r < q => self.fail(&format!("Illegal character in {what}"), r),
            _ => Ok(()),
        }
    }

    /// `parseAuthority`: `Some` for a server-based authority, `None` for a registry-based one.
    fn authority(&self, p: usize, n: usize) -> Result<Option<Server>, String> {
        // `scan(p, n, "]") > p`: true unless the authority starts with `]`
        let server_chars = if self.find(p, n, ']') > p {
            self.scan(p, n, |c| server_char(c) || c == '%', true)? == n
        } else {
            self.scan(p, n, server_char, true)? == n
        };
        let qreg = self.scan(p, n, reg_name_char, true)?;
        let reg_chars = qreg == n;
        if reg_chars && !server_chars {
            return Ok(None);
        }
        let (mut q, mut server, mut ex) = (p, None, None);
        if server_chars {
            let attempt = self.server(p, n, reg_chars).and_then(|(end, parts)| match end {
                end if end == n => Ok((end, Some(parts))),
                _ if reg_chars => Ok((p, None)),
                end => self.fail("Expected end of authority", end),
            });
            match attempt {
                Ok((end, parts)) => (q, server) = (end, parts),
                Err(e) => ex = Some(e),
            }
        }
        if q < n {
            return match ex {
                _ if reg_chars => Ok(None),
                Some(e) => Err(e),
                None => self.fail("Illegal character in authority", if server_chars { q } else { qreg }),
            };
        }
        Ok(server)
    }

    /// `parseServer`: `[userinfo@]host[:port]`, with where it stopped.
    fn server(&self, start: usize, n: usize, skip: bool) -> Result<(usize, Server), String> {
        let mut p = start;
        let mut user_info = None;
        let q = self.find(p, n, '@');
        if q < n {
            self.check(p, q, user_info_char, true, "user info")?;
            user_info = Some(self.text(p, q));
            p = q + 1;
        }
        let host;
        if self.at(p, n, '[') {
            p += 1;
            let q = self.find(p, n, ']');
            if !(q > p && q < n) {
                return self.fail("Expected closing bracket for IPv6 address", q);
            }
            let r = self.find(p, q, '%');
            if r > p && r < q {
                self.ipv6_reference(p, r)?;
                if r + 1 == q {
                    return Err(format!("scope id expected: {}", self.input));
                }
                self.check(r + 1, q, |c| c.is_ascii_alphanumeric() || c == '_' || c == '.', false, "scope id")?;
            } else {
                self.ipv6_reference(p, q)?;
            }
            host = self.text(p - 1, q + 1);
            p = q + 1;
        } else {
            let q = match self.ipv4_address(p, n) {
                Some(q) if q > p => q,
                _ => self.hostname(p, n, skip)?,
            };
            host = self.text(p, q);
            p = q;
        }
        let mut port = -1;
        if self.at(p, n, ':') {
            p += 1;
            if n > p {
                self.check(p, n, digit, false, "port number")?;
                port = match self.text(p, n).parse::<i32>() {
                    Ok(port) => port,
                    Err(_) => return self.fail("Malformed port number", p),
                };
                p = n;
            }
        } else if p < n && skip {
            return Ok((p, (user_info, host, port)));
        }
        if p < n {
            return self.fail("Expected port number", p);
        }
        Ok((p, (user_info, host, port)))
    }

    /// `scanByte`: digits whose value fits in a byte.
    fn byte(&self, p: usize, n: usize) -> usize {
        let q = (p..n).find(|&i| !digit(self.c[i])).unwrap_or(n);
        if q <= p {
            return q;
        }
        let i = (p..q).find(|&i| self.c[i] != '0').unwrap_or(q);
        match q - i {
            0..3 => q,
            3 if self.text(p, q).parse::<u32>().is_ok_and(|v| v <= 255) => q,
            _ => p,
        }
    }

    /// `scanIPv4Address`: `None` for -1.
    fn scan_ipv4(&self, start: usize, n: usize, strict: bool) -> Result<Option<usize>, String> {
        let m = (start..n).find(|&i| !(digit(self.c[i]) || self.c[i] == '.')).unwrap_or(n);
        if m <= start || (strict && m != n) {
            return Ok(None);
        }
        let mut p = start;
        let mut q = p;
        for k in 0..7 {
            q = if k % 2 == 0 { self.byte(p, m) } else if self.at(p, m, '.') { p + 1 } else { p };
            if q <= p {
                break;
            }
            p = q;
            if k == 6 && q == m {
                return Ok(Some(q));
            }
        }
        if strict {
            return self.fail("Malformed IPv4 address", q);
        }
        Ok(None)
    }

    /// `takeIPv4Address`.
    fn take_ipv4(&self, start: usize, n: usize, expected: &str) -> Result<usize, String> {
        match self.scan_ipv4(start, n, true)? {
            Some(p) if p > start => Ok(p),
            _ => self.fail(&format!("Expected {expected}"), start),
        }
    }

    /// `parseIPv4Address`: an address followed by nothing or `:`.
    fn ipv4_address(&self, start: usize, n: usize) -> Option<usize> {
        let p = self.scan_ipv4(start, n, false).ok().flatten()?;
        (!(p > start && p < n && self.c[p] != ':')).then_some(p)
    }

    /// `parseHostname`: labels of letters, digits and inner dashes; a qualified name's last label starts with a letter.
    fn hostname(&self, start: usize, n: usize, skip: bool) -> Result<usize, String> {
        let alnum = |p: usize| (p..n).find(|&i| !self.c[i].is_ascii_alphanumeric()).unwrap_or(n);
        let mut p = start;
        let mut last = None;
        loop {
            let q = alnum(p);
            if q <= p {
                break;
            }
            last = Some(p);
            p = q;
            let q = (p..n).find(|&i| !(self.c[i].is_ascii_alphanumeric() || self.c[i] == '-')).unwrap_or(n);
            if q > p {
                if self.c[q - 1] == '-' {
                    return self.fail("Illegal character in hostname", q - 1);
                }
                p = q;
            }
            if !self.at(p, n, '.') {
                break;
            }
            p += 1;
            if p >= n {
                break;
            }
        }
        if p < n && !self.at(p, n, ':') {
            if skip {
                return Ok(p);
            }
            return self.fail("Illegal character in hostname", p);
        }
        let Some(l) = last else { return self.fail("Expected hostname", start) };
        if l > start && !self.c[l].is_ascii_alphabetic() {
            return self.fail("Illegal character in hostname", l);
        }
        Ok(p)
    }

    /// `parseIPv6Reference`.
    fn ipv6_reference(&self, start: usize, n: usize) -> Result<usize, String> {
        let mut p = start;
        let mut compressed = false;
        if let Some(q) = self.hex_seq(p, n)? {
            p = q;
            if self.at_str(p, n, "::") {
                compressed = true;
                p = self.hex_post(p + 2, n)?;
            } else if self.at(p, n, ':') {
                p = self.take_ipv4(p + 1, n, "IPv4 address")?;
                self.ipv6_bytes.set(self.ipv6_bytes.get() + 4);
            }
        } else if self.at_str(p, n, "::") {
            compressed = true;
            p = self.hex_post(p + 2, n)?;
        }
        let bytes = self.ipv6_bytes.get();
        if p < n {
            return self.fail("Malformed IPv6 address", start);
        }
        if bytes > 16 {
            return self.fail("IPv6 address too long", start);
        }
        if !compressed && bytes < 16 {
            return self.fail("IPv6 address too short", start);
        }
        if compressed && bytes == 16 {
            return self.fail("Malformed IPv6 address", start);
        }
        Ok(p)
    }

    /// `scanHexPost`.
    fn hex_post(&self, mut p: usize, n: usize) -> Result<usize, String> {
        if p == n {
            return Ok(p);
        }
        match self.hex_seq(p, n)? {
            Some(q) => {
                p = q;
                if self.at(p, n, ':') {
                    p = self.take_ipv4(p + 1, n, "hex digits or IPv4 address")?;
                    self.ipv6_bytes.set(self.ipv6_bytes.get() + 4);
                }
            }
            None => {
                p = self.take_ipv4(p, n, "hex digits or IPv4 address")?;
                self.ipv6_bytes.set(self.ipv6_bytes.get() + 4);
            }
        }
        Ok(p)
    }

    /// `scanHexSeq`: `None` for -1.
    fn hex_seq(&self, start: usize, n: usize) -> Result<Option<usize>, String> {
        let hexes = |p: usize| (p..n).find(|&i| !hex(self.c[i])).unwrap_or(n);
        let q = hexes(start);
        if q <= start || self.at(q, n, '.') {
            return Ok(None);
        }
        if q > start + 4 {
            return self.fail("IPv6 hexadecimal digit sequence too long", start);
        }
        self.ipv6_bytes.set(self.ipv6_bytes.get() + 2);
        let mut p = q;
        while p < n {
            if !self.at(p, n, ':') || self.at(p + 1, n, ':') {
                break;
            }
            p += 1;
            let q = hexes(p);
            if q <= p {
                return self.fail("Expected digits for an IPv6 address", p);
            }
            if self.at(q, n, '.') {
                p -= 1;
                break;
            }
            if q > p + 4 {
                return self.fail("IPv6 hexadecimal digit sequence too long", p);
            }
            self.ipv6_bytes.set(self.ipv6_bytes.get() + 2);
            p = q;
        }
        Ok(Some(p))
    }
}

/// `new URI(input)`: the parts, or the `URISyntaxException` message.
pub fn parse(input: &str) -> Result<JavaUri, String> {
    let mut uri = JavaUri { port: -1, ..JavaUri::default() };
    let (rest, fragment_at) = match input.find('#') {
        Some(i) => (&input[..i], Some(i)),
        None => (input, None),
    };
    if let Some(i) = fragment_at {
        check(input, i + 1, &input[i + 1..], uric, "fragment")?;
    }
    // Scheme: a letter, then letters, digits, `+`, `-`, `.`, up to the first `:` before any `/`, `?`.
    let colon = rest.find(':').filter(|i| !rest[..*i].contains(['/', '?']));
    let (scheme, after_scheme, offset) = match colon {
        Some(0) => return Err(syntax("Expected scheme name", input, 0)),
        Some(i) if rest[..i].starts_with(|c: char| c.is_ascii_alphabetic()) && rest[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) => {
            (Some(rest[..i].to_string()), &rest[i + 1..], i + 1)
        }
        Some(i) => {
            let bad = rest[..i]
                .chars()
                .enumerate()
                .find(|(k, c)| !(if *k == 0 { c.is_ascii_alphabetic() } else { c.is_ascii_alphanumeric() || "+-.".contains(*c) }))
                .map_or(0, |(k, _)| k);
            return Err(syntax("Illegal character in scheme name", input, bad));
        }
        None => (None, rest, 0),
    };
    uri.scheme = scheme;
    if uri.scheme.is_some() && !after_scheme.starts_with('/') {
        if after_scheme.is_empty() {
            return Err(syntax("Expected scheme-specific part", input, offset));
        }
        check(input, offset, after_scheme, uric, "opaque part")?;
        return Ok(uri);
    }
    let (hierarchical, query) = match after_scheme.find('?') {
        Some(i) => (&after_scheme[..i], Some(&after_scheme[i + 1..])),
        None => (after_scheme, None),
    };
    let path_start;
    let path = if let Some(authority_and_path) = hierarchical.strip_prefix("//") {
        let end = authority_and_path.find('/').unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..end];
        let authority_offset = offset + 2;
        uri.raw_authority = (!authority.is_empty()).then(|| authority.to_string());
        if authority.is_empty() {
            if end == authority_and_path.len() && query.is_none() && fragment_at.is_none() {
                return Err(syntax("Expected authority", input, authority_offset));
            }
        } else {
            let parser = Parser { input, c: input.chars().collect(), ipv6_bytes: std::cell::Cell::new(0) };
            let p = input[..authority_offset].chars().count();
            if let Some((user_info, host, port)) = parser.authority(p, p + authority.chars().count())? {
                uri.raw_user_info = user_info;
                uri.host = Some(host);
                uri.port = port;
            }
        }
        path_start = authority_offset + end;
        &authority_and_path[end..]
    } else {
        path_start = offset;
        hierarchical
    };
    check(input, path_start, path, path_char, "path")?;
    uri.raw_path = Some(path.to_string());
    if let Some(q) = query {
        check(input, offset + hierarchical.len() + 1, q, uric, "query")?;
        uri.raw_query = Some(q.to_string());
    }
    Ok(uri)
}

/// `getPath()`: the raw path with its escapes decoded as UTF-8.
pub fn path(uri: &JavaUri) -> Option<String> {
    uri.raw_path.as_deref().map(crate::grpc_plane::percent_decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_as_java_net_uri() {
        let u = parse("amqp://u:p@rabbit:5673/vh?heartbeat=1#f").unwrap();
        assert_eq!(
            u,
            JavaUri {
                scheme: Some("amqp".into()),
                raw_user_info: Some("u:p".into()),
                raw_authority: Some("u:p@rabbit:5673".into()),
                host: Some("rabbit".into()),
                port: 5673,
                raw_path: Some("/vh".into()),
                raw_query: Some("heartbeat=1".into())
            }
        );
        assert_eq!(parse("amqp://").unwrap_err(), "Expected authority at index 7: amqp://");
        assert_eq!(parse("not a uri").unwrap_err(), "Illegal character in path at index 3: not a uri");
        assert_eq!(parse("amqp://r a").unwrap_err(), "Illegal character in authority at index 8: amqp://r a");
        assert_eq!(parse("amqp://rabbit/%zz").unwrap_err(), "Malformed escape pair at index 14: amqp://rabbit/%zz");
        assert_eq!(parse("amqp://rabbit:abc").unwrap().host, None);
        assert_eq!(parse("amqp://rab_bit").unwrap().host, None);
        assert_eq!(parse("amqp:rabbit").unwrap().raw_path, None);
        assert_eq!(parse("localhost").unwrap().scheme, None);
        assert_eq!(parse("amqp:///vh").unwrap().host, None);
        assert_eq!(parse("amqp://[::1]:5672").unwrap().host.as_deref(), Some("[::1]"));
        assert_eq!(parse("amqp://rabbit:").unwrap().port, -1);
        assert_eq!(parse("amqp://host.with.dots:99999").unwrap().port, 99999);
        assert_eq!(parse("amqp://ü@rabbit").unwrap().raw_user_info.as_deref(), Some("ü"));
    }

    /// Messages from JDK 26's `new URI(…)` (the `URIName` vectors).
    #[test]
    fn rejects_as_java_net_uri() {
        assert_eq!(parse("[::1]").unwrap_err(), "Illegal character in scheme name at index 0: [::1]");
        assert_eq!(parse("http://[::1/").unwrap_err(), "Expected closing bracket for IPv6 address at index 11: http://[::1/");
        assert_eq!(parse("http://[1::2::3]/").unwrap_err(), "Expected hex digits or IPv4 address at index 13: http://[1::2::3]/");
        assert_eq!(parse("http://[1:2]/").unwrap_err(), "IPv6 address too short at index 8: http://[1:2]/");
        assert_eq!(parse("http://[::1]x/").unwrap_err(), "Expected port number at index 12: http://[::1]x/");
        assert_eq!(parse("http://[::1%]/").unwrap_err(), "scope id expected: http://[::1%]/");
        assert_eq!(parse("http://[::ffff:1.2.3.4]:80/").unwrap().host.as_deref(), Some("[::ffff:1.2.3.4]"));
        assert_eq!(parse("http://[fe80::1%en0]/").unwrap().host.as_deref(), Some("[fe80::1%en0]"));
    }

    #[test]
    fn paths_are_decoded_as_utf8() {
        assert_eq!(path(&parse("amqp://h/%C3%BC").unwrap()).as_deref(), Some("/ü"));
        assert_eq!(path(&parse("mailto:a@b").unwrap()), None);
    }
}
