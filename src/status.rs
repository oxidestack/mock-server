//! Reason phrases exactly as Netty's `HttpResponseStatus` writes them, which is what MockServer puts on the wire.

pub fn reason_phrase(code: u32) -> String {
    reason(code).into_owned()
}

/// [`reason_phrase`], borrowed for a known status.
pub fn reason(code: u32) -> std::borrow::Cow<'static, str> {
    let known = match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Unordered Collection",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => {
            // `new HttpResponseStatus(code)`: the status class's default phrase plus the code.
            let class = match code {
                100..=199 => "Informational",
                200..=299 => "Success",
                300..=399 => "Redirection",
                400..=499 => "Client Error",
                500..=599 => "Server Error",
                _ => "Unknown Status",
            };
            return format!("{class} ({code})").into();
        }
    };
    known.into()
}
