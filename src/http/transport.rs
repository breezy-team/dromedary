//! `HttpTransport` — a `dromedary::Transport` over HTTP(S).
//!
//! Bridges the low-level [`HttpClient`] (TLS, proxy, redirects, auth)
//! to the dromedary transport trait so Rust callers can drive a
//! `dyn Transport` against an `http://` or `https://` URL without
//! going through PyO3.
//!
//! The read-side machinery — `get`, `readv` with Range coalescing,
//! `_post`/`_head` — is ported from the Python HttpTransport in
//! `dromedary/http/urllib.py`. Write operations are rejected with
//! `Error::TransportNotPossible` because HTTP is a read-only
//! transport; WebDAV-style writes live in a separate transport.

use std::sync::{Arc, Mutex};

use url::Url;

use crate::http::client::{HttpClient, HttpResponse, RequestOptions};
use crate::http::response::{handle_response, InFile, RangeFile, ResponseError, ResponseKind};
use crate::lock::BogusLock;
use crate::{Error, Permissions, ReadStream, Result, Stat, Transport, UrlFragment};

/// Range-request support hint. The client starts at `Multi`
/// (multi-range request per coalesced readv) and degrades when the
/// server misbehaves: first to `Single` (one range per request),
/// then to `None` (download whole file). Once degraded it never
/// climbs back — the cost of a failed upgrade is worse than the
/// benefit of recovery for the typical bzr use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeHint {
    Multi,
    Single,
    None,
}

/// HTTP(S) transport.
///
/// Holds an `Arc<HttpClient>` so clones share the same connection
/// pool, auth cache, and credentials. `base` is the transport's
/// root URL without segment parameters (always ends with `/`);
/// `segment_parameters` stores the breezy-style `,key=value` suffix
/// parameters separately so they never leak into requests on the
/// wire but are still visible via `get_segment_parameters()` and
/// the joined form reported by `Transport::base()`.
/// `unqualified_scheme` is the HTTP scheme without any `+impl`
/// qualifier so we can hand back clean URLs from `external_url`
/// and `_remote_path`.
#[derive(Clone)]
pub struct HttpTransport {
    base: Url,
    unqualified_scheme: String,
    segment_parameters: std::collections::BTreeMap<String, String>,
    client: Arc<HttpClient>,
    range_hint: Arc<Mutex<RangeHint>>,
}

impl HttpTransport {
    /// Build a new transport over `base`. The URL must use an
    /// `http` or `https` scheme (optionally with a `+impl` suffix
    /// like `http+urllib://`, which we ignore beyond logging).
    pub fn new(base: &str, client: Arc<HttpClient>) -> Result<Self> {
        let (unqualified_scheme, normalised_base, segment_parameters) = normalise_http_url(base)?;
        Ok(Self {
            base: normalised_base,
            unqualified_scheme,
            segment_parameters,
            client,
            range_hint: Arc::new(Mutex::new(RangeHint::Multi)),
        })
    }

    /// Clone this transport at a new base URL. Shares the underlying
    /// `HttpClient` — so the auth cache, connection pool, and
    /// credentials follow us. Segment parameters are cleared on the
    /// clone (matching the Python `ConnectedTransport.clone` shape,
    /// which did the same via `_raw_base`).
    fn clone_at(&self, new_base: Url) -> Self {
        Self {
            base: new_base,
            unqualified_scheme: self.unqualified_scheme.clone(),
            segment_parameters: std::collections::BTreeMap::new(),
            client: self.client.clone(),
            range_hint: self.range_hint.clone(),
        }
    }

    /// Concrete version of [`Transport::clone`]. Same semantics —
    /// optionally apply an offset — but returns `Self` so callers
    /// that need the concrete type (the PyO3 wrapper, mostly) don't
    /// have to downcast a `Box<dyn Transport>`.
    ///
    /// `clone` differs from `abspath` in that the result is always
    /// directory-shaped (ends in `/`): a transport's base URL is
    /// conventionally a directory, and downstream `join`/`abspath`
    /// calls only work right when the base ends with a slash.
    pub fn clone_concrete(&self, offset: Option<&UrlFragment>) -> Result<Self> {
        let new_base = match offset {
            Some(o) => {
                let mut url = self.abspath(o)?;
                if !url.path().ends_with('/') {
                    let mut path = url.path().to_string();
                    path.push('/');
                    url.set_path(&path);
                }
                url
            }
            None => self.base.clone(),
        };
        Ok(self.clone_at(new_base))
    }

    /// The URL a server sees for `relpath`. Credentials are stripped
    /// from the userinfo (they belong in headers, not in the path we
    /// hand the server), and the scheme is the unqualified form so
    /// `http+urllib://host/` never leaks upstream.
    pub fn remote_url(&self, relpath: &UrlFragment) -> Result<Url> {
        let mut url = self.abspath(relpath)?;
        let _ = url.set_username("");
        let _ = url.set_password(None);
        let _ = url.set_scheme(&self.unqualified_scheme);
        Ok(url)
    }

    /// Issue a raw HTTP request. Mirrors the Python
    /// `HttpTransport.request` method: returns the Rust
    /// `HttpResponse` with redirect / auth / activity machinery
    /// already applied by the client.
    pub fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        follow_redirects: bool,
    ) -> Result<HttpResponse> {
        let opts = RequestOptions {
            follow_redirects,
            ..RequestOptions::default()
        };
        let resp = self
            .client
            .request_with_origin_url(
                method,
                url,
                self.base.as_str(),
                headers,
                body,
                &opts,
                None,
            )
            .map_err(client_err_to_transport_err)?;

        let code = resp.status;
        if !follow_redirects && matches!(code, 301 | 302 | 303 | 307 | 308) {
            let target = resp
                .redirected_to
                .clone()
                .unwrap_or_else(|| url.to_string());
            return Err(Error::RedirectRequested {
                source: url.to_string(),
                target,
                is_permanent: matches!(code, 301 | 308),
            });
        }
        Ok(resp)
    }

    /// HEAD with breezy-compatible status-code handling.
    fn head_request(&self, relpath: &UrlFragment) -> Result<HttpResponse> {
        let abspath = self.remote_url(relpath)?.to_string();
        let resp = self.request("HEAD", &abspath, &[], &[], false)?;
        if !matches!(resp.status, 200 | 404) {
            return Err(Error::UnexpectedHttpStatus {
                path: abspath,
                code: resp.status,
                extra: None,
            });
        }
        Ok(resp)
    }

    /// POST a body to `relpath`. Mirrors Python `HttpTransport._post`.
    /// Returns `(status, range_file)` where `range_file` is a
    /// `RangeFile` wrapping the response body (suitable for feeding
    /// into the bzr smart-protocol medium reader).
    pub fn post(&self, relpath: &UrlFragment, body: &[u8]) -> Result<(u16, HttpRangeFile)> {
        let abspath = self.remote_url(relpath)?.to_string();
        let headers = [(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        )];
        let resp = self.request("POST", &abspath, &headers, body, false)?;
        let (status, file) = wrap_response_body(abspath, resp)?;
        Ok((status, file))
    }

    /// Internal `_get` with range support. Returns `(status,
    /// range_file)` for a GET that may be range-limited by
    /// `attempted_range_header`. 404 → `NoSuchFile`, 416 →
    /// `InvalidHttpRange`, 400 → `BadHttpRequest` or
    /// `InvalidHttpRange` depending on whether we sent a Range
    /// header, other non-2xx → `UnexpectedHttpStatus`.
    fn _get(
        &self,
        relpath: &UrlFragment,
        attempted_range_header: Option<&str>,
    ) -> Result<(u16, HttpRangeFile)> {
        let abspath = self.remote_url(relpath)?.to_string();
        let headers: Vec<(String, String)> = attempted_range_header
            .map(|r| vec![("Range".to_string(), format!("bytes={}", r))])
            .unwrap_or_default();
        let resp = self.request("GET", &abspath, &headers, &[], false)?;
        match resp.status {
            200 | 206 => {}
            404 => return Err(Error::NoSuchFile(Some(abspath))),
            416 => {
                return Err(Error::InvalidHttpRange {
                    path: abspath,
                    range: attempted_range_header.unwrap_or("").to_string(),
                    msg: format!("Server return code {}", resp.status),
                })
            }
            400 => {
                if let Some(r) = attempted_range_header {
                    return Err(Error::InvalidHttpRange {
                        path: abspath,
                        range: r.to_string(),
                        msg: format!("Server return code {}", resp.status),
                    });
                }
                return Err(Error::BadHttpRequest {
                    path: abspath,
                    reason: resp.reason.clone(),
                });
            }
            code => {
                return Err(Error::UnexpectedHttpStatus {
                    path: abspath,
                    code,
                    extra: None,
                })
            }
        }
        wrap_response_body(abspath, resp)
    }

    /// Format the current ranges + tail amount into a Range-header
    /// value if any can be built. Mirrors the Python
    /// `_attempted_range_header` with the same downgrade logic.
    fn attempted_range_header(
        &self,
        offsets: &[(usize, usize)],
        tail_amount: usize,
    ) -> Option<String> {
        let hint = *self.range_hint.lock().unwrap();
        match hint {
            RangeHint::Multi => Some(format_range_header(offsets, tail_amount)),
            RangeHint::Single => {
                if !offsets.is_empty() {
                    if tail_amount != 0 {
                        // Can't merge ranges with a tail_amount into
                        // one; caller falls back to the whole file.
                        return None;
                    }
                    let first = offsets.first().unwrap();
                    let last = offsets.last().unwrap();
                    let start = first.0;
                    let end = last.0 + last.1 - 1;
                    Some(format_range_header(&[(start, end - start + 1)], 0))
                } else {
                    Some(format_range_header(offsets, tail_amount))
                }
            }
            RangeHint::None => None,
        }
    }

    /// Step the range hint down one rung after a server misbehaves.
    /// Returns false if we've already hit the floor (no ranges) —
    /// caller must surface the error to the user.
    pub fn degrade_range_hint(&self) -> bool {
        let mut hint = self.range_hint.lock().unwrap();
        match *hint {
            RangeHint::Multi => {
                *hint = RangeHint::Single;
                true
            }
            RangeHint::Single => {
                *hint = RangeHint::None;
                true
            }
            RangeHint::None => false,
        }
    }

    /// Current range hint as a short string: `"multi"`, `"single"`,
    /// or `None`. Matches the values the Python HttpTransport used
    /// so tests that reach into `_range_hint` continue to work.
    pub fn range_hint_str(&self) -> Option<&'static str> {
        match *self.range_hint.lock().unwrap() {
            RangeHint::Multi => Some("multi"),
            RangeHint::Single => Some("single"),
            RangeHint::None => None,
        }
    }

    /// Accessor for the shared `HttpClient`. Exposed so the PyO3
    /// wrapper can pass through `request(...)` with a Python-side
    /// activity callback without re-resolving the client through
    /// a second URL parse.
    pub fn client(&self) -> &Arc<HttpClient> {
        &self.client
    }

    /// OPTIONS request: returns the response headers or raises for
    /// 404 / 403 / 405. Mirrors the Python `_options`.
    pub fn options(&self, relpath: &UrlFragment) -> Result<Vec<(String, String)>> {
        let abspath = self.remote_url(relpath)?.to_string();
        let resp = self.request("OPTIONS", &abspath, &[], &[], false)?;
        match resp.status {
            404 => Err(Error::NoSuchFile(Some(abspath))),
            403 | 405 => Err(Error::InvalidHttpResponse {
                path: abspath,
                msg: "OPTIONS not supported or forbidden for remote URL".into(),
            }),
            _ => Ok(resp.headers.clone()),
        }
    }

    /// HEAD request: returns the raw response so callers can inspect
    /// headers. Rejects non-200/404 statuses.
    pub fn head(&self, relpath: &UrlFragment) -> Result<HttpResponse> {
        self.head_request(relpath)
    }
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "HttpTransport({})", self.base)
    }
}

/// `RangeFile` wrapping the response body with its source URL for
/// error reporting. Implements `ReadStream` so callers that treat
/// `get()` as returning a read+seek stream work unchanged.
pub struct HttpRangeFile {
    inner: RangeFile<BufferedBody>,
}

impl HttpRangeFile {
    /// Read bytes at `offset` with the given `size`. Wraps
    /// `RangeFile::seek` + `read`. The caller is responsible for
    /// ensuring `offset` falls within the current range window.
    pub fn read_at(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.inner
            .seek(offset as i64, 0)
            .map_err(response_err_to_transport_err)?;
        let got = self
            .inner
            .read(size as i64)
            .map_err(response_err_to_transport_err)?;
        if got.len() != size {
            return Err(Error::ShortReadvError(
                self.inner.path().to_string(),
                offset,
                size as u64,
                got.len() as u64,
            ));
        }
        Ok(got)
    }
}

impl std::io::Read for HttpRangeFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let chunk = self
            .inner
            .read(buf.len() as i64)
            .map_err(|e| std::io::Error::other(format!("{:?}", e)))?;
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        Ok(n)
    }
}

impl std::io::Seek for HttpRangeFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let (offset, whence) = match pos {
            std::io::SeekFrom::Start(o) => (o as i64, 0u32),
            std::io::SeekFrom::Current(o) => (o, 1u32),
            std::io::SeekFrom::End(o) => (o, 2u32),
        };
        self.inner
            .seek(offset, whence)
            .map_err(|e| std::io::Error::other(format!("{:?}", e)))?;
        Ok(self.inner.tell())
    }
}

impl ReadStream for HttpRangeFile {}

/// Adapter: wraps a fully-buffered body (`Vec<u8>` + cursor) as the
/// `InFile` type that `RangeFile` consumes. The body is already in
/// memory at this point — `HttpResponse` eagerly drains it on
/// access so seeking works without replaying the network stream.
struct BufferedBody {
    body: Vec<u8>,
    pos: usize,
}

impl BufferedBody {
    fn new(body: Vec<u8>) -> Self {
        Self { body, pos: 0 }
    }
}

impl InFile for BufferedBody {
    fn read(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let end = (self.pos + n).min(self.body.len());
        let chunk = self.body[self.pos..end].to_vec();
        self.pos = end;
        Ok(chunk)
    }
    fn readline(&mut self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while self.pos < self.body.len() {
            let b = self.body[self.pos];
            self.pos += 1;
            out.push(b);
            if b == b'\n' {
                break;
            }
        }
        Ok(out)
    }
}

/// Normalise an HTTP URL: enforce a trailing slash and split out
/// the unqualified scheme. Accepts `+impl` suffixes (e.g.
/// `http+urllib://host/`) but rewrites them to the plain scheme
/// form before parsing so the resulting `Url` reports `http` /
/// `https` as its scheme. The `url` crate is strict about scheme
/// changes between "special" (http/https/etc.) and "non-special"
/// schemes, so we can't fix this up after-the-fact via
/// `Url::set_scheme`.
fn normalise_http_url(
    base: &str,
) -> Result<(String, Url, std::collections::BTreeMap<String, String>)> {
    let trimmed = base.trim();
    let scheme_end = trimmed
        .find("://")
        .ok_or_else(|| Error::UrlError(url::ParseError::RelativeUrlWithoutBase))?;
    let raw_scheme = &trimmed[..scheme_end];
    // Strip any `+impl` suffix: `http+urllib` → `http`.
    let unqualified = raw_scheme
        .split_once('+')
        .map(|(s, _)| s)
        .unwrap_or(raw_scheme)
        .to_string();
    if unqualified != "http" && unqualified != "https" {
        return Err(Error::UrlError(url::ParseError::RelativeUrlWithoutBase));
    }
    let rest = &trimmed[scheme_end..];
    let canonical = format!("{}{}", unqualified, rest);
    // Segment parameters (`,key=value`) appended to the path are a
    // breezy/dromedary Transport-layer convention (e.g. `,branch=foo`)
    // that we store separately from the URL proper: they never go on
    // the wire. Split them off here so the rest of the transport
    // sees a clean URL.
    let (base_part, params) = crate::urlutils::split_segment_parameters(&canonical)
        .map_err(|_| Error::UrlError(url::ParseError::RelativeUrlWithoutBase))?;
    let base_with_slash = if base_part.ends_with('/') {
        base_part.to_string()
    } else {
        format!("{}/", base_part)
    };
    // RFC 3986 §6.2.2.2: percent-encoded unreserved characters must be
    // decoded to their literal form for a URL to be in canonical form.
    // Apply that here so cloning and abspath round-trip consistently with
    // paths that came in needlessly-escaped (`%7E` → `~` etc.).
    let base_with_slash = crate::urlutils::unquote_unreserved(&base_with_slash);
    let parsed = Url::parse(&base_with_slash)?;
    let segment_parameters: std::collections::BTreeMap<String, String> = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Ok((unqualified, parsed, segment_parameters))
}

/// Format a list of (start, length) offsets + optional tail amount
/// as an HTTP Range header value.
fn format_range_header(offsets: &[(usize, usize)], tail_amount: usize) -> String {
    let mut parts: Vec<String> = offsets
        .iter()
        .map(|(start, length)| format!("{}-{}", start, start + length - 1))
        .collect();
    if tail_amount != 0 {
        parts.push(format!("-{}", tail_amount));
    }
    parts.join(",")
}

/// Wrap a response body in a `RangeFile`. For 200 responses we
/// build the RangeFile directly from the buffered body (no range
/// metadata to parse). For 206 we run through `handle_response`
/// which inspects Content-Type / Content-Range to set up the
/// boundary or single-range window.
fn wrap_response_body(url: String, mut resp: HttpResponse) -> Result<(u16, HttpRangeFile)> {
    let status = resp.status;
    let body = resp.read(None).map_err(Error::Io)?;
    if status == 200 {
        // Plain whole-file response: skip handle_response and build
        // a RangeFile directly so we don't need to thread the body
        // through the ResponseFile intermediate.
        let rf = RangeFile::new(url, BufferedBody::new(body));
        return Ok((status, HttpRangeFile { inner: rf }));
    }
    // 206 (or anything else handle_response accepts): inspect the
    // headers to set up the range window.
    let headers = resp.headers.clone();
    let get_header = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_string())
    };
    let kind = handle_response(url.clone(), status, &get_header, BufferedBody::new(body))
        .map_err(response_err_to_transport_err)?;
    let rf = match kind {
        ResponseKind::Range(rf) => rf,
        ResponseKind::Plain(_) => {
            // handle_response only returns Plain for 200, which we
            // intercepted above. Anything else here is a parse-layer
            // bug we shouldn't paper over.
            return Err(Error::InvalidHttpResponse {
                path: url,
                msg: format!("unexpected handle_response shape for status {}", status),
            });
        }
    };
    Ok((status, HttpRangeFile { inner: rf }))
}

/// Map a `ResponseError` from the parse layer to our transport
/// `Error`. The `ResponseError` variants are already 1-to-1 with
/// dromedary errors (see `src/http/response.rs`), so this is a
/// straightforward translation.
fn response_err_to_transport_err(err: ResponseError) -> Error {
    match err {
        ResponseError::InvalidResponse { path, msg } => Error::InvalidHttpResponse { path, msg },
        ResponseError::InvalidHttpRange { path, range, msg } => {
            Error::InvalidHttpRange { path, range, msg }
        }
        ResponseError::BoundaryMissing { path, boundary } => Error::InvalidHttpResponse {
            path,
            msg: format!(
                "HTTP MIME Boundary missing ({})",
                String::from_utf8_lossy(&boundary)
            ),
        },
        ResponseError::ShortReadv {
            path,
            offset,
            length,
            actual,
        } => Error::ShortReadvError(path, offset, length, actual),
        ResponseError::InvalidRange { path, offset, msg } => Error::InvalidHttpResponse {
            path,
            msg: format!("invalid range at offset {}: {}", offset, msg),
        },
        ResponseError::UnexpectedStatus { path, code } => Error::UnexpectedHttpStatus {
            path,
            code,
            extra: None,
        },
        ResponseError::Io(e) => Error::Io(e),
        ResponseError::InvalidWhence(w) => Error::InvalidHttpResponse {
            path: String::new(),
            msg: format!("invalid whence: {}", w),
        },
        ResponseError::BackwardSeek { path, pos, offset } => Error::InvalidHttpResponse {
            path,
            msg: format!("backward seek: pos={}, offset={}", pos, offset),
        },
    }
}

/// Map a `ClientError` from the HTTP client to our transport
/// `Error`. Transport-level failures (DNS, TCP, TLS) surface as
/// `Error::Io` wrapping the underlying io::Error; malformed requests
/// as `Error::InvalidHttpResponse`.
fn client_err_to_transport_err(err: crate::http::client::ClientError) -> Error {
    use crate::http::client::ClientError;
    match err {
        ClientError::InvalidRequest(msg) => Error::InvalidHttpResponse {
            path: String::new(),
            msg,
        },
        ClientError::Io(e) => Error::Io(e),
        // DNS / TCP / TLS failures — these surface as
        // `dromedary.errors.ConnectionError` on the Python side so
        // breezy's retry loop can catch them the way it used to.
        ClientError::Transport(e) => Error::ConnectionError(e.to_string()),
    }
}

impl Transport for HttpTransport {
    fn external_url(&self) -> Result<Url> {
        // `base` already has the unqualified scheme after
        // `normalise_http_url`, so we just hand it back.
        let mut url = self.base.clone();
        let _ = url.set_scheme(&self.unqualified_scheme);
        Ok(url)
    }

    fn base(&self) -> Url {
        if self.segment_parameters.is_empty() {
            return self.base.clone();
        }
        let raw = self.base.as_str();
        let params: std::collections::HashMap<&str, &str> = self
            .segment_parameters
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // join_segment_parameters can only fail for malformed inputs
        // (`=` in key, `,` in value); our params came from set_segment
        // which pre-validates, so this is infallible in practice.
        let joined = crate::urlutils::join_segment_parameters(raw, &params)
            .unwrap_or_else(|_| raw.to_string());
        Url::parse(&joined).unwrap_or_else(|_| self.base.clone())
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        false
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        let (_code, rf) = self._get(relpath, None)?;
        Ok(Box::new(rf))
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        let resp = self.head_request(relpath)?;
        Ok(resp.status == 200)
    }

    fn stat(&self, _relpath: &UrlFragment) -> Result<Stat> {
        Err(Error::TransportNotPossible(Some(
            "http does not support stat()".into(),
        )))
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        Ok(Box::new(self.clone_concrete(offset)?))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        if relpath.is_empty() || relpath == "." {
            return Ok(self.base.clone());
        }
        // URLs must be ASCII on the wire. Callers hand us pre-escaped
        // paths (via urlutils.escape); silently percent-encoding here
        // would hide bugs where that escape was skipped.
        if !relpath.is_ascii() {
            return Err(Error::UrlError(url::ParseError::InvalidDomainCharacter));
        }
        // Unescape unreserved characters (RFC 3986: a-z A-Z 0-9 - . _ ~)
        // that callers sometimes percent-encode needlessly. Keeps
        // abspath output canonical so clone()s of sibling branches
        // produce identical-looking base URLs. (lp:842223)
        let normalised = crate::urlutils::unquote_unreserved(relpath);
        let joined = self
            .base
            .join(&normalised)
            .map_err(|_| Error::UrlError(url::ParseError::InvalidDomainCharacter))?;
        // Match the Python `URL.clone(relpath)` semantics of
        // dropping a trailing slash from the joined path. Callers
        // that explicitly want the directory form re-append `/`
        // themselves (e.g. clone() in the Python subclass).
        let joined = if joined.path().len() > 1 && joined.path().ends_with('/') {
            let mut u = joined;
            let new_path = u.path().trim_end_matches('/').to_string();
            u.set_path(&new_path);
            u
        } else {
            joined
        };
        Ok(joined)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        crate::relpath_against_base(&self.base, abspath)
    }

    fn mkdir(&self, _relpath: &UrlFragment, _permissions: Option<Permissions>) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support mkdir()".into(),
        )))
    }

    fn put_file(
        &self,
        _relpath: &UrlFragment,
        _f: &mut dyn std::io::Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        Err(Error::TransportNotPossible(Some(
            "http does not support put_file()".into(),
        )))
    }

    fn delete(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support delete()".into(),
        )))
    }

    fn rmdir(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support rmdir()".into(),
        )))
    }

    fn rename(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support rename()".into(),
        )))
    }

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()> {
        if key.contains('=') {
            return Err(Error::UrlError(url::ParseError::InvalidDomainCharacter));
        }
        match value {
            Some(v) => {
                if v.contains(',') {
                    return Err(Error::UrlError(url::ParseError::InvalidDomainCharacter));
                }
                self.segment_parameters
                    .insert(key.to_string(), v.to_string());
            }
            None => {
                self.segment_parameters.remove(key);
            }
        }
        Ok(())
    }

    fn get_segment_parameters(&self) -> Result<std::collections::HashMap<String, String>> {
        Ok(self
            .segment_parameters
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn readlink(&self, _relpath: &UrlFragment) -> Result<String> {
        Err(Error::TransportNotPossible(Some(
            "http does not support readlink()".into(),
        )))
    }

    fn hardlink(&self, _from: &UrlFragment, _to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support hardlink()".into(),
        )))
    }

    fn symlink(&self, _from: &UrlFragment, _to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support symlink()".into(),
        )))
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        Box::new(std::iter::once(Err(Error::TransportNotPossible(Some(
            "http does not support iter_files_recursive()".into(),
        )))))
    }

    fn open_write_stream(
        &self,
        _relpath: &UrlFragment,
        _permissions: Option<Permissions>,
    ) -> Result<Box<dyn crate::WriteStream + Send + Sync>> {
        Err(Error::TransportNotPossible(Some(
            "http does not support open_write_stream()".into(),
        )))
    }

    fn delete_tree(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support delete_tree()".into(),
        )))
    }

    fn is_readonly(&self) -> bool {
        true
    }

    fn listable(&self) -> bool {
        false
    }

    fn recommended_page_size(&self) -> usize {
        64 * 1024
    }

    fn lock_read(&self, _relpath: &UrlFragment) -> Result<Box<dyn crate::Lock + Send + Sync>> {
        // HTTP doesn't have shared-read locks; return a bogus lock
        // that no-ops on unlock, matching the Python version.
        Ok(Box::new(BogusLock))
    }

    fn lock_write(&self, _relpath: &UrlFragment) -> Result<Box<dyn crate::Lock + Send + Sync>> {
        Err(Error::TransportNotPossible(Some(
            "http does not support lock_write()".into(),
        )))
    }

    fn local_abspath(&self, _relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        Err(Error::NotLocalUrl(self.base.to_string()))
    }

    fn list_dir(&self, _relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        Box::new(std::iter::once(Err(Error::TransportNotPossible(Some(
            "http does not support list_dir()".into(),
        )))))
    }

    fn append_file(
        &self,
        _relpath: &UrlFragment,
        _f: &mut dyn std::io::Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        Err(Error::TransportNotPossible(Some(
            "http does not support append_file()".into(),
        )))
    }

    fn copy(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible(Some(
            "http does not support copy()".into(),
        )))
    }

    fn readv<'a>(
        &self,
        relpath: &'a UrlFragment,
        offsets: Vec<(u64, usize)>,
        adjust_for_latency: bool,
        upper_limit: Option<u64>,
    ) -> Box<dyn Iterator<Item = Result<(u64, Vec<u8>)>> + Send + 'a> {
        // Collect everything we need to drive the retry loop into
        // owned data so the iterator can outlive the initial call.
        let offsets = if adjust_for_latency {
            crate::readv::sort_expand_and_combine(
                offsets,
                upper_limit,
                self.recommended_page_size(),
            )
        } else {
            offsets
        };
        // Drain up-front because `readv` yields an iterator and
        // doing the HTTP request lazily would complicate error
        // surfacing. Mirrors the Python impl's approach of running
        // the whole coalesced chain eagerly and yielding results.
        let results = self.readv_eager(relpath, offsets);
        Box::new(results.into_iter())
    }
}

impl crate::ConnectedTransport for HttpTransport {}

impl HttpTransport {
    /// Eager `readv` implementation: issue coalesced GET requests,
    /// degrade the range hint on failure, and return the results as
    /// a Vec so the `Transport::readv` iterator can yield them.
    ///
    /// Matches the Python `_readv` algorithm: sort + coalesce
    /// offsets into the smallest number of Range-header entries,
    /// issue one or more GET requests respecting the range hint,
    /// parse multipart / single-range responses via `RangeFile`,
    /// and fall back to `single` and then `none` (full-file
    /// download) on failure.
    fn readv_eager(
        &self,
        relpath: &UrlFragment,
        offsets: Vec<(u64, usize)>,
    ) -> Vec<Result<(u64, Vec<u8>)>> {
        let offsets_usize: Vec<(usize, usize)> =
            offsets.iter().map(|(o, s)| (*o as usize, *s)).collect();

        let mut remaining = offsets_usize.clone();
        let mut out: Vec<Result<(u64, Vec<u8>)>> = Vec::with_capacity(remaining.len());
        // The last per-pass error we saw. We prefer to surface the
        // specific server/IO error once we run out of degradation
        // rungs — "server misbehaved on range requests" is less
        // useful than e.g. `InvalidHttpRange` or `ShortReadvError`.
        let mut last_retry_err: Option<Error> = None;

        loop {
            let sorted: Vec<(usize, usize)> = {
                let mut v = remaining.clone();
                v.sort();
                v
            };
            let coalesced =
                match crate::readv::coalesce_offsets(&sorted, Some(0), Some(128), Some(0)) {
                    Ok(c) => c,
                    Err(e) => {
                        out.push(Err(Error::InvalidHttpResponse {
                            path: relpath.to_string(),
                            msg: format!("overlapping ranges: {}", e),
                        }));
                        return out;
                    }
                };

            match self.readv_one_pass(relpath, &coalesced, &remaining) {
                Ok(pass_out) => {
                    out.extend(pass_out);
                    return out;
                }
                Err(ReadvPassError::Retry {
                    remaining: new_remaining,
                    cause,
                }) => {
                    // Server misbehaved; try again with a degraded
                    // range hint.
                    if !self.degrade_range_hint() {
                        out.push(Err(cause.or(last_retry_err).unwrap_or_else(|| {
                            Error::InvalidHttpResponse {
                                path: relpath.to_string(),
                                msg: "server repeatedly misbehaved on range requests".into(),
                            }
                        })));
                        return out;
                    }
                    last_retry_err = cause;
                    remaining = new_remaining;
                }
                Err(ReadvPassError::Hard(err)) => {
                    out.push(Err(err));
                    return out;
                }
            }
        }
    }

    /// One pass of the `readv` coalescing loop. Groups coalesced
    /// chunks into batches of up to `MAX_GET_RANGES` per request
    /// when running under `RangeHint::Multi`; under `Single` each
    /// chunk gets its own request; under `None` we issue one full-
    /// file GET that covers everything.
    fn readv_one_pass(
        &self,
        relpath: &UrlFragment,
        coalesced: &[(usize, usize, Vec<(usize, usize)>)],
        offsets_order: &[(usize, usize)],
    ) -> std::result::Result<Vec<Result<(u64, Vec<u8>)>>, ReadvPassError> {
        // Apache's default range cap is ~400; pick well under that.
        const MAX_GET_RANGES: usize = 200;

        let hint = *self.range_hint.lock().unwrap();
        let batches: Vec<&[(usize, usize, Vec<(usize, usize)>)]> = match hint {
            RangeHint::None => vec![coalesced],
            RangeHint::Single => coalesced.chunks(1).collect::<Vec<_>>(),
            RangeHint::Multi => coalesced.chunks(MAX_GET_RANGES).collect::<Vec<_>>(),
        };

        let mut results: Vec<Result<(u64, Vec<u8>)>> = Vec::with_capacity(offsets_order.len());
        let mut data_map: std::collections::HashMap<(usize, usize), Vec<u8>> =
            std::collections::HashMap::new();
        let mut iter = offsets_order.iter();
        let Some(mut current) = iter.next().copied() else {
            return Ok(results);
        };

        for batch in batches {
            // Build the Range header from this batch's coalesced
            // chunks. Under `RangeHint::None` we pass None to skip
            // the header entirely (full-file download).
            let flat: Vec<(usize, usize)> = batch
                .iter()
                .map(|(start, length, _ranges)| (*start, *length))
                .collect();
            let range_header = self.attempted_range_header(&flat, 0);

            let (_code, mut rf) = match self._get(relpath, range_header.as_deref()) {
                Ok(pair) => pair,
                Err(
                    e @ (Error::InvalidHttpRange { .. }
                    | Error::InvalidHttpResponse { .. }
                    | Error::ShortReadvError(_, _, _, _)),
                ) => {
                    return Err(ReadvPassError::Retry {
                        remaining: offsets_order.to_vec(),
                        cause: Some(e),
                    });
                }
                Err(other) => return Err(ReadvPassError::Hard(other)),
            };

            for (coal_start, _coal_length, ranges) in batch {
                for (sub_offset, sub_size) in ranges {
                    let abs_start = coal_start + sub_offset;
                    let data = match rf.read_at(abs_start as u64, *sub_size) {
                        Ok(d) => d,
                        Err(
                            e @ (Error::ShortReadvError(_, _, _, _)
                            | Error::InvalidHttpRange { .. }
                            | Error::InvalidHttpResponse { .. }),
                        ) => {
                            return Err(ReadvPassError::Retry {
                                remaining: offsets_order.to_vec(),
                                cause: Some(e),
                            });
                        }
                        Err(other) => return Err(ReadvPassError::Hard(other)),
                    };
                    if (abs_start, *sub_size) == current {
                        results.push(Ok((abs_start as u64, data)));
                        match iter.next() {
                            Some(next) => current = *next,
                            None => return Ok(results),
                        }
                    } else {
                        data_map.insert((abs_start, *sub_size), data);
                    }
                    while let Some(d) = data_map.remove(&current) {
                        results.push(Ok((current.0 as u64, d)));
                        match iter.next() {
                            Some(next) => current = *next,
                            None => return Ok(results),
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client::HttpClientConfig;

    fn fresh_client() -> Arc<HttpClient> {
        Arc::new(HttpClient::new(HttpClientConfig::default()).expect("client builds"))
    }

    #[test]
    fn normalise_http_url_keeps_trailing_slash() {
        let (scheme, url, _params) = normalise_http_url("http://example.com").unwrap();
        assert_eq!(scheme, "http");
        assert!(url.as_str().ends_with('/'));
    }

    #[test]
    fn normalise_http_url_strips_impl_suffix() {
        let (scheme, _url, _params) = normalise_http_url("http+urllib://example.com/").unwrap();
        // The unqualified scheme drops the +urllib qualifier so
        // external_url and remote_url emit the canonical form.
        assert_eq!(scheme, "http");
    }

    #[test]
    fn normalise_http_url_rejects_non_http() {
        assert!(normalise_http_url("ftp://example.com/").is_err());
    }

    #[test]
    fn transport_is_readonly() {
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(t.is_readonly());
    }

    #[test]
    fn transport_listable_false() {
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(!t.listable());
    }

    #[test]
    fn transport_external_url_is_canonical() {
        let t = HttpTransport::new("http+urllib://example.com/", fresh_client()).unwrap();
        let url = t.external_url().unwrap();
        // The +urllib qualifier shouldn't leak.
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn transport_remote_url_strips_credentials() {
        let t = HttpTransport::new("http://user:pass@example.com/", fresh_client()).unwrap();
        let url = t.remote_url("path").unwrap();
        // user/password belong in headers, not in the URL we send
        // upstream. Servers shouldn't see credentials in path-form.
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
    }

    #[test]
    fn transport_clone_with_offset_resolves_against_base() {
        let t = HttpTransport::new("http://example.com/a/", fresh_client()).unwrap();
        let cloned = Transport::clone(&t, Some("b/")).unwrap();
        assert_eq!(cloned.base().as_str(), "http://example.com/a/b/");
    }

    #[test]
    fn transport_write_methods_reject_with_transport_not_possible() {
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            t.put_file("x", &mut empty, None),
            Err(Error::TransportNotPossible(_))
        ));
        assert!(matches!(
            t.mkdir("d", None),
            Err(Error::TransportNotPossible(_))
        ));
        assert!(matches!(t.delete("x"), Err(Error::TransportNotPossible(_))));
    }

    #[test]
    fn format_range_header_basic() {
        assert_eq!(
            format_range_header(&[(0, 100), (200, 50)], 0),
            "0-99,200-249"
        );
    }

    #[test]
    fn format_range_header_with_tail() {
        assert_eq!(format_range_header(&[(0, 100)], 50), "0-99,-50");
    }

    #[test]
    fn format_range_header_tail_only() {
        assert_eq!(format_range_header(&[], 100), "-100");
    }

    // ----- abspath / clone_concrete -----

    #[test]
    fn abspath_empty_returns_base() {
        let t = HttpTransport::new("http://example.com/a/", fresh_client()).unwrap();
        assert_eq!(t.abspath("").unwrap().as_str(), "http://example.com/a/");
        assert_eq!(t.abspath(".").unwrap().as_str(), "http://example.com/a/");
    }

    #[test]
    fn abspath_rejects_non_ascii() {
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(matches!(t.abspath("héllo"), Err(Error::UrlError(_))));
    }

    #[test]
    fn abspath_unescapes_unreserved_characters() {
        // RFC 3986 unreserved chars (A-Z a-z 0-9 - . _ ~) must come
        // out un-escaped so clone()s of sibling branches are prefix-
        // comparable (lp:842223).
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        let url = t.abspath("%2D%2E%30%39%41%5A%5F%61%7A%7E").unwrap();
        assert_eq!(url.as_str(), "http://example.com/-.09AZ_az~");
    }

    #[test]
    fn abspath_drops_trailing_slash_from_relpath() {
        // Matches Python `URL.clone(relpath)` semantics: callers that
        // want directory-shape use clone() (which re-adds the slash),
        // abspath is path-only.
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert_eq!(
            t.abspath("foo/").unwrap().as_str(),
            "http://example.com/foo"
        );
    }

    #[test]
    fn clone_concrete_adds_trailing_slash_when_missing() {
        let t = HttpTransport::new("http://example.com/a/", fresh_client()).unwrap();
        // Offset without a trailing slash — the clone should still
        // be directory-shaped so downstream joins work correctly.
        let cloned = t.clone_concrete(Some("b")).unwrap();
        assert_eq!(cloned.base().as_str(), "http://example.com/a/b/");
    }

    #[test]
    fn clone_concrete_preserves_existing_trailing_slash() {
        let t = HttpTransport::new("http://example.com/a/", fresh_client()).unwrap();
        let cloned = t.clone_concrete(Some("b/")).unwrap();
        assert_eq!(cloned.base().as_str(), "http://example.com/a/b/");
    }

    #[test]
    fn clone_concrete_none_returns_identical_base() {
        let t = HttpTransport::new("http://example.com/a/", fresh_client()).unwrap();
        let cloned = t.clone_concrete(None).unwrap();
        assert_eq!(cloned.base().as_str(), "http://example.com/a/");
    }

    // ----- segment parameters -----

    #[test]
    fn segment_parameters_parsed_from_base_url() {
        let t = HttpTransport::new(
            "http://example.com/path/,key1=val1,key2=val2",
            fresh_client(),
        )
        .unwrap();
        let params = t.get_segment_parameters().unwrap();
        assert_eq!(params.get("key1"), Some(&"val1".to_string()));
        assert_eq!(params.get("key2"), Some(&"val2".to_string()));
        // base() reports the joined form so the segment params
        // survive any serialisation round-trip.
        assert!(t.base().as_str().contains("key1=val1"));
        assert!(t.base().as_str().contains("key2=val2"));
    }

    #[test]
    fn segment_parameters_dont_appear_on_the_wire() {
        // `remote_url` is the URL we hand the server — segment params
        // are a dromedary-internal convention and must stay local.
        let t = HttpTransport::new("http://example.com/path/,key=val", fresh_client()).unwrap();
        let remote = t.remote_url("file").unwrap();
        assert!(!remote.as_str().contains(','));
        assert!(!remote.as_str().contains("key=val"));
    }

    #[test]
    fn set_segment_parameter_round_trip() {
        let mut t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        t.set_segment_parameter("arm", Some("board")).unwrap();
        assert_eq!(
            t.get_segment_parameters().unwrap().get("arm"),
            Some(&"board".to_string())
        );
        // Setting value=None removes the parameter.
        t.set_segment_parameter("arm", None).unwrap();
        assert!(t.get_segment_parameters().unwrap().get("arm").is_none());
        // Removing a nonexistent parameter is a no-op, not an error.
        t.set_segment_parameter("nonexistent", None).unwrap();
    }

    #[test]
    fn set_segment_parameter_rejects_equals_in_key() {
        let mut t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(t.set_segment_parameter("k=bad", Some("v")).is_err());
    }

    #[test]
    fn set_segment_parameter_rejects_comma_in_value() {
        let mut t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        // Commas separate parameters, so a value containing one would
        // be indistinguishable from two parameters on the next parse.
        assert!(t.set_segment_parameter("k", Some("bad,value")).is_err());
    }

    #[test]
    fn clone_clears_segment_parameters() {
        // Matches Python ConnectedTransport semantics: clone drops
        // segment parameters because they belong to the specific
        // base URL, not to the connection.
        let t = HttpTransport::new("http://example.com/a/,key=val", fresh_client()).unwrap();
        let cloned = t.clone_concrete(None).unwrap();
        assert!(cloned.get_segment_parameters().unwrap().is_empty());
    }

    // ----- ConnectedTransport trait getters -----

    #[test]
    fn connected_scheme_is_unqualified() {
        let t = HttpTransport::new("http+urllib://example.com/", fresh_client()).unwrap();
        // `+urllib` is stripped at construction, so scheme() reports
        // the unqualified form even though the caller gave a suffix.
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::scheme(&t),
            "http"
        );
    }

    #[test]
    fn connected_host_and_port() {
        let t = HttpTransport::new("http://example.com:8080/", fresh_client()).unwrap();
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::host(&t),
            Some("example.com".to_string())
        );
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::port(&t),
            Some(8080)
        );
    }

    #[test]
    fn connected_port_absent_for_default_port() {
        // Url::port() returns None when the scheme's default port is
        // used (80 for http, 443 for https) — callers that want the
        // default port fall back themselves.
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert_eq!(<HttpTransport as crate::ConnectedTransport>::port(&t), None);
    }

    #[test]
    fn connected_user_and_password_are_percent_decoded() {
        let t = HttpTransport::new("http://jo%40home:p%40ss@example.com/", fresh_client()).unwrap();
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::user(&t),
            Some("jo@home".to_string())
        );
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::password(&t),
            Some("p@ss".to_string())
        );
    }

    #[test]
    fn connected_user_and_password_absent_when_not_in_url() {
        let t = HttpTransport::new("http://example.com/", fresh_client()).unwrap();
        assert_eq!(<HttpTransport as crate::ConnectedTransport>::user(&t), None);
        assert_eq!(
            <HttpTransport as crate::ConnectedTransport>::password(&t),
            None
        );
    }

    // ----- classify_reuse_for -----

    #[test]
    fn classify_reuse_same_origin_same_path() {
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http://host/path/"),
            crate::ReuseMatch::Same
        );
    }

    #[test]
    fn classify_reuse_same_origin_normalises_trailing_slash() {
        // `/path` and `/path/` are the same transport.
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http://host/path"),
            crate::ReuseMatch::Same
        );
    }

    #[test]
    fn classify_reuse_same_origin_different_path() {
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http://host/other/"),
            crate::ReuseMatch::Sibling
        );
    }

    #[test]
    fn classify_reuse_different_scheme_rejected() {
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "https://host/path/"),
            crate::ReuseMatch::None
        );
    }

    #[test]
    fn classify_reuse_impl_qualifier_stripped() {
        // `http://` and `http+urllib://` address the same origin —
        // the qualifier is implementation choice, not part of identity.
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http+urllib://host/path/"),
            crate::ReuseMatch::Same
        );
    }

    #[test]
    fn classify_reuse_different_host_or_port_rejected() {
        let base = url::Url::parse("http://host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http://other/path/"),
            crate::ReuseMatch::None
        );
        assert_eq!(
            crate::classify_reuse_for(&base, "http://host:9090/path/"),
            crate::ReuseMatch::None
        );
    }

    #[test]
    fn classify_reuse_different_user_rejected() {
        let base = url::Url::parse("http://alice@host/path/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "http://bob@host/path/"),
            crate::ReuseMatch::None
        );
    }

    #[test]
    fn classify_reuse_unparseable_url_returns_none() {
        let base = url::Url::parse("http://host/").unwrap();
        assert_eq!(
            crate::classify_reuse_for(&base, "not a url"),
            crate::ReuseMatch::None
        );
    }
}

/// Internal control flow between `readv_eager` and `readv_one_pass`.
enum ReadvPassError {
    /// Server misbehaved; step the range hint down and try again
    /// with the given remaining offsets. `cause` is the underlying
    /// error (if any) that triggered the retry — surfaced to the
    /// caller once the degradation ladder runs out, so the final
    /// error is specific rather than a generic "server misbehaved".
    Retry {
        remaining: Vec<(usize, usize)>,
        cause: Option<Error>,
    },
    /// Hard error — surface to the caller.
    Hard(Error),
}
