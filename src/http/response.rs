//! HTTP response body helpers.
//!
//! Port of `dromedary/http/response.py`: two file-like wrappers
//! (`ResponseFile`, `RangeFile`) and the `handle_response` factory.
//! The parse logic is written over an [`InFile`] trait so it can be
//! unit-tested in pure Rust against a `Cursor`, and then re-used from
//! PyO3 by implementing [`InFile`] on a Python file-like.
//!
//! The class contract is defined by the Python originals. In
//! particular:
//!
//! - `ResponseFile` supports forward-only seeks and proxies `read` /
//!   `readline` / `readlines` / `tell` to the wrapped file-like.
//! - `RangeFile` overlays range-window semantics on top: reading past
//!   the current range raises `InvalidRange`, and in a multipart
//!   response a seek past the end discards data and walks to the next
//!   part by reading the boundary and `Content-Range:` header. The
//!   grammar we accept is
//!
//!   ```text
//!   file:           single_range | multiple_range
//!   single_range:   content_range_header data
//!   multiple_range: boundary_header boundary
//!                   (content_range_header data boundary)+
//!   ```
//!
//! Sockets can't be rewound, so "seek backwards" is always a hard
//! error — that's enforced in both `ResponseFile::seek` and
//! `RangeFile::seek`.

use std::collections::HashMap;
use std::io;

/// Source of bytes backing a `ResponseFile` / `RangeFile`.
///
/// Mirrors the subset of the Python file-like protocol the Python
/// implementation actually used: byte-oriented `read(n)` and
/// `readline()` (newline-terminated, empty at EOF). No `seek` — the
/// original works on sockets, which are inherently forward-only, and
/// the range-file simulates backwards-disallowed seeks by discarding.
pub trait InFile {
    /// Read *up to* `n` bytes. Returning fewer than `n` is not
    /// necessarily EOF (matches the Python semantics of `socket.recv`
    /// / `BytesIO.read`): callers that need exactly `n` bytes must
    /// loop.
    fn read(&mut self, n: usize) -> io::Result<Vec<u8>>;

    /// Read a line, newline character included, like
    /// `io.BufferedReader.readline()` or `socket.makefile().readline()`.
    /// Returns empty on EOF.
    fn readline(&mut self) -> io::Result<Vec<u8>>;
}

/// Errors raised by the response parser. Each variant maps 1:1 to a
/// Python exception class defined in `dromedary.errors`, with the
/// exact field set the Python side constructs.
#[derive(Debug)]
pub enum ResponseError {
    /// `dromedary.errors.InvalidHttpResponse(path, msg)`.
    InvalidResponse { path: String, msg: String },
    /// `dromedary.errors.InvalidHttpRange(path, range, msg)`.
    InvalidHttpRange {
        path: String,
        range: String,
        msg: String,
    },
    /// `dromedary.errors.HttpBoundaryMissing(path, msg)`. The Python
    /// side passes the raw boundary bytes as the `msg`; we mirror that
    /// by keeping the field name.
    BoundaryMissing { path: String, boundary: Vec<u8> },
    /// `dromedary.errors.ShortReadvError(path, offset, length, actual)`.
    ShortReadv {
        path: String,
        offset: u64,
        length: u64,
        actual: u64,
    },
    /// `dromedary.errors.InvalidRange(path, offset, msg)`.
    InvalidRange {
        path: String,
        offset: u64,
        msg: String,
    },
    /// `dromedary.errors.UnexpectedHttpStatus(path, code)`.
    UnexpectedStatus { path: String, code: u16 },
    /// An IO error surfaced from the underlying file-like. The Python
    /// side lets these bubble up as-is.
    Io(io::Error),
    /// A seek was requested with an unknown `whence` value. The
    /// Python `RangeFile.seek` raised `ValueError` for this case,
    /// distinct from `InvalidRange` (a legitimate-but-out-of-bounds
    /// seek).
    InvalidWhence(u32),
    /// Forward-only seek rejected: the caller asked to seek to an
    /// absolute position that was earlier than the current one. The
    /// Python `ResponseFile.seek` flagged this as `AssertionError`;
    /// we surface it as its own variant so the PyO3 layer can raise
    /// a distinct exception type rather than something generic.
    BackwardSeek { path: String, pos: u64, offset: i64 },
}

impl From<io::Error> for ResponseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ResponseError>;

// ---------------------------------------------------------------------------
// ResponseFile: forward-only wrapper that tracks position across the
// underlying stream. Reads pass through; seek forward is simulated by
// reading and discarding.
// ---------------------------------------------------------------------------

/// A wrapper around the http socket containing the result of a GET
/// request. Only `read()` and forward-only `seek()` are supported.
pub struct ResponseFile<F: InFile> {
    path: String,
    file: F,
    pos: u64,
}

impl<F: InFile> ResponseFile<F> {
    /// Construct around the given input; `path` is used only in error
    /// messages.
    pub fn new(path: impl Into<String>, file: F) -> Self {
        Self {
            path: path.into(),
            file,
            pos: 0,
        }
    }

    /// Current position reported to callers.
    pub fn tell(&self) -> u64 {
        self.pos
    }

    /// Read up to `size` bytes; `None` means read all. Mirrors the
    /// Python signature.
    pub fn read(&mut self, size: Option<usize>) -> Result<Vec<u8>> {
        let data = match size {
            Some(n) => self.file.read(n)?,
            None => read_all(&mut self.file)?,
        };
        self.pos += data.len() as u64;
        Ok(data)
    }

    /// Read a single line.
    pub fn readline(&mut self) -> Result<Vec<u8>> {
        let data = self.file.readline()?;
        self.pos += data.len() as u64;
        Ok(data)
    }

    /// Read all remaining lines and return them as a vector. Matches
    /// the Python `readlines()` in that it only honours the split
    /// performed by the underlying file-like.
    pub fn readlines(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        loop {
            let line = self.file.readline()?;
            if line.is_empty() {
                break;
            }
            self.pos += line.len() as u64;
            out.push(line);
        }
        Ok(out)
    }

    /// Forward-only seek. Whence matches `os.SEEK_*` values:
    /// `0 == SET`, `1 == CUR`. Python's original also rejects `SEEK_END`
    /// (anything other than SET/CUR) with an assertion.
    pub fn seek(&mut self, offset: i64, whence: u32) -> Result<()> {
        let to_discard: u64 = match whence {
            0 => {
                // absolute
                if offset < 0 || (offset as u64) < self.pos {
                    return Err(ResponseError::BackwardSeek {
                        path: self.path.clone(),
                        pos: self.pos,
                        offset,
                    });
                }
                (offset as u64) - self.pos
            }
            1 => {
                // relative; Python's version accepts negative offset
                // but the later `read()` call on the socket would just
                // block. We mirror its "read offset bytes forward"
                // behaviour for offset >= 0 and reject negatives.
                if offset < 0 {
                    return Err(ResponseError::BackwardSeek {
                        path: self.path.clone(),
                        pos: self.pos,
                        offset,
                    });
                }
                offset as u64
            }
            other => return Err(ResponseError::InvalidWhence(other)),
        };
        if to_discard > 0 {
            self.read(Some(to_discard as usize))?;
        }
        Ok(())
    }

    /// Borrow the wrapped path (useful for subclasses built on top).
    pub fn path(&self) -> &str {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// RangeFile: overlays range/multipart semantics on top of the same
// forward-only stream. Track the current `(start, size)` window; when
// we exhaust it in a multipart response we read a boundary + Content-
// Range header and move the window forward.
// ---------------------------------------------------------------------------

/// In `_checked_read()` we may have to discard several MB in the worst
/// case. To avoid buffering that much, we read-and-discard by chunks.
/// The underlying file is either a socket or a `BytesIO`, so 8 KiB
/// chunks are fine.
const DISCARDED_BUF_SIZE: usize = 8192;

/// File-like exposing ranges of a larger resource. All accesses must
/// be sequential: ranges are discovered as the stream is consumed.
pub struct RangeFile<F: InFile> {
    inner: ResponseFile<F>,
    start: u64,
    /// `None` means "size unknown" (i.e. the whole file, or a range
    /// whose length the server didn't declare).
    size: Option<u64>,
    boundary: Option<Vec<u8>>,
    /// Parsed headers for the *current* part of a multipart response.
    /// `None` before any part has been read.
    headers: Option<HashMap<String, String>>,
    /// Chunk size used by `checked_read` — tests set this very low to
    /// exercise the buffer loop.
    discarded_buf_size: usize,
}

impl<F: InFile> RangeFile<F> {
    pub fn new(path: impl Into<String>, file: F) -> Self {
        let mut rf = Self {
            inner: ResponseFile::new(path, file),
            start: 0,
            size: None,
            boundary: None,
            headers: None,
            discarded_buf_size: DISCARDED_BUF_SIZE,
        };
        // Default to "the whole file of unspecified size", matching
        // `RangeFile.__init__` in Python.
        rf.set_range(0, None);
        rf
    }

    /// Change the range window. `size=None` means "unknown" (Python's
    /// `-1`). Resets `pos` to `start` like the Python original does.
    pub fn set_range(&mut self, start: u64, size: Option<u64>) {
        self.start = start;
        self.size = size;
        self.inner.pos = start;
    }

    /// Multipart mode: once the boundary is known, the wrapper reads
    /// the first boundary + Content-Range headers to position itself
    /// at the start of the first part's body. Subsequent boundary
    /// crossings happen automatically as `read`/`seek` walks forward.
    pub fn set_boundary(&mut self, boundary: Vec<u8>) -> Result<()> {
        self.boundary = Some(boundary);
        self.read_boundary()?;
        self.read_range_definition()?;
        Ok(())
    }

    /// Read the boundary line. RFC 2616 §19.2 allows additional
    /// `CRLF` preceding the boundary so we skip any we find. IIS 6/7
    /// wraps the boundary in `<>`; we unquote those too.
    pub fn read_boundary(&mut self) -> Result<()> {
        let boundary = self
            .boundary
            .as_ref()
            .expect("set_boundary() must be called before read_boundary()")
            .clone();
        let mut line = b"\r\n".to_vec();
        while line == b"\r\n" {
            line = self.inner.file.readline()?;
        }
        if line.is_empty() {
            // A timeout in the proxy caused the response to end early
            // (launchpad bug 198646).
            return Err(ResponseError::BoundaryMissing {
                path: self.inner.path.clone(),
                boundary,
            });
        }
        let mut expected = Vec::with_capacity(boundary.len() + 4);
        expected.extend_from_slice(b"--");
        expected.extend_from_slice(&boundary);
        expected.extend_from_slice(b"\r\n");
        if line != expected {
            // email.utils.unquote() mis-handles `<...>`-wrapped
            // boundaries (IIS 6/7), so let it take a second pass.
            if unquote_boundary(&line) != expected {
                let shown = String::from_utf8_lossy(&line);
                let b_shown = String::from_utf8_lossy(&boundary);
                return Err(ResponseError::InvalidResponse {
                    path: self.inner.path.clone(),
                    msg: format!("Expected a boundary ({}) line, got '{}'", b_shown, shown),
                });
            }
        }
        Ok(())
    }

    /// Parse the headers introducing the new range and apply the
    /// Content-Range value.
    pub fn read_range_definition(&mut self) -> Result<()> {
        let headers = parse_headers(&mut self.inner.file)?;
        let cr = headers.get("content-range").cloned().ok_or_else(|| {
            ResponseError::InvalidResponse {
                path: self.inner.path.clone(),
                msg: "Content-Range header missing in a multi-part response".into(),
            }
        })?;
        self.headers = Some(headers);
        self.set_range_from_header(&cr)
    }

    /// Apply a `Content-Range: bytes START-END/TOTAL` header. Values
    /// other than `bytes` or malformed numbers raise
    /// [`ResponseError::InvalidHttpRange`].
    pub fn set_range_from_header(&mut self, content_range: &str) -> Result<()> {
        // Python's version uses `str.split()` with no args, which
        // splits on any whitespace run and drops empty tokens. So
        // leading/trailing/internal spaces and tabs are all OK, but
        // `"bytes10-2/3"` (no whitespace between type and values) is
        // a malformed header.
        let mut it = content_range.split_ascii_whitespace();
        let rtype = it.next().ok_or_else(|| ResponseError::InvalidHttpRange {
            path: self.inner.path.clone(),
            range: content_range.to_string(),
            msg: "Malformed header".into(),
        })?;
        let values = it.next().ok_or_else(|| ResponseError::InvalidHttpRange {
            path: self.inner.path.clone(),
            range: content_range.to_string(),
            msg: "Malformed header".into(),
        })?;
        // Python's unpack via `rtype, values = content_range.split()`
        // raises `ValueError` if there are more than two tokens too.
        if it.next().is_some() {
            return Err(ResponseError::InvalidHttpRange {
                path: self.inner.path.clone(),
                range: content_range.to_string(),
                msg: "Malformed header".into(),
            });
        }
        if rtype != "bytes" {
            return Err(ResponseError::InvalidHttpRange {
                path: self.inner.path.clone(),
                range: content_range.to_string(),
                msg: format!("Unsupported range type '{}'", rtype),
            });
        }
        // The grammar is START-END/TOTAL (total may be `*`).
        let (start_end, _total) =
            values
                .split_once('/')
                .ok_or_else(|| ResponseError::InvalidHttpRange {
                    path: self.inner.path.clone(),
                    range: content_range.to_string(),
                    msg: "Invalid range values".into(),
                })?;
        let (start_s, end_s) =
            start_end
                .split_once('-')
                .ok_or_else(|| ResponseError::InvalidHttpRange {
                    path: self.inner.path.clone(),
                    range: content_range.to_string(),
                    msg: "Invalid range values".into(),
                })?;
        let start: i64 = start_s
            .parse()
            .map_err(|_| ResponseError::InvalidHttpRange {
                path: self.inner.path.clone(),
                range: content_range.to_string(),
                msg: "Invalid range values".into(),
            })?;
        let end: i64 = end_s.parse().map_err(|_| ResponseError::InvalidHttpRange {
            path: self.inner.path.clone(),
            range: content_range.to_string(),
            msg: "Invalid range values".into(),
        })?;
        let size = end - start + 1;
        if size <= 0 {
            return Err(ResponseError::InvalidHttpRange {
                path: self.inner.path.clone(),
                range: content_range.to_string(),
                msg: "Invalid range, size <= 0".into(),
            });
        }
        self.set_range(start as u64, Some(size as u64));
        Ok(())
    }

    pub fn tell(&self) -> u64 {
        self.inner.pos
    }

    pub fn path(&self) -> &str {
        &self.inner.path
    }

    // Accessors below are named with an `rs_` prefix so the PyO3
    // bindings can mirror the original pure-Python attributes
    // (`_start`, `_size`, `_pos`, `_boundary`) without colliding
    // with `RangeFile`'s own methods. The underscore-prefixed
    // attribute names are part of the observable API — a handful of
    // tests and callers read or assign to them directly.

    pub fn rs_start(&self) -> u64 {
        self.start
    }

    pub fn rs_set_start(&mut self, start: u64) {
        self.start = start;
    }

    pub fn rs_size(&self) -> Option<u64> {
        self.size
    }

    pub fn rs_set_size(&mut self, size: Option<u64>) {
        self.size = size;
    }

    pub fn rs_set_pos(&mut self, pos: u64) {
        self.inner.pos = pos;
    }

    pub fn rs_boundary(&self) -> Option<&[u8]> {
        self.boundary.as_deref()
    }

    pub fn rs_discarded_buf_size(&self) -> usize {
        self.discarded_buf_size
    }

    pub fn rs_set_discarded_buf_size(&mut self, value: usize) {
        self.discarded_buf_size = value;
    }

    /// Read and discard exactly `size` bytes; used internally by
    /// seek/boundary-walking. Raises `ShortReadv` if the stream ends
    /// early — this is what signals the server misbehaved.
    fn checked_read(&mut self, size: u64) -> Result<()> {
        let pos = self.inner.pos;
        let mut remaining = size;
        while remaining > 0 {
            let take = remaining.min(self.discarded_buf_size as u64) as usize;
            let data = self.inner.file.read(take)?;
            if data.is_empty() {
                return Err(ResponseError::ShortReadv {
                    path: self.inner.path.clone(),
                    offset: pos,
                    length: size,
                    actual: size - remaining,
                });
            }
            remaining -= data.len() as u64;
        }
        self.inner.pos += size;
        Ok(())
    }

    /// Walk forward to the next part of a multipart response. Raises
    /// `InvalidRange` if this wasn't multipart to begin with (there's
    /// no next range to advance to).
    fn seek_to_next_range(&mut self) -> Result<()> {
        if self.boundary.is_none() {
            return Err(ResponseError::InvalidRange {
                path: self.inner.path.clone(),
                offset: self.inner.pos,
                msg: format!(
                    "Range ({}, {}) exhausted",
                    self.start,
                    format_size(self.size)
                ),
            });
        }
        self.read_boundary()?;
        self.read_range_definition()?;
        Ok(())
    }

    /// Read up to `size` bytes from the current range. `size < 0`
    /// means "read to end of range". Reading across ranges is not
    /// supported (the socket would already be past the boundary).
    pub fn read(&mut self, size: i64) -> Result<Vec<u8>> {
        // If we're sitting exactly at the end of a known-size range,
        // decide whether to walk to the next range or stop.
        if let Some(sz) = self.size {
            if self.inner.pos == self.start + sz {
                if size == 0 {
                    return Ok(Vec::new());
                } else {
                    self.seek_to_next_range()?;
                }
            }
        }
        if self.inner.pos < self.start {
            return Err(ResponseError::InvalidRange {
                path: self.inner.path.clone(),
                offset: self.inner.pos,
                msg: format!(
                    "Can't read {} bytes before range ({}, {})",
                    size,
                    self.start,
                    format_size(self.size)
                ),
            });
        }
        if let Some(sz) = self.size {
            if size > 0 && self.inner.pos + (size as u64) > self.start + sz {
                return Err(ResponseError::InvalidRange {
                    path: self.inner.path.clone(),
                    offset: self.inner.pos,
                    msg: format!(
                        "Can't read {} bytes across range ({}, {})",
                        size,
                        self.start,
                        format_size(self.size)
                    ),
                });
            }
        }

        // Cap the read so we never overflow past the range end.
        let limited: Option<usize> = match (self.size, size) {
            (Some(sz), _) => {
                let remaining = self.start + sz - self.inner.pos;
                let cap = match size {
                    n if n >= 0 => remaining.min(n as u64),
                    _ => remaining,
                };
                Some(cap as usize)
            }
            (None, n) if n < 0 => None,
            (None, n) => Some(n as usize),
        };
        let data = match limited {
            Some(n) => pump_exactly(&mut self.inner.file, n)?,
            None => read_all(&mut self.inner.file)?,
        };
        self.inner.pos += data.len() as u64;
        Ok(data)
    }

    /// Forward-only seek, with whence meaning `os.SEEK_*`. Seeking
    /// past the current range in a multipart response walks to the
    /// next part by reading the boundary + Content-Range; size `None`
    /// (unknown) rejects SEEK_END.
    pub fn seek(&mut self, offset: i64, whence: u32) -> Result<()> {
        let start_pos = self.inner.pos;
        let final_pos: i64 = match whence {
            0 => offset,
            1 => start_pos as i64 + offset,
            2 => match self.size {
                Some(sz) => self.start as i64 + sz as i64 + offset,
                None => {
                    return Err(ResponseError::InvalidRange {
                        path: self.inner.path.clone(),
                        offset: start_pos,
                        msg: "RangeFile: can't seek from end while size is unknown".into(),
                    });
                }
            },
            other => return Err(ResponseError::InvalidWhence(other)),
        };

        if final_pos < self.inner.pos as i64 {
            return Err(ResponseError::InvalidRange {
                path: self.inner.path.clone(),
                offset: start_pos,
                msg: format!("RangeFile: trying to seek backwards to {}", final_pos),
            });
        }

        let final_pos = final_pos as u64;
        if let Some(sz) = self.size {
            let mut cur_limit = self.start + sz;
            while final_pos > cur_limit {
                let remain = cur_limit - self.inner.pos;
                if remain > 0 {
                    self.checked_read(remain)?;
                }
                self.seek_to_next_range()?;
                cur_limit = self.start + self.size.expect("after seek_to_next_range size is set");
            }
        }

        let size = final_pos.saturating_sub(self.inner.pos);
        if size > 0 {
            self.checked_read(size)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// handle_response: the factory that picks between ResponseFile and
// RangeFile based on the status code + headers. 200 returns the plain
// wrapper; 206 returns a RangeFile (with boundary set for multipart
// responses, or a single Content-Range applied otherwise). Anything
// else raises UnexpectedHttpStatus.
// ---------------------------------------------------------------------------

/// The two possible wrappers returned by [`handle_response`].
pub enum ResponseKind<F: InFile> {
    Plain(ResponseFile<F>),
    Range(RangeFile<F>),
}

/// Inspect the status code + headers and wrap `data` in the right
/// response type. See `dromedary/http/response.py::handle_response`.
///
/// `get_header` returns the (lower-cased) header value or `None`; the
/// caller is responsible for case-insensitive lookup. On 206 we need
/// `content-type` and possibly `content-range` from the real response
/// headers.
pub fn handle_response<F: InFile>(
    url: impl Into<String>,
    code: u16,
    get_header: &dyn Fn(&str) -> Option<String>,
    data: F,
) -> Result<ResponseKind<F>> {
    let url = url.into();
    match code {
        200 => Ok(ResponseKind::Plain(ResponseFile::new(url, data))),
        206 => {
            let mut rf = RangeFile::new(url.clone(), data);
            // RFC 2616 §7.2.1: missing Content-Type defaults to
            // application/octet-stream, so this is never multipart.
            let content_type = get_header("content-type")
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let (mimetype, params) = parse_content_type(&content_type);
            if mimetype == "multipart/byteranges" {
                let boundary =
                    params
                        .get("boundary")
                        .ok_or_else(|| ResponseError::InvalidResponse {
                            path: url.clone(),
                            msg: "multipart/byteranges missing boundary parameter".into(),
                        })?;
                rf.set_boundary(boundary.as_bytes().to_vec())?;
            } else {
                let cr =
                    get_header("content-range").ok_or_else(|| ResponseError::InvalidResponse {
                        path: url.clone(),
                        msg: "Missing the Content-Range header in a 206 range response".into(),
                    })?;
                rf.set_range_from_header(&cr)?;
            }
            Ok(ResponseKind::Range(rf))
        }
        code => Err(ResponseError::UnexpectedStatus { path: url, code }),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_all<F: InFile>(file: &mut F) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let chunk = file.read(DISCARDED_BUF_SIZE)?;
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Read exactly `n` bytes from `file`, looping over short reads.
/// Returns less than `n` only on EOF — matching how the Python
/// `pumpfile` helper behaves when the source is a socket.
fn pump_exactly<F: InFile>(file: &mut F, n: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let chunk = file.read(n - out.len())?;
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Parse `Content-Type: mimetype; key=value; key2=value2`. Returns the
/// lower-cased mime type and a map of parameter keys (lower-cased) to
/// values with any surrounding double-quotes stripped.
fn parse_content_type(value: &str) -> (String, HashMap<String, String>) {
    let mut parts = value.split(';');
    let mime = parts
        .next()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut params = HashMap::new();
    for p in parts {
        let p = p.trim();
        if let Some((k, v)) = p.split_once('=') {
            let v = v.trim();
            let v = if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
                &v[1..v.len() - 1]
            } else {
                v
            };
            params.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    (mime, params)
}

/// Unquote a boundary line that IIS 6/7 wraps in angle brackets.
/// Preserves the `"--"` prefix and the trailing `\r\n`; only the
/// middle 20-odd bytes are run through the unquoter. Mirrors the
/// Python helper verbatim.
fn unquote_boundary(line: &[u8]) -> Vec<u8> {
    if line.len() < 4 {
        return line.to_vec();
    }
    let prefix = &line[..2];
    let suffix = &line[line.len() - 2..];
    let body = &line[2..line.len() - 2];
    // email.utils.unquote strips `"..."` or `<...>` wrapping (and
    // handles a couple of backslash escapes inside `"..."`). We do
    // the same for the inner bytes, interpreted as ASCII.
    let inner = match std::str::from_utf8(body) {
        Ok(s) => email_unquote(s).into_bytes(),
        Err(_) => body.to_vec(),
    };
    let mut out = Vec::with_capacity(prefix.len() + inner.len() + suffix.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&inner);
    out.extend_from_slice(suffix);
    out
}

/// Stripped-down port of `email.utils.unquote`: removes a matching
/// pair of `"..."` (unescaping `\\` and `\"`) or `<...>` wrappers.
fn email_unquote(s: &str) -> String {
    if s.len() <= 1 {
        return s.to_string();
    }
    if s.starts_with('"') && s.ends_with('"') {
        return s[1..s.len() - 1]
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
    }
    if s.starts_with('<') && s.ends_with('>') {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Read RFC 822-style headers up to the blank line. Header names are
/// lower-cased; values are trimmed of leading/trailing whitespace.
/// Multi-line continuation (leading whitespace on the next line) is
/// folded with a single space, matching `http.client.parse_headers`.
fn parse_headers<F: InFile>(file: &mut F) -> Result<HashMap<String, String>> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut last_key: Option<String> = None;
    loop {
        let raw = file.readline()?;
        if raw.is_empty() {
            break;
        }
        let line = std::str::from_utf8(&raw).map_err(|_| ResponseError::InvalidResponse {
            path: String::new(),
            msg: "non-UTF-8 header".into(),
        })?;
        // Strip the CRLF / LF terminator.
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(k) = &last_key {
                let prev = out.get(k).cloned().unwrap_or_default();
                let folded = format!("{} {}", prev, line.trim());
                out.insert(k.clone(), folded);
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            last_key = Some(k.clone());
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn format_size(size: Option<u64>) -> String {
    match size {
        Some(n) => n.to_string(),
        None => "-1".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the logic against a Cursor-backed InFile.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Cursor};

    /// Test adapter: a `Cursor<Vec<u8>>`-backed `InFile`. Matches
    /// Python's `BytesIO` semantics (unbuffered `read`, `readline`
    /// terminates on `\n` or EOF).
    struct TestFile {
        cur: Cursor<Vec<u8>>,
    }

    impl TestFile {
        fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                cur: Cursor::new(bytes.into()),
            }
        }
    }

    impl InFile for TestFile {
        fn read(&mut self, n: usize) -> io::Result<Vec<u8>> {
            use std::io::Read;
            let mut out = vec![0u8; n];
            let got = self.cur.read(&mut out)?;
            out.truncate(got);
            Ok(out)
        }
        fn readline(&mut self) -> io::Result<Vec<u8>> {
            let mut out = Vec::new();
            self.cur.read_until(b'\n', &mut out)?;
            Ok(out)
        }
    }

    #[test]
    fn response_file_read_tracks_position() {
        let mut rf = ResponseFile::new("p", TestFile::new(b"hello, world".to_vec()));
        assert_eq!(rf.read(Some(5)).unwrap(), b"hello");
        assert_eq!(rf.tell(), 5);
        assert_eq!(rf.read(None).unwrap(), b", world");
        assert_eq!(rf.tell(), 12);
    }

    #[test]
    fn response_file_readline() {
        let mut rf = ResponseFile::new("p", TestFile::new(b"a\nbb\nccc".to_vec()));
        assert_eq!(rf.readline().unwrap(), b"a\n");
        assert_eq!(rf.readline().unwrap(), b"bb\n");
        assert_eq!(rf.readline().unwrap(), b"ccc");
        assert_eq!(rf.readline().unwrap(), b"");
    }

    #[test]
    fn response_file_forward_seek_discards() {
        let mut rf = ResponseFile::new("p", TestFile::new(b"0123456789".to_vec()));
        rf.seek(3, 0).unwrap();
        assert_eq!(rf.tell(), 3);
        assert_eq!(rf.read(Some(3)).unwrap(), b"345");
    }

    #[test]
    fn response_file_seek_backwards_errors() {
        let mut rf = ResponseFile::new("p", TestFile::new(b"abcd".to_vec()));
        rf.read(Some(3)).unwrap();
        let err = rf.seek(1, 0).unwrap_err();
        assert!(matches!(err, ResponseError::BackwardSeek { .. }));
    }

    #[test]
    fn response_file_seek_invalid_whence() {
        let mut rf = ResponseFile::new("p", TestFile::new(b"abcd".to_vec()));
        let err = rf.seek(0, 14).unwrap_err();
        assert!(matches!(err, ResponseError::InvalidWhence(14)));
    }

    #[test]
    fn range_file_default_reads_whole_stream() {
        let mut rf = RangeFile::new("p", TestFile::new(b"the quick brown fox".to_vec()));
        let got = rf.read(-1).unwrap();
        assert_eq!(got, b"the quick brown fox");
    }

    #[test]
    fn range_file_set_range_caps_read() {
        let mut rf = RangeFile::new("p", TestFile::new(b"abcdefg".to_vec()));
        rf.set_range(0, Some(3));
        let got = rf.read(-1).unwrap();
        assert_eq!(got, b"abc");
    }

    #[test]
    fn range_file_read_past_range_errors() {
        let mut rf = RangeFile::new("p", TestFile::new(b"abcdefg".to_vec()));
        rf.set_range(0, Some(3));
        let err = rf.read(5).unwrap_err();
        assert!(matches!(err, ResponseError::InvalidRange { .. }));
    }

    #[test]
    fn parse_headers_basic() {
        let mut f =
            TestFile::new(b"Content-Type: text/plain\r\nContent-Length: 12\r\n\r\n".to_vec());
        let h = parse_headers(&mut f).unwrap();
        assert_eq!(
            h.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        assert_eq!(h.get("content-length").map(String::as_str), Some("12"));
    }

    #[test]
    fn parse_headers_folds_continuations() {
        let mut f = TestFile::new(b"X-Foo: alpha\r\n  beta\r\n\r\n".to_vec());
        let h = parse_headers(&mut f).unwrap();
        assert_eq!(h.get("x-foo").map(String::as_str), Some("alpha beta"));
    }

    #[test]
    fn parse_content_type_with_boundary() {
        let (mime, params) = parse_content_type(r#"multipart/byteranges; boundary="abc123""#);
        assert_eq!(mime, "multipart/byteranges");
        assert_eq!(params.get("boundary").map(String::as_str), Some("abc123"));
    }

    #[test]
    fn unquote_boundary_handles_angle_brackets() {
        // IIS 6/7 wraps the boundary in <...>
        let line = b"--<abc>\r\n";
        let expected = b"--abc\r\n";
        assert_eq!(unquote_boundary(line), expected);
    }

    #[test]
    fn set_range_from_header_parses_bytes_range() {
        let mut rf = RangeFile::new("p", TestFile::new(Vec::new()));
        rf.set_range_from_header("bytes 200-999/1234").unwrap();
        assert_eq!(rf.start, 200);
        assert_eq!(rf.size, Some(800));
    }

    #[test]
    fn set_range_from_header_rejects_non_bytes() {
        let mut rf = RangeFile::new("p", TestFile::new(Vec::new()));
        let err = rf.set_range_from_header("lines 0-10/20").unwrap_err();
        assert!(matches!(err, ResponseError::InvalidHttpRange { .. }));
    }

    #[test]
    fn set_range_from_header_rejects_inverted() {
        let mut rf = RangeFile::new("p", TestFile::new(Vec::new()));
        let err = rf.set_range_from_header("bytes 10-5/20").unwrap_err();
        assert!(matches!(err, ResponseError::InvalidHttpRange { .. }));
    }

    #[test]
    fn handle_response_200_plain() {
        let data = TestFile::new(b"body".to_vec());
        let get = |_: &str| -> Option<String> { None };
        let k = handle_response("u", 200, &get, data).unwrap();
        match k {
            ResponseKind::Plain(mut rf) => {
                assert_eq!(rf.read(None).unwrap(), b"body");
            }
            _ => panic!("expected Plain"),
        }
    }

    #[test]
    fn handle_response_206_single_range() {
        let data = TestFile::new(b"abcde".to_vec());
        let get = |name: &str| match name {
            "content-type" => Some("application/octet-stream".to_string()),
            "content-range" => Some("bytes 0-4/5".to_string()),
            _ => None,
        };
        let k = handle_response("u", 206, &get, data).unwrap();
        match k {
            ResponseKind::Range(mut rf) => {
                assert_eq!(rf.read(-1).unwrap(), b"abcde");
            }
            _ => panic!("expected Range"),
        }
    }

    #[test]
    fn handle_response_other_is_unexpected_status() {
        let data = TestFile::new(Vec::new());
        let get = |_: &str| -> Option<String> { None };
        // `unwrap_err` needs `T: Debug` and `ResponseKind` isn't Debug
        // (its inner `F` wouldn't be, in general), so match explicitly.
        match handle_response("u", 404, &get, data) {
            Err(ResponseError::UnexpectedStatus { code: 404, .. }) => {}
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => panic!("expected an error"),
        }
    }

    /// Multipart walk: two parts separated by boundaries; seek to the
    /// second range and read it.
    #[test]
    fn range_file_multipart_walk() {
        let boundary = b"XYZ";
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"--XYZ\r\n");
        body.extend_from_slice(b"Content-Range: bytes 0-2/10\r\n\r\n");
        body.extend_from_slice(b"abc");
        body.extend_from_slice(b"\r\n--XYZ\r\n");
        body.extend_from_slice(b"Content-Range: bytes 5-7/10\r\n\r\n");
        body.extend_from_slice(b"fgh");

        let mut rf = RangeFile::new("u", TestFile::new(body));
        rf.set_boundary(boundary.to_vec()).unwrap();
        // After set_boundary we're positioned at the start of part #1.
        assert_eq!(rf.tell(), 0);
        assert_eq!(rf.read(3).unwrap(), b"abc");
        // Seek forward into the second range; the wrapper walks the
        // boundary automatically.
        rf.seek(5, 0).unwrap();
        assert_eq!(rf.read(3).unwrap(), b"fgh");
    }
}
