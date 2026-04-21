//! Python bindings for `dromedary::http::client`.
//!
//! Exposes `HttpClient` as a `#[pyclass]`. The Python `HttpTransport`
//! in `dromedary/http/urllib.py` uses this instead of the legacy
//! urllib.request handler stack.
//!
//! The returned `HttpResponse` pyclass mirrors the shape the Python
//! code previously got from its `Urllib3LikeResponse` adapter —
//! `.status`, `.reason`, `.getheader()`, `.getheaders()`, `.data`,
//! `.text`, `.read()`, `.readline()`, `.readlines()` — so existing
//! callers (and the still-Python `HttpTransport.request` wrapper) see
//! no breaking change.

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use dromedary::http::client::{
    ClientError, HttpClient as RsHttpClient, HttpClientConfig, HttpResponse as RsHttpResponse,
    RequestOptions,
};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyString, PyTuple};

import_exception!(dromedary.errors, ConnectionError);
import_exception!(dromedary.errors, InvalidHttpResponse);

/// Turn a [`ClientError`] into an appropriate Python exception.
///
/// Transport-level failures (DNS, TCP, TLS) become
/// `dromedary.errors.ConnectionError`; malformed URLs / methods
/// become `ValueError`; IO errors after the response started
/// become `OSError`. This matches how the Python urllib-handler
/// stack used to funnel errors.
fn client_err_to_py(err: ClientError) -> PyErr {
    match err {
        ClientError::InvalidRequest(msg) => PyValueError::new_err(msg),
        ClientError::Io(e) => PyIOError::new_err(e.to_string()),
        ClientError::Transport(e) => {
            // `ureq::Error`'s Display carries the useful context
            // (hostname, port, TLS reason). Wrap as ConnectionError
            // so breezy's retry loop triggers on it the way it did
            // for the old handler-layer errors.
            ConnectionError::new_err(e.to_string())
        }
    }
}

#[pyclass(module = "dromedary._transport_rs.http", frozen)]
pub(crate) struct HttpClient {
    inner: RsHttpClient,
    // Default options applied when Python callers don't pass an
    // override. Wrapped in a Mutex because pyclass(frozen) forbids
    // &mut self; callers interact via dedicated setters below.
    defaults: Mutex<RequestOptions>,
}

#[pymethods]
impl HttpClient {
    /// Construct a new client.
    ///
    /// `ca_certs` — optional path to a PEM bundle.
    /// `disable_verification` — matches Python's `ssl.CERT_NONE`.
    /// `user_agent` — if omitted, inherits the module-level default.
    /// `read_timeout_ms` — 0 or negative means "no timeout".
    #[new]
    #[pyo3(signature = (
        ca_certs=None,
        disable_verification=false,
        user_agent=None,
        read_timeout_ms=0,
    ))]
    fn new(
        ca_certs: Option<PathBuf>,
        disable_verification: bool,
        user_agent: Option<String>,
        read_timeout_ms: i64,
    ) -> PyResult<Self> {
        let timeout = if read_timeout_ms > 0 {
            Some(Duration::from_millis(read_timeout_ms as u64))
        } else {
            None
        };
        let cfg = HttpClientConfig {
            ca_certs_path: ca_certs,
            disable_verification,
            user_agent,
            read_timeout: timeout,
        };
        let inner = RsHttpClient::new(cfg).map_err(client_err_to_py)?;
        Ok(Self {
            inner,
            defaults: Mutex::new(RequestOptions::default()),
        })
    }

    /// Set the default `follow_redirects` flag for subsequent calls
    /// that don't pass an explicit `follow_redirects` argument.
    ///
    /// Exposed so breezy's `HttpTransport.request(..., retries=N)`
    /// can toggle following once per transport rather than threading
    /// the flag through every call site.
    fn set_default_follow_redirects(&self, follow: bool) {
        self.defaults.lock().unwrap().follow_redirects = follow;
    }

    /// Issue an HTTP request.
    ///
    /// `headers` is an iterable of `(name, value)` pairs (matching the
    /// stdlib pattern). The response is returned as an `HttpResponse`
    /// pyclass mirroring the old `Urllib3LikeResponse` shape.
    #[pyo3(signature = (method, url, headers=None, body=None, follow_redirects=None))]
    fn request(
        &self,
        py: Python,
        method: &str,
        url: &str,
        headers: Option<Py<PyAny>>,
        body: Option<Py<PyAny>>,
        follow_redirects: Option<bool>,
    ) -> PyResult<HttpResponse> {
        let header_pairs = match headers {
            Some(h) => extract_headers(py, &h)?,
            None => Vec::new(),
        };
        let body_bytes = match body {
            Some(b) => extract_body(py, &b)?,
            None => Vec::new(),
        };
        let opts = {
            let mut o = self.defaults.lock().unwrap().clone();
            if let Some(f) = follow_redirects {
                o.follow_redirects = f;
            }
            o
        };

        // `Python::detach` releases the GIL while the HTTP call is
        // in flight so other Python threads can run (matching the
        // behaviour of the old urllib-based transport, which did the
        // actual socket read under the GIL-released `ssl` module).
        let resp = py.detach(|| {
            self.inner
                .request_with(method, url, &header_pairs, &body_bytes, &opts)
        });
        let resp = resp.map_err(client_err_to_py)?;
        Ok(HttpResponse::new(resp))
    }
}

/// Urllib3-shaped response returned by [`HttpClient::request`].
///
/// Intentionally offers both the Python-file protocol (`read`,
/// `readline`, `readlines`) and the urllib3 property set (`status`,
/// `reason`, `data`, `text`, `getheader`, `getheaders`) so existing
/// callers pulled from `Urllib3LikeResponse` work unchanged.
#[pyclass(module = "dromedary._transport_rs.http")]
pub(crate) struct HttpResponse {
    inner: Mutex<HttpResponseInner>,
}

/// Interior-mutable state held behind the pyclass lock. Separated
/// so we can borrow `&mut self` without exposing it through pyo3.
struct HttpResponseInner {
    /// Raw response data — headers stay accessible after the body is
    /// consumed, unlike an HTTPResponse which invalidates on close.
    raw: RsHttpResponse,
    /// Cursor over `raw.body`; advances on every `read` / `readline`.
    body: Cursor<Vec<u8>>,
}

impl HttpResponse {
    fn new(raw: RsHttpResponse) -> Self {
        let body = Cursor::new(raw.body.clone());
        Self {
            inner: Mutex::new(HttpResponseInner { raw, body }),
        }
    }
}

#[pymethods]
impl HttpResponse {
    #[getter]
    fn status(&self) -> u16 {
        self.inner.lock().unwrap().raw.status
    }

    #[getter]
    fn reason(&self) -> String {
        self.inner.lock().unwrap().raw.reason.clone()
    }

    /// Final URL after any redirect following. For requests that
    /// weren't redirected this equals the request URL.
    #[getter]
    fn final_url(&self) -> String {
        self.inner.lock().unwrap().raw.final_url.clone()
    }

    /// Set when the server returned a 3xx that the client didn't
    /// auto-follow (`follow_redirects=False`). Callers use this to
    /// raise `RedirectRequested`.
    #[getter]
    fn redirected_to(&self) -> Option<String> {
        self.inner.lock().unwrap().raw.redirected_to.clone()
    }

    /// Case-insensitive header lookup. `default` is returned if
    /// no header matches.
    #[pyo3(signature = (name, default=None))]
    fn getheader(&self, py: Python, name: &str, default: Option<Py<PyAny>>) -> Py<PyAny> {
        let inner = self.inner.lock().unwrap();
        match inner.raw.header(name) {
            Some(v) => PyString::new(py, v).into(),
            None => default.unwrap_or_else(|| py.None()),
        }
    }

    /// Return all headers as a list of `(name, value)` tuples.
    fn getheaders<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let inner = self.inner.lock().unwrap();
        let items: Vec<Bound<'py, PyAny>> = inner
            .raw
            .headers
            .iter()
            .map(|(k, v)| {
                let tup = PyTuple::new(py, [PyString::new(py, k), PyString::new(py, v)])?;
                Ok::<_, PyErr>(tup.into_any())
            })
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, items)
    }

    /// Full response body as bytes. Cached; reading this doesn't
    /// advance the `read()` cursor.
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let inner = self.inner.lock().unwrap();
        PyBytes::new(py, &inner.raw.body)
    }

    /// Decoded body as str, using the Content-Type charset when
    /// present. Matches the Python `Urllib3LikeResponse.text` shim —
    /// returns `None` on a 204 No Content response.
    #[getter]
    fn text(&self, py: Python) -> PyResult<Py<PyAny>> {
        let inner = self.inner.lock().unwrap();
        if inner.raw.status == 204 {
            return Ok(py.None());
        }
        let charset = inner
            .raw
            .header("content-type")
            .and_then(|v| {
                // Very small content-type parser: find `charset=`.
                v.split(';').find_map(|piece| {
                    let piece = piece.trim();
                    piece
                        .strip_prefix("charset=")
                        .map(|c| c.trim_matches('"').to_string())
                })
            })
            .unwrap_or_else(|| "utf-8".to_string());

        // Only UTF-8 is handled natively; everything else falls back
        // to replacing invalid bytes. Real non-UTF-8 payloads are
        // vanishingly rare on the Bazaar smart-protocol path this
        // is aimed at, and breezy didn't support them either.
        let text = match charset.to_ascii_lowercase().as_str() {
            "utf-8" | "utf8" => String::from_utf8_lossy(&inner.raw.body).into_owned(),
            _ => String::from_utf8_lossy(&inner.raw.body).into_owned(),
        };
        Ok(PyString::new(py, &text).into())
    }

    /// File-like read. `size=None` reads all remaining bytes,
    /// matching the Python convention.
    #[pyo3(signature = (size=None))]
    fn read<'py>(&self, py: Python<'py>, size: Option<i64>) -> PyResult<Bound<'py, PyBytes>> {
        let mut inner = self.inner.lock().unwrap();
        let mut out = Vec::new();
        match size {
            None | Some(-1) => {
                inner
                    .body
                    .read_to_end(&mut out)
                    .map_err(PyIOError::new_err_from_io)?;
            }
            Some(n) if n >= 0 => {
                let mut buf = vec![0u8; n as usize];
                let got = inner
                    .body
                    .read(&mut buf)
                    .map_err(PyIOError::new_err_from_io)?;
                buf.truncate(got);
                out = buf;
            }
            Some(_) => {
                // Negative `size` other than -1: Python's file protocol
                // treats these as "read all", so we do too.
                inner
                    .body
                    .read_to_end(&mut out)
                    .map_err(PyIOError::new_err_from_io)?;
            }
        }
        Ok(PyBytes::new(py, &out))
    }

    /// Read up to the next newline (inclusive) or EOF.
    #[pyo3(signature = (_size=-1))]
    fn readline<'py>(&self, py: Python<'py>, _size: i64) -> PyResult<Bound<'py, PyBytes>> {
        let mut inner = self.inner.lock().unwrap();
        let pos = inner.body.position() as usize;
        let total = inner.raw.body.len();
        let end = inner.raw.body[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(total);
        // Copy the bytes out before advancing the cursor so the
        // borrow checker doesn't see overlapping mutable/immutable
        // borrows of `inner`.
        let line: Vec<u8> = inner.raw.body[pos..end].to_vec();
        inner.body.set_position(end as u64);
        Ok(PyBytes::new(py, &line))
    }

    fn readlines<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let mut out: Vec<Bound<'py, PyBytes>> = Vec::new();
        loop {
            let line = self.readline(py, -1)?;
            if line.as_bytes().is_empty() {
                break;
            }
            out.push(line);
        }
        PyList::new(py, out)
    }

    /// No-op; matches the file-like contract. The underlying body
    /// is already fully buffered so there's nothing to release.
    fn close(&self) {}
}

/// Adapter: ureq's `PyIOError::new_err_from_io` doesn't exist; we
/// ship our own trivial conversion so the `read()` / `readline()`
/// paths stay concise.
trait PyIOErrorExt {
    fn new_err_from_io(e: std::io::Error) -> PyErr;
}

impl PyIOErrorExt for PyIOError {
    fn new_err_from_io(e: std::io::Error) -> PyErr {
        PyIOError::new_err(e.to_string())
    }
}

/// Coerce whatever Python hands us into `(name, value)` pairs. We
/// accept either a dict or any iterable of two-tuples, matching the
/// old `request` signature where callers could pass either.
fn extract_headers(py: Python, obj: &Py<PyAny>) -> PyResult<Vec<(String, String)>> {
    let bound = obj.bind(py);
    if let Ok(d) = bound.cast::<pyo3::types::PyDict>() {
        let mut out = Vec::with_capacity(d.len());
        for (k, v) in d.iter() {
            out.push((k.extract::<String>()?, v.extract::<String>()?));
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    for item in bound.try_iter()? {
        let pair = item?;
        let tup = pair.cast::<PyTuple>().map_err(|_| {
            PyValueError::new_err("headers must be a dict or iterable of (name, value) tuples")
        })?;
        if tup.len() != 2 {
            return Err(PyValueError::new_err(
                "header tuples must have exactly two elements",
            ));
        }
        let k: String = tup.get_item(0)?.extract()?;
        let v: String = tup.get_item(1)?.extract()?;
        out.push((k, v));
    }
    Ok(out)
}

/// Accept `bytes`, `bytearray`, `memoryview`, or `str` (encoded as
/// UTF-8) as the request body. Matches how the Python side
/// previously passed data to `connection._send_request`.
fn extract_body(py: Python, obj: &Py<PyAny>) -> PyResult<Vec<u8>> {
    let bound = obj.bind(py);
    if let Ok(b) = bound.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(s) = bound.extract::<String>() {
        return Ok(s.into_bytes());
    }
    // Fallback: coerce via `bytes()` (handles bytearray, memoryview).
    let as_bytes = py
        .get_type::<PyBytes>()
        .call1((bound.clone(),))
        .map_err(|e| PyValueError::new_err(format!("can't interpret body as bytes: {}", e)))?;
    let b = as_bytes
        .cast::<PyBytes>()
        .map_err(|e| PyValueError::new_err(format!("body coercion failed: {}", e)))?;
    Ok(b.as_bytes().to_vec())
}

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<HttpClient>()?;
    m.add_class::<HttpResponse>()?;
    Ok(())
}
