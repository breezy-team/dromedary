//! Python bindings for `dromedary::http::transport::HttpTransport`.
//!
//! Exposes the Rust HTTP transport as
//! `dromedary._transport_rs.http.HttpTransport`, a pyclass that
//! extends `Transport`. The Python `HttpTransport` in
//! `dromedary/http/urllib.py` becomes a thin subclass that adds
//! breezy-side hooks (`_medium`, `_report_activity` override,
//! ssl-config resolution, redirect fix-up) without re-implementing
//! the transport itself.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dromedary::http::client::{
    ActivityCallback, HttpClientConfig, NegotiateProvider, RequestOptions,
};
use dromedary::http::{HttpClient, HttpTransport as RsHttpTransport};
use dromedary::Transport as RsTransport;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::map_transport_err_to_py_err;
use crate::{ConnectedTransport, Transport};

use super::client::{
    client_err_to_py, extract_body, extract_headers, make_activity_callback, HttpResponse,
    PythonCredentialProvider, PythonNegotiateProvider,
};

/// Python-bound Rust HTTP transport.
///
/// Constructor: `HttpTransport(base, ca_certs=None,
/// disable_verification=False, user_agent=None,
/// read_timeout_ms=0)`. Each construction builds a fresh
/// `HttpClient`; call `clone()` to get a sibling transport that
/// shares the underlying agent and auth cache.
///
/// We stash a concrete `Arc<RsHttpTransport>` alongside the base
/// `Transport` so helper methods like `_post` can reach the
/// HttpTransport-specific API without going through a
/// `dyn Transport` downcast.
#[pyclass(extends=ConnectedTransport, subclass, module = "dromedary._transport_rs.http")]
pub(crate) struct HttpTransport {
    // `pub(crate)` rather than private so sibling modules (notably
    // `webdav`) can construct an HttpTransport pyclass parent that
    // points at their own transport's embedded HttpTransport —
    // necessary for `extends=HttpTransport` pyclasses to share the
    // inherited `request` / `_post` / ... methods.
    pub(crate) inner: Arc<RsHttpTransport>,
}

#[pymethods]
impl HttpTransport {
    #[new]
    #[pyo3(signature = (
        base,
        ca_certs=None,
        disable_verification=false,
        user_agent=None,
        read_timeout_ms=0,
    ))]
    fn new(
        base: &str,
        ca_certs: Option<PathBuf>,
        disable_verification: bool,
        user_agent: Option<String>,
        read_timeout_ms: i64,
    ) -> PyResult<PyClassInitializer<Self>> {
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
        let client = HttpClient::with_providers(
            cfg,
            Box::new(PythonCredentialProvider),
            Box::new(PythonNegotiateProvider) as Box<dyn NegotiateProvider>,
        )
        .map_err(|e| {
            map_transport_err_to_py_err(
                dromedary::Error::Io(std::io::Error::other(format!("{}", e))),
                None,
                Some(base),
            )
        })?;
        let rust = RsHttpTransport::new(base, Arc::new(client))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(base)))?;
        let inner = Arc::new(rust);
        Ok(http_transport_initializer(inner))
    }

    /// Clone this transport at an optional offset, sharing the
    /// underlying HttpClient.
    ///
    /// Returns an instance of the base Rust ``HttpTransport``.
    /// Python subclasses that want ``type(self)``-preserving cloning
    /// should override ``clone`` and use
    /// ``_rust_replace_inner_from`` to graft the shared state onto
    /// a freshly-constructed subclass instance.
    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<&str>,
    ) -> PyResult<Bound<'a, HttpTransport>> {
        let cloned = slf
            .inner
            .clone_concrete(offset)
            .map_err(|e| map_transport_err_to_py_err(e, None, offset))?;
        Bound::new(py, http_transport_initializer(Arc::new(cloned)))
    }

    /// Replace this transport's inner state with the state of
    /// ``source``, effectively turning ``self`` into a clone of
    /// ``source`` at the current base URL. Used by the Python
    /// subclass override of ``clone`` to achieve shared-state
    /// cloning while preserving the subclass identity: the subclass
    /// builds a fresh instance with its desired base, then calls
    /// this method to inherit the source transport's HttpClient,
    /// auth cache, and range-hint state.
    ///
    /// After calling this, the two transports share the same
    /// underlying Rust state exactly as if the receiver had been
    /// produced by ``source.clone(offset)``.
    fn _rust_replace_inner_from(
        mut slf: PyRefMut<Self>,
        source: PyRef<Self>,
        offset: Option<&str>,
    ) -> PyResult<()> {
        let cloned = source
            .inner
            .clone_concrete(offset)
            .map_err(|e| map_transport_err_to_py_err(e, None, offset))?;
        let new_inner = Arc::new(cloned);
        // Replace the base Transport(Box<dyn Transport>) too so
        // calls routed through the dyn vtable see the cloned state.
        let base_box: Box<dyn dromedary::Transport> = Box::new(Clone::clone(&*new_inner));
        // Walk up through the ConnectedTransport layer to reach the
        // Transport pyclass where the dyn handle actually lives.
        let connected = slf.as_super();
        connected.as_super().0 = base_box;
        slf.inner = new_inner;
        Ok(())
    }

    /// Current range hint as `"multi"`, `"single"`, or `None`. Part
    /// of the public-ish transport interface so the breezy test
    /// suite can observe the client's fallback state.
    #[getter]
    fn _range_hint(&self) -> Option<&'static str> {
        self.inner.range_hint_str()
    }

    /// Step the range hint down one rung. Returns True if we
    /// stepped, False if we were already at the floor.
    fn _degrade_range_hint(&self) -> bool {
        self.inner.degrade_range_hint()
    }

    /// Unqualified HTTP scheme (`"http"` or `"https"`) — strips any
    /// `+impl` qualifier present in the base URL. Exposed for
    /// breezy's test harness which reads it directly.
    #[getter]
    fn _unqualified_scheme(&self) -> PyResult<String> {
        // Base URL's scheme is always the unqualified form after
        // normalise_http_url(); use that rather than re-parsing.
        let url = RsTransport::base(&*self.inner);
        Ok(url.scheme().to_string())
    }

    /// Build the remote URL for `relpath`: absolute URL with any
    /// embedded user/password stripped and the scheme reduced to
    /// its unqualified form. Auth goes through headers, not URL.
    fn _remote_path(&self, relpath: &str) -> PyResult<String> {
        let url = self
            .inner
            .remote_url(relpath)
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        Ok(url.to_string())
    }

    /// Drop any cached connection state. A no-op on the Rust client
    /// (ureq's pool is per-agent and released lazily), but kept for
    /// API compatibility with the urllib handler stack.
    fn disconnect(&self) {}

    /// Issue an HTTP request through the transport's shared client.
    ///
    /// Returns the same `HttpResponse` pyclass the standalone
    /// `HttpClient.request` hands back, so existing callers that
    /// previously did `self._client.request(...)` don't need to
    /// change response-handling code.
    #[pyo3(signature = (
        method,
        url,
        headers=None,
        body=None,
        follow_redirects=false,
        report_activity=None,
    ))]
    fn request(
        &self,
        py: Python,
        method: &str,
        url: &str,
        headers: Option<Py<PyAny>>,
        body: Option<Py<PyAny>>,
        follow_redirects: bool,
        report_activity: Option<Py<PyAny>>,
    ) -> PyResult<HttpResponse> {
        let header_pairs = match headers {
            Some(h) => extract_headers(py, &h)?,
            None => Vec::new(),
        };
        let body_bytes = match body {
            Some(b) => extract_body(py, &b)?,
            None => Vec::new(),
        };
        let opts = RequestOptions {
            follow_redirects,
            ..RequestOptions::default()
        };
        let activity: Option<ActivityCallback> = report_activity.map(make_activity_callback);
        let resp = py.detach(|| {
            self.inner.client().request_with(
                method,
                url,
                &header_pairs,
                &body_bytes,
                &opts,
                activity.as_ref(),
            )
        });
        let resp = resp.map_err(client_err_to_py)?;
        Ok(HttpResponse::new(resp))
    }

    /// HEAD `relpath`. Returns the response for 200 / 404 and
    /// raises for everything else, matching the Python `_head`.
    fn _head(&self, py: Python, relpath: &str) -> PyResult<HttpResponse> {
        let resp = py
            .detach(|| self.inner.head(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        Ok(HttpResponse::new(resp))
    }

    /// OPTIONS `relpath`. Returns the response headers as a list of
    /// `(name, value)` tuples on 2xx; raises `NoSuchFile` on 404 or
    /// `InvalidHttpResponse` on 403/405.
    fn _options(&self, py: Python, relpath: &str) -> PyResult<Vec<(String, String)>> {
        py.detach(|| self.inner.options(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    /// POST `body` to `relpath` and return `(status, response_body)`.
    /// Mirrors the Python `HttpTransport._post` used by breezy's
    /// smart HTTP medium.
    fn _post<'py>(
        &self,
        py: Python<'py>,
        relpath: &str,
        body: &[u8],
    ) -> PyResult<(u16, Bound<'py, PyBytes>)> {
        // Release the GIL around the blocking HTTP exchange: the
        // in-process breezy test HTTP server runs in a Python thread
        // and can't accept connections while we hold the GIL, which
        // otherwise deadlocks POST-over-loopback tests.
        let (status, buf) = py
            .detach(|| -> Result<(u16, Vec<u8>), dromedary::Error> {
                let (status, mut rf) = self.inner.post(relpath, body)?;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut rf, &mut buf).map_err(dromedary::Error::Io)?;
                Ok((status, buf))
            })
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        Ok((status, PyBytes::new(py, &buf)))
    }
}

/// Build the three-layer `Transport → ConnectedTransport →
/// HttpTransport` initializer PyO3 needs for pyclass construction.
///
/// `pub(crate)` so `webdav::transport` can extend the chain with a
/// fourth `add_subclass(HttpDavTransport {...})` layer, reusing the
/// HttpTransport parent's `inner` pointer to share the HTTP client
/// and range-hint state with the DAV transport above it.
pub(crate) fn http_transport_initializer(
    inner: Arc<RsHttpTransport>,
) -> PyClassInitializer<HttpTransport> {
    let base_box: Box<dyn dromedary::Transport> = Box::new(Clone::clone(&*inner));
    PyClassInitializer::from(Transport(base_box))
        .add_subclass(ConnectedTransport)
        .add_subclass(HttpTransport { inner })
}

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<HttpTransport>()?;
    Ok(())
}
