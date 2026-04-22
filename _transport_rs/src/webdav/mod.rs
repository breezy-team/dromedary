//! Python bindings for `dromedary::webdav`.
//!
//! Feature-gated behind `webdav`. Exposes
//! `dromedary._transport_rs.webdav.HttpDavTransport` as a pyclass
//! that extends `_transport_rs.http.HttpTransport`, so the Python
//! `dromedary.webdav.webdav.HttpDavTransport` becomes a thin
//! subclass just like the HTTP transport did in Stage 10.

pub mod transport;

use pyo3::prelude::*;

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<transport::HttpDavTransport>()?;
    Ok(())
}
