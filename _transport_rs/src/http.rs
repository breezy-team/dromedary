//! Python bindings for the HTTP helper functions in `dromedary::http`.

use pyo3::prelude::*;
use pyo3::types::PyList;

#[pyfunction]
#[pyo3(signature = (use_cache=true))]
fn get_ca_path(use_cache: bool) -> String {
    dromedary::http::get_ca_path(use_cache)
}

#[pyfunction]
fn clear_ca_path_cache() {
    dromedary::http::clear_ca_path_cache();
}

#[pyfunction]
fn default_ca_certs() -> String {
    dromedary::http::default_ca_certs()
}

pub(crate) fn register(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_ca_path, m)?)?;
    m.add_function(wrap_pyfunction!(clear_ca_path_cache, m)?)?;
    m.add_function(wrap_pyfunction!(default_ca_certs, m)?)?;

    let locations = PyList::new(py, dromedary::http::SSL_CA_CERTS_KNOWN_LOCATIONS)?;
    m.add("SSL_CA_CERTS_KNOWN_LOCATIONS", locations)?;

    Ok(())
}
