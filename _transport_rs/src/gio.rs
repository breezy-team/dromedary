use crate::{map_transport_err_to_py_err, Transport};
use pyo3::prelude::*;

#[pyclass(extends=Transport, subclass)]
pub(crate) struct GioTransport {}

#[pymethods]
impl GioTransport {
    #[new]
    #[pyo3(signature = (base, _from_transport=None))]
    fn new(base: &str, _from_transport: Option<Py<PyAny>>) -> PyResult<(Self, Transport)> {
        let _ = _from_transport;
        let rust = dromedary::gio::GioTransport::new(base)
            .map_err(|e| map_transport_err_to_py_err(e, None, None))?;
        Ok((GioTransport {}, Transport(Box::new(rust))))
    }

    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<String>,
    ) -> PyResult<Bound<'a, GioTransport>> {
        let super_ = slf.as_ref();
        let inner = super_
            .0
            .clone(offset.as_deref())
            .map_err(|e| map_transport_err_to_py_err(e, None, None))?;
        let init = PyClassInitializer::from(Transport(inner)).add_subclass(GioTransport {});
        Bound::new(py, init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<GioTransport>()?;
    Ok(())
}
