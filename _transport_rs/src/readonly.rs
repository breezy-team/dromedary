use crate::{Transport, TransportDecorator};
use dromedary::pyo3::PyTransport;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

const PREFIX: &str = "readonly+";

fn resolve_inner(py: Python, url: &str, decorated: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
    if let Some(d) = decorated {
        return Ok(d);
    }
    if !url.starts_with(PREFIX) {
        return Err(PyValueError::new_err(format!(
            "url {:?} doesn't start with decorator prefix {:?}",
            url, PREFIX
        )));
    }
    let rest = &url[PREFIX.len()..];
    let dromedary = py.import("dromedary")?;
    let urlutils = py.import("dromedary.urlutils")?;
    let is_url: bool = urlutils.call_method1("is_url", (rest,))?.extract()?;
    let func = if is_url {
        dromedary.getattr("get_transport_from_url")?
    } else {
        dromedary.getattr("get_transport_from_path")?
    };
    Ok(func.call1((rest,))?.unbind())
}

fn wrap_inner(decorated: &Py<PyAny>, py: Python) -> Transport {
    let py_inner: Box<dyn dromedary::Transport + Send + Sync> =
        Box::new(PyTransport::from(decorated.clone_ref(py)));
    Transport(Box::new(dromedary::readonly::ReadonlyTransport::new(
        py_inner,
    )))
}

#[pyclass(extends=TransportDecorator, subclass)]
pub(crate) struct ReadonlyTransportDecorator;

#[pymethods]
impl ReadonlyTransportDecorator {
    #[new]
    #[pyo3(signature = (url, _decorated=None, _from_transport=None))]
    fn new(
        py: Python,
        url: &str,
        _decorated: Option<Py<PyAny>>,
        _from_transport: Option<Py<PyAny>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        let _ = _from_transport;
        let decorated = resolve_inner(py, url, _decorated)?;
        let wrapped = wrap_inner(&decorated, py);
        Ok(PyClassInitializer::from(wrapped)
            .add_subclass(TransportDecorator {
                decorated,
                prefix: PREFIX,
            })
            .add_subclass(ReadonlyTransportDecorator))
    }

    #[classmethod]
    fn _get_url_prefix(_cls: &Bound<'_, pyo3::types::PyType>) -> &'static str {
        PREFIX
    }

    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'a, ReadonlyTransportDecorator>> {
        let decorator: &TransportDecorator = slf.as_super();
        let decorated = decorator.decorated.clone_ref(py);
        let decorated_clone = match offset {
            Some(o) => decorated.call_method1(py, "clone", (o,))?,
            None => decorated.call_method0(py, "clone")?,
        };
        let wrapped = wrap_inner(&decorated_clone, py);
        let init = PyClassInitializer::from(wrapped)
            .add_subclass(TransportDecorator {
                decorated: decorated_clone,
                prefix: PREFIX,
            })
            .add_subclass(ReadonlyTransportDecorator);
        Bound::new(py, init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<ReadonlyTransportDecorator>()?;
    Ok(())
}
