//! Python bindings for `dromedary::http::response`.
//!
//! Exposes `ResponseFile`, `RangeFile`, and `handle_response` so that
//! the Python side of `dromedary.http` can drop its hand-rolled
//! implementation and delegate here.
//!
//! The two classes each hold their Rust counterpart. The underlying
//! input file is an arbitrary Python file-like: we don't require
//! `pyo3-filelike` because the trait we need (`read(n)` and
//! `readline()` only) is simpler than the full file protocol.

use std::io;

use pyo3::exceptions::PyTypeError;
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use dromedary::http::response::{
    handle_response as rs_handle_response, InFile, RangeFile as RsRangeFile, ResponseError,
    ResponseFile as RsResponseFile, ResponseKind,
};

import_exception!(dromedary.errors, InvalidHttpResponse);
import_exception!(dromedary.errors, InvalidHttpRange);
import_exception!(dromedary.errors, HttpBoundaryMissing);
import_exception!(dromedary.errors, ShortReadvError);
import_exception!(dromedary.errors, InvalidRange);
import_exception!(dromedary.errors, UnexpectedHttpStatus);

/// Adapter: a Python file-like object accessed via Python attribute
/// calls. We do **not** wrap with `pyo3_filelike::PyBinaryFile`
/// because we need the file-like's own `readline()` semantics to
/// match what socket / BytesIO objects already provide — stdlib
/// `BufReader::read_until` splits differently on non-terminated
/// last lines.
struct PyInFile {
    obj: Py<PyAny>,
}

impl PyInFile {
    fn new(obj: Py<PyAny>) -> Self {
        Self { obj }
    }
}

fn py_err_to_io(e: PyErr) -> io::Error {
    io::Error::other(e.to_string())
}

fn pyany_to_bytes(py: Python, any: &Bound<PyAny>) -> io::Result<Vec<u8>> {
    if let Ok(b) = any.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    // Some file-likes (e.g. text-mode objects, or `StringIO`) return
    // `str` instead of `bytes`. Convert with UTF-8 encoding; matches
    // the Python-side behaviour where a caller using a StringIO for
    // tests would get the same bytes out.
    if let Ok(s) = any.extract::<String>() {
        return Ok(s.into_bytes());
    }
    // As a last resort, anything buffer-protocol-compatible (memoryview,
    // bytearray) can go through `bytes()`.
    let as_bytes = py
        .get_type::<PyBytes>()
        .call1((any,))
        .map_err(py_err_to_io)?;
    let b = as_bytes
        .cast::<PyBytes>()
        .map_err(|e| io::Error::other(format!("file-like returned non-bytes: {}", e)))?;
    Ok(b.as_bytes().to_vec())
}

impl InFile for PyInFile {
    fn read(&mut self, n: usize) -> io::Result<Vec<u8>> {
        Python::attach(|py| {
            let r = self
                .obj
                .bind(py)
                .call_method1("read", (n,))
                .map_err(py_err_to_io)?;
            pyany_to_bytes(py, &r)
        })
    }

    fn readline(&mut self) -> io::Result<Vec<u8>> {
        Python::attach(|py| {
            let r = self
                .obj
                .bind(py)
                .call_method0("readline")
                .map_err(py_err_to_io)?;
            pyany_to_bytes(py, &r)
        })
    }
}

fn response_err_to_py(err: ResponseError) -> PyErr {
    match err {
        ResponseError::InvalidResponse { path, msg } => InvalidHttpResponse::new_err((path, msg)),
        ResponseError::InvalidHttpRange { path, range, msg } => {
            InvalidHttpRange::new_err((path, range, msg))
        }
        ResponseError::BoundaryMissing { path, boundary } => {
            // The Python side passes the raw boundary bytes as the
            // `msg` argument; mirror that.
            Python::attach(|py| {
                HttpBoundaryMissing::new_err((path, PyBytes::new(py, &boundary).unbind()))
            })
        }
        ResponseError::ShortReadv {
            path,
            offset,
            length,
            actual,
        } => ShortReadvError::new_err((path, offset, length, actual)),
        ResponseError::InvalidRange { path, offset, msg } => {
            InvalidRange::new_err((path, offset, msg))
        }
        ResponseError::UnexpectedStatus { path, code } => {
            UnexpectedHttpStatus::new_err((path, code))
        }
        ResponseError::Io(e) => pyo3::exceptions::PyIOError::new_err(e.to_string()),
        ResponseError::InvalidWhence(w) => {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid value {} for whence.", w))
        }
        ResponseError::BackwardSeek { path, pos, offset } => {
            pyo3::exceptions::PyAssertionError::new_err(format!(
                "{}: can't seek backwards, pos: {}, offset: {}",
                path, pos, offset
            ))
        }
    }
}

/// Python binding: `dromedary._transport_rs.http.ResponseFile`.
///
/// Constructor: `ResponseFile(path, infile)`. The `infile` must
/// expose at least `read(n)` and `readline()` — standard file-like
/// duck typing, the same as what the Python original needed.
#[pyclass(module = "dromedary._transport_rs.http", subclass)]
pub(crate) struct ResponseFile {
    inner: RsResponseFile<PyInFile>,
}

#[pymethods]
impl ResponseFile {
    #[new]
    fn new(path: String, infile: Py<PyAny>) -> Self {
        Self {
            inner: RsResponseFile::new(path, PyInFile::new(infile)),
        }
    }

    /// No-op; matches the Python API for file-like compatibility.
    fn close(&self) {}

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<Py<PyAny>>,
        _exc_val: Option<Py<PyAny>>,
        _exc_tb: Option<Py<PyAny>>,
    ) -> bool {
        false
    }

    /// Read up to `size` bytes; `None` (the default) means "read to
    /// EOF". `-1` is accepted as an alias for `None`, matching the
    /// Python convention.
    #[pyo3(signature = (size=None))]
    fn read<'py>(&mut self, py: Python<'py>, size: Option<i64>) -> PyResult<Bound<'py, PyBytes>> {
        let sz = match size {
            None | Some(-1) => None,
            Some(n) if n < 0 => None,
            Some(n) => Some(n as usize),
        };
        let data = self.inner.read(sz).map_err(response_err_to_py)?;
        Ok(PyBytes::new(py, &data))
    }

    fn readline<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.readline().map_err(response_err_to_py)?;
        Ok(PyBytes::new(py, &data))
    }

    /// Read all remaining lines. The optional `size` argument is
    /// accepted for Python-file-like compatibility but ignored,
    /// matching the Python version.
    #[pyo3(signature = (_size=None))]
    fn readlines<'py>(
        &mut self,
        py: Python<'py>,
        _size: Option<i64>,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let lines = self.inner.readlines().map_err(response_err_to_py)?;
        Ok(lines.into_iter().map(|l| PyBytes::new(py, &l)).collect())
    }

    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let line = self.inner.readline().map_err(response_err_to_py)?;
        if line.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PyBytes::new(py, &line)))
        }
    }

    fn tell(&self) -> u64 {
        self.inner.tell()
    }

    #[pyo3(signature = (offset, whence=0))]
    fn seek(&mut self, offset: i64, whence: u32) -> PyResult<()> {
        self.inner.seek(offset, whence).map_err(response_err_to_py)
    }
}

/// Python binding: `dromedary._transport_rs.http.RangeFile`.
///
/// Not a subclass of `ResponseFile` in the Rust bindings — nothing
/// in the Python code base does `isinstance(rf, ResponseFile)`, so
/// keeping them independent avoids the PyO3 subclass boilerplate.
#[pyclass(module = "dromedary._transport_rs.http")]
pub(crate) struct RangeFile {
    inner: RsRangeFile<PyInFile>,
}

#[pymethods]
impl RangeFile {
    #[new]
    fn new(path: String, infile: Py<PyAny>) -> Self {
        Self {
            inner: RsRangeFile::new(path, PyInFile::new(infile)),
        }
    }

    fn close(&self) {}

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<Py<PyAny>>,
        _exc_val: Option<Py<PyAny>>,
        _exc_tb: Option<Py<PyAny>>,
    ) -> bool {
        false
    }

    /// Read up to `size` bytes from the current range. `-1` means
    /// "read to end of range" (matches the Python default).
    #[pyo3(signature = (size=-1))]
    fn read<'py>(&mut self, py: Python<'py>, size: i64) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.read(size).map_err(response_err_to_py)?;
        Ok(PyBytes::new(py, &data))
    }

    fn tell(&self) -> u64 {
        self.inner.tell()
    }

    #[pyo3(signature = (offset, whence=0))]
    fn seek(&mut self, offset: i64, whence: u32) -> PyResult<()> {
        self.inner.seek(offset, whence).map_err(response_err_to_py)
    }

    fn set_range(&mut self, start: u64, size: i64) {
        let size = if size < 0 { None } else { Some(size as u64) };
        self.inner.set_range(start, size);
    }

    /// Multipart boundary; passed as bytes by the caller. A non-bytes
    /// argument raises `TypeError` to match the Python
    /// `isinstance(boundary, bytes)` check.
    fn set_boundary(&mut self, py: Python, boundary: Py<PyAny>) -> PyResult<()> {
        let bound = boundary.bind(py);
        let bytes = bound
            .cast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("boundary must be bytes"))?;
        self.inner
            .set_boundary(bytes.as_bytes().to_vec())
            .map_err(response_err_to_py)
    }

    fn read_boundary(&mut self) -> PyResult<()> {
        self.inner.read_boundary().map_err(response_err_to_py)
    }

    fn read_range_definition(&mut self) -> PyResult<()> {
        self.inner
            .read_range_definition()
            .map_err(response_err_to_py)
    }

    fn set_range_from_header(&mut self, content_range: &str) -> PyResult<()> {
        self.inner
            .set_range_from_header(content_range)
            .map_err(response_err_to_py)
    }

    // Python-compatibility properties — the original pure-Python
    // implementation exposed `_start`, `_size`, `_pos`, and
    // `_boundary` as ordinary instance attributes. Several tests
    // (and occasionally user code that bypassed the normal seek
    // machinery) poke them directly, so we mirror them here. The
    // setter methods use the `set_<name>` naming that PyO3 expects
    // for `#[setter]` on properties called `_start` / `_size` /
    // `_pos`; that's what puts the underscore in the middle of the
    // Rust name.

    #[getter(_start)]
    fn py_start(&self) -> u64 {
        self.inner.rs_start()
    }

    #[setter(_start)]
    fn py_set_start(&mut self, value: u64) {
        self.inner.rs_set_start(value);
    }

    /// `-1` means "size unknown" (matches the Python convention).
    #[getter(_size)]
    fn py_size(&self) -> i64 {
        match self.inner.rs_size() {
            Some(n) => n as i64,
            None => -1,
        }
    }

    #[setter(_size)]
    fn py_set_size(&mut self, value: i64) {
        let v = if value < 0 { None } else { Some(value as u64) };
        self.inner.rs_set_size(v);
    }

    #[getter(_pos)]
    fn py_pos(&self) -> u64 {
        self.inner.tell()
    }

    #[setter(_pos)]
    fn py_set_pos(&mut self, value: u64) {
        self.inner.rs_set_pos(value);
    }

    #[getter(_boundary)]
    fn py_boundary<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.rs_boundary().map(|b| PyBytes::new(py, b))
    }

    #[getter(_discarded_buf_size)]
    fn py_discarded_buf_size(&self) -> usize {
        self.inner.rs_discarded_buf_size()
    }

    #[setter(_discarded_buf_size)]
    fn py_set_discarded_buf_size(&mut self, value: usize) {
        self.inner.rs_set_discarded_buf_size(value);
    }
}

/// Factory mirroring `dromedary.http.response.handle_response`.
///
/// Instead of taking a `getheader` callback like the Python version,
/// we accept the headers dict up front and look them up case-
/// insensitively. `getheader` takes `(name, default)` in Python; we
/// unify by requiring a plain `dict[str, str]` from the caller and
/// handling the default here.
#[pyfunction]
pub(crate) fn handle_response(
    py: Python,
    url: String,
    code: u16,
    getheader: Py<PyAny>,
    data: Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    // Bridge the Python getheader(name, default=None) callable to a
    // Rust closure returning Option<String>.
    let get = |name: &str| -> Option<String> {
        Python::attach(|py| {
            let res = getheader.bind(py).call1((name, py.None())).ok()?;
            if res.is_none() {
                None
            } else {
                res.extract::<String>().ok()
            }
        })
    };
    let kind =
        rs_handle_response(url, code, &get, PyInFile::new(data)).map_err(response_err_to_py)?;
    match kind {
        ResponseKind::Plain(inner) => {
            let cls = Py::new(py, ResponseFile { inner })?;
            Ok(cls.into_any())
        }
        ResponseKind::Range(inner) => {
            let cls = Py::new(py, RangeFile { inner })?;
            Ok(cls.into_any())
        }
    }
}

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<ResponseFile>()?;
    m.add_class::<RangeFile>()?;
    m.add_function(wrap_pyfunction!(handle_response, m)?)?;
    Ok(())
}
