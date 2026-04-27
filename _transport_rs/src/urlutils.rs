use pyo3::exceptions::PyTypeError;
use pyo3::exceptions::PyValueError;
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use std::collections::HashMap;
use std::path::PathBuf;

import_exception!(dromedary.urlutils, InvalidURLJoin);
import_exception!(dromedary.urlutils, InvalidURL);
import_exception!(dromedary.errors, PathNotChild);

#[pyfunction]
fn is_url(url: &str) -> bool {
    dromedary::urlutils::is_url(url)
}

/// On Windows, `file://` URLs without a drive letter are invalid. The
/// `split`/`basename`/`dirname`/`strip_trailing_slash` helpers historically
/// raised `InvalidURL` for such URLs (matching breezy's behaviour). The
/// underlying Rust `split` is platform-agnostic and just splits at the last
/// path separator, so do the validation here in the Python boundary.
#[cfg(target_os = "windows")]
fn validate_win32_file_url(url: &str) -> PyResult<()> {
    if !is_win32_drive_letter_url(url)
        && url.starts_with("file:///")
        && url.len() > "file:///".len()
    {
        return Err(InvalidURL::new_err(("Invalid Win32 local URL", url)));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[inline]
fn validate_win32_file_url(_url: &str) -> PyResult<()> {
    Ok(())
}

/// Whether `url` is a `file:///<letter>:|...` or `file:///<letter>|...` URL.
#[cfg(target_os = "windows")]
fn is_win32_drive_letter_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("file:///") else {
        return false;
    };
    let mut chars = rest.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.next(), Some(':') | Some('|'))
}

#[pyfunction]
#[pyo3(signature = (url, exclude_trailing_slash = true))]
fn split(url: &str, exclude_trailing_slash: Option<bool>) -> PyResult<(String, String)> {
    validate_win32_file_url(url)?;
    Ok(split_impl(url, exclude_trailing_slash.unwrap_or(true)))
}

#[cfg(not(target_os = "windows"))]
#[inline]
fn split_impl(url: &str, exclude_trailing_slash: bool) -> (String, String) {
    dromedary::urlutils::split(url, exclude_trailing_slash)
}

/// On Windows, drive-letter local URLs split as `file:///C:` + `/path`. The
/// generic split treats the URL as `file://` + `/C:/path` and produces the
/// wrong head/tail; mirror breezy's `_win32_split` here.
#[cfg(target_os = "windows")]
fn split_impl(url: &str, exclude_trailing_slash: bool) -> (String, String) {
    if is_win32_drive_letter_url(url) {
        let url_base = "file://";
        // SAFETY: validated above that the URL has shape `file:///<L><:|>...`
        let path = &url["file://".len()..]; // starts with `/<letter><:|>...`
        if let Ok((url_base, path)) =
            dromedary::urlutils::win32::extract_drive_letter(url_base, path)
        {
            // `path` is now the part after the drive (e.g. "/foo/bar").
            return split_after_drive(&url_base, &path, exclude_trailing_slash);
        }
    }
    dromedary::urlutils::split(url, exclude_trailing_slash)
}

#[cfg(target_os = "windows")]
fn split_after_drive(url_base: &str, path: &str, exclude_trailing_slash: bool) -> (String, String) {
    let mut p = path;
    if exclude_trailing_slash && p.len() > 1 && p.ends_with('/') {
        p = &p[..p.len() - 1];
    }
    match p.rsplit_once('/') {
        None => (url_base.to_string(), p.to_string()),
        Some((head, tail)) => {
            let head = if head.is_empty() { "/" } else { head };
            (url_base.to_string() + head, tail.to_string())
        }
    }
}

#[pyfunction]
fn _find_scheme_and_separator(url: &str) -> (Option<usize>, Option<usize>) {
    dromedary::urlutils::find_scheme_and_separator(url)
}

#[pyfunction]
fn strip_trailing_slash(url: &str) -> PyResult<String> {
    validate_win32_file_url(url)?;
    #[cfg(target_os = "windows")]
    {
        if url.ends_with('/') && is_win32_drive_letter_url(url) {
            // Drive-letter local URL: preserve `file:///C:/` as-is and
            // strip exactly one trailing slash from anything longer.
            return Ok(dromedary::urlutils::win32::strip_local_trailing_slash(url));
        }
    }
    Ok(dromedary::urlutils::strip_trailing_slash(url).to_string())
}

#[pyfunction]
#[pyo3(signature = (url, exclude_trailing_slash = true))]
fn dirname(url: &str, exclude_trailing_slash: Option<bool>) -> PyResult<String> {
    validate_win32_file_url(url)?;
    Ok(split_impl(url, exclude_trailing_slash.unwrap_or(true)).0)
}

#[pyfunction]
#[pyo3(signature = (url, exclude_trailing_slash = true))]
fn basename(url: &str, exclude_trailing_slash: Option<bool>) -> PyResult<String> {
    validate_win32_file_url(url)?;
    Ok(split_impl(url, exclude_trailing_slash.unwrap_or(true)).1)
}

fn map_urlutils_error_to_pyerr(e: dromedary::urlutils::Error) -> PyErr {
    match e {
        dromedary::urlutils::Error::AboveRoot(base, path) => {
            InvalidURLJoin::new_err(("Above root", base, path))
        }
        dromedary::urlutils::Error::SubsegmentMissesEquals(segment) => {
            InvalidURL::new_err(("Subsegment misses equals", segment))
        }
        dromedary::urlutils::Error::UnsafeCharacters(c) => {
            InvalidURL::new_err(("Unsafe characters", c))
        }
        dromedary::urlutils::Error::IoError(err) => err.into(),
        dromedary::urlutils::Error::SegmentParameterKeyContainsEquals(url, segment) => {
            InvalidURLJoin::new_err(("Segment parameter contains equals (=)", url, segment))
        }
        dromedary::urlutils::Error::SegmentParameterContainsComma(url, segments) => {
            InvalidURLJoin::new_err(("Segment parameter contains comma (,)", url, segments))
        }
        dromedary::urlutils::Error::NotLocalUrl(url) => {
            InvalidURL::new_err(("Not a local url", url))
        }
        dromedary::urlutils::Error::UrlNotAscii(url) => InvalidURL::new_err(("URL not ascii", url)),
        dromedary::urlutils::Error::InvalidUNCUrl(url) => {
            InvalidURL::new_err(("Invalid UNC URL", url))
        }
        dromedary::urlutils::Error::InvalidWin32LocalUrl(url) => {
            InvalidURL::new_err(("Invalid Win32 local URL", url))
        }
        dromedary::urlutils::Error::InvalidWin32Path(path) => {
            InvalidURL::new_err(("Invalid Win32 path", path))
        }
        dromedary::urlutils::Error::PathNotChild(path, start) => {
            PathNotChild::new_err((path, start))
        }
        dromedary::urlutils::Error::UrlTooShort(url) => {
            PyValueError::new_err(("URL too short", url))
        }
        dromedary::urlutils::Error::InvalidUrlPort(url, port_str) => {
            InvalidURL::new_err((format!("invalid port number {port_str} in url:\n{url}"),))
        }
    }
}

#[pyfunction(signature = (url, *args))]
fn joinpath(url: &str, args: &Bound<PyTuple>) -> PyResult<String> {
    let mut path = Vec::new();
    for arg in args.iter() {
        if let Ok(arg) = arg.extract::<String>() {
            path.push(arg);
        } else {
            return Err(PyTypeError::new_err(
                "path must be a string or a list of strings",
            ));
        }
    }
    let path_ref = path.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    dromedary::urlutils::joinpath(url, path_ref.as_slice()).map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction(signature = (url, *args))]
fn join(url: &str, args: &Bound<PyTuple>) -> PyResult<String> {
    let mut path = Vec::new();
    for arg in args.iter() {
        if let Ok(arg) = arg.extract::<String>() {
            path.push(arg);
        } else {
            return Err(PyTypeError::new_err(
                "path must be a string or a list of strings",
            ));
        }
    }
    let path_ref = path.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    dromedary::urlutils::join(url, path_ref.as_slice()).map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn split_segment_parameters(url: &str) -> PyResult<(&str, HashMap<&str, &str>)> {
    dromedary::urlutils::split_segment_parameters(url).map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn split_segment_parameters_raw(url: &str) -> (&str, Vec<&str>) {
    dromedary::urlutils::split_segment_parameters_raw(url)
}

#[pyfunction]
fn strip_segment_parameters(url: &str) -> &str {
    dromedary::urlutils::strip_segment_parameters(url)
}

#[pyfunction]
fn relative_url(base: &str, url: &str) -> String {
    dromedary::urlutils::relative_url(base, url)
}

#[pyfunction]
fn combine_paths(base_path: &str, relpath: &str) -> String {
    dromedary::urlutils::combine_paths(base_path, relpath)
}

#[pyfunction]
#[pyo3(signature = (text, safe = None))]
fn escape(py: Python, text: Py<PyAny>, safe: Option<&str>) -> PyResult<String> {
    if let Ok(text) = text.extract::<String>(py) {
        Ok(dromedary::urlutils::escape(text.as_bytes(), safe))
    } else if let Ok(text) = text.extract::<Vec<u8>>(py) {
        Ok(dromedary::urlutils::escape(text.as_slice(), safe))
    } else {
        Err(PyTypeError::new_err("text must be a string or bytes"))
    }
}

#[pyfunction]
fn normalize_url(url: &str) -> PyResult<String> {
    dromedary::urlutils::normalize_url(url).map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn local_path_to_url(path: PathBuf) -> PyResult<String> {
    dromedary::urlutils::local_path_to_url(path.as_path()).map_err(|e| e.into())
}

#[pyfunction(name = "local_path_to_url")]
fn win32_local_path_to_url(path: PathBuf) -> PyResult<String> {
    dromedary::urlutils::win32::local_path_to_url(path).map_err(|e| e.into())
}

#[pyfunction(name = "local_path_to_url")]
fn posix_local_path_to_url(path: &str) -> PyResult<String> {
    dromedary::urlutils::posix::local_path_to_url(path).map_err(|e| e.into())
}

#[pyfunction(signature = (url, *args))]
fn join_segment_parameters_raw(url: &str, args: &Bound<PyTuple>) -> PyResult<String> {
    let mut path = Vec::new();
    for arg in args.iter() {
        if let Ok(arg) = arg.extract::<String>() {
            path.push(arg);
        } else {
            return Err(PyTypeError::new_err(
                "path must be a string or a list of strings",
            ));
        }
    }
    let path_ref = path.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    dromedary::urlutils::join_segment_parameters_raw(url, path_ref.as_slice())
        .map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn join_segment_parameters(url: &str, parameters: HashMap<String, String>) -> PyResult<String> {
    let parameters = parameters
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    dromedary::urlutils::join_segment_parameters(url, &parameters)
        .map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn local_path_from_url(url: &str) -> PyResult<String> {
    let path =
        dromedary::urlutils::local_path_from_url(url).map_err(map_urlutils_error_to_pyerr)?;

    match path.to_str() {
        Some(path) => Ok(path.to_string()),
        None => Err(PyValueError::new_err("Path is not valid UTF-8")),
    }
}

#[pyfunction(name = "local_path_from_url")]
fn win32_local_path_from_url(url: &str) -> PyResult<String> {
    let path = dromedary::urlutils::win32::local_path_from_url(url)
        .map_err(map_urlutils_error_to_pyerr)?;

    match path.to_str() {
        Some(path) => Ok(path.to_string()),
        None => Err(PyValueError::new_err("Path is not valid UTF-8")),
    }
}

/// On win32 the drive letter needs to be added to the url base.
#[pyfunction(name = "extract_drive_letter")]
fn win32_extract_drive_letter(url_base: &str, path: &str) -> PyResult<(String, String)> {
    dromedary::urlutils::win32::extract_drive_letter(url_base, path)
        .map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction(name = "strip_local_trailing_slash")]
fn win32_strip_local_trailing_slash(url: &str) -> String {
    dromedary::urlutils::win32::strip_local_trailing_slash(url)
}

#[pyfunction(name = "local_path_from_url")]
fn posix_local_path_from_url(url: &str) -> PyResult<String> {
    let path = dromedary::urlutils::posix::local_path_from_url(url)
        .map_err(map_urlutils_error_to_pyerr)?;

    match path.to_str() {
        Some(path) => Ok(path.to_string()),
        None => Err(PyValueError::new_err("Path is not valid UTF-8")),
    }
}

#[pyfunction]
fn unescape(text: &str) -> PyResult<String> {
    dromedary::urlutils::unescape(text).map_err(map_urlutils_error_to_pyerr)
}

#[pyfunction]
fn derive_to_location(base: &str) -> String {
    dromedary::urlutils::derive_to_location(base)
}

#[pyfunction]
fn file_relpath(base: &str, path: &str) -> PyResult<String> {
    dromedary::urlutils::file_relpath(base, path).map_err(map_urlutils_error_to_pyerr)
}

/// Permissive percent-decode mirroring Python's urllib.parse.unquote:
/// non-ASCII or undecodable input is returned unchanged.
fn unquote_lossy(s: &str) -> String {
    dromedary::urlutils::unescape(s).unwrap_or_else(|_| s.to_string())
}

/// Rust port of dromedary.urlutils.URL — a parsed URL with both
/// quoted and unquoted forms of each component. Attributes are mutable
/// to match the historical Python behaviour.
#[pyclass(name = "URL", subclass, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct UrlObject {
    #[pyo3(get, set)]
    scheme: String,
    #[pyo3(get, set)]
    quoted_user: Option<String>,
    #[pyo3(get, set)]
    user: Option<String>,
    #[pyo3(get, set)]
    quoted_password: Option<String>,
    #[pyo3(get, set)]
    password: Option<String>,
    #[pyo3(get, set)]
    quoted_host: String,
    #[pyo3(get, set)]
    host: String,
    #[pyo3(get, set)]
    port: Option<u16>,
    #[pyo3(get, set)]
    quoted_path: String,
    #[pyo3(get, set)]
    path: String,
}

#[pymethods]
impl UrlObject {
    #[new]
    fn new(
        scheme: String,
        quoted_user: Option<String>,
        quoted_password: Option<String>,
        quoted_host: String,
        port: Option<u16>,
        quoted_path: String,
    ) -> Self {
        let host = unquote_lossy(&quoted_host);
        let user = quoted_user.as_deref().map(unquote_lossy);
        let password = quoted_password.as_deref().map(unquote_lossy);
        let normalized_path = dromedary::urlutils::normalize_quoted_path(&quoted_path);
        let path = unquote_lossy(&normalized_path);
        UrlObject {
            scheme,
            quoted_user,
            user,
            quoted_password,
            password,
            quoted_host,
            host,
            port,
            quoted_path: normalized_path,
            path,
        }
    }

    #[classmethod]
    fn from_string(_cls: &Bound<pyo3::types::PyType>, url: &str) -> PyResult<Self> {
        let parsed = dromedary::urlutils::parse_url(url).map_err(map_urlutils_error_to_pyerr)?;
        Ok(UrlObject::new(
            parsed.scheme,
            parsed.quoted_user,
            parsed.quoted_password,
            parsed.quoted_host,
            parsed.port,
            parsed.quoted_path,
        ))
    }

    fn __eq__(&self, other: &Bound<PyAny>) -> bool {
        // Match Python: compare scheme/host/user/password/path. Port is
        // intentionally not compared (preserved from the original impl).
        match other.extract::<PyRef<UrlObject>>() {
            Ok(o) => {
                self.scheme == o.scheme
                    && self.host == o.host
                    && self.user == o.user
                    && self.password == o.password
                    && self.path == o.path
            }
            Err(_) => false,
        }
    }

    fn __repr__(&self) -> String {
        // <URL('http', None, None, '1:2:3::40', 80, '/one')>
        fn opt_repr<T: std::fmt::Display>(v: &Option<T>) -> String {
            match v {
                Some(s) => format!("'{}'", s),
                None => "None".to_string(),
            }
        }
        let port_repr = match self.port {
            Some(p) => p.to_string(),
            None => "None".to_string(),
        };
        format!(
            "<URL('{}', {}, {}, '{}', {}, '{}')>",
            self.scheme,
            opt_repr(&self.quoted_user),
            opt_repr(&self.quoted_password),
            self.quoted_host,
            port_repr,
            self.quoted_path,
        )
    }

    fn __str__(&self) -> String {
        // Bracket the host if it looks like an IPv6 literal.
        let mut netloc = if self.quoted_host.contains(':') {
            format!("[{}]", self.quoted_host)
        } else {
            self.quoted_host.clone()
        };
        if let Some(user) = &self.quoted_user {
            // Password is intentionally omitted to avoid accidental exposure.
            netloc = format!("{}@{}", user, netloc);
        }
        if let Some(port) = self.port {
            netloc = format!("{}:{}", netloc, port);
        }
        let sep = if self.quoted_path.starts_with('/') || self.quoted_path.is_empty() {
            ""
        } else {
            "/"
        };
        format!("{}://{}{}{}", self.scheme, netloc, sep, self.quoted_path)
    }

    #[pyo3(signature = (offset = None))]
    fn clone(&self, offset: Option<&str>) -> PyResult<Self> {
        let path = match offset {
            Some(off) => {
                // offset must already be url-encoded. Non-ASCII input means
                // the caller forgot to escape — surface that as InvalidURL
                // rather than silently passing the raw bytes through.
                let relative = dromedary::urlutils::unescape(off)
                    .map_err(|_| InvalidURL::new_err((off.to_string(),)))?;
                let combined = dromedary::urlutils::combine_paths(&self.path, &relative);
                dromedary::urlutils::escape(combined.as_bytes(), Some("/~"))
            }
            None => self.quoted_path.clone(),
        };
        Ok(UrlObject::new(
            self.scheme.clone(),
            self.quoted_user.clone(),
            self.quoted_password.clone(),
            self.quoted_host.clone(),
            self.port,
            path,
        ))
    }
}

/// (scheme, user, password, host, port, path) — all unquoted.
type ParsedUrlTuple = (
    String,
    Option<String>,
    Option<String>,
    String,
    Option<u16>,
    String,
);

#[pyfunction]
fn parse_url(url: &str) -> PyResult<ParsedUrlTuple> {
    let p = dromedary::urlutils::parse_url(url).map_err(map_urlutils_error_to_pyerr)?;
    Ok((
        p.scheme,
        p.quoted_user.as_deref().map(unquote_lossy),
        p.quoted_password.as_deref().map(unquote_lossy),
        unquote_lossy(&p.quoted_host),
        p.port,
        unquote_lossy(&p.quoted_path),
    ))
}

#[pymodule]
pub fn _urlutils_rs(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_url, m)?)?;
    m.add_function(wrap_pyfunction!(split, m)?)?;
    m.add_function(wrap_pyfunction!(_find_scheme_and_separator, m)?)?;
    m.add_function(wrap_pyfunction!(strip_trailing_slash, m)?)?;
    m.add_function(wrap_pyfunction!(dirname, m)?)?;
    m.add_function(wrap_pyfunction!(basename, m)?)?;
    m.add_function(wrap_pyfunction!(joinpath, m)?)?;
    m.add_function(wrap_pyfunction!(join, m)?)?;
    m.add_function(wrap_pyfunction!(split_segment_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(split_segment_parameters_raw, m)?)?;
    m.add_function(wrap_pyfunction!(strip_segment_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(join_segment_parameters_raw, m)?)?;
    m.add_function(wrap_pyfunction!(join_segment_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(relative_url, m)?)?;
    m.add_function(wrap_pyfunction!(combine_paths, m)?)?;
    m.add_function(wrap_pyfunction!(escape, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_url, m)?)?;
    m.add_function(wrap_pyfunction!(local_path_to_url, m)?)?;
    m.add_function(wrap_pyfunction!(local_path_from_url, m)?)?;
    m.add_function(wrap_pyfunction!(unescape, m)?)?;
    m.add_function(wrap_pyfunction!(derive_to_location, m)?)?;
    m.add_function(wrap_pyfunction!(file_relpath, m)?)?;
    m.add_function(wrap_pyfunction!(parse_url, m)?)?;
    m.add_class::<UrlObject>()?;
    let win32m = PyModule::new(py, "win32")?;
    win32m.add_function(wrap_pyfunction!(win32_local_path_to_url, &win32m)?)?;
    win32m.add_function(wrap_pyfunction!(win32_local_path_from_url, &win32m)?)?;
    win32m.add_function(wrap_pyfunction!(win32_extract_drive_letter, &win32m)?)?;
    win32m.add_function(wrap_pyfunction!(win32_strip_local_trailing_slash, &win32m)?)?;
    m.add_submodule(&win32m)?;
    let posixm = PyModule::new(py, "posix")?;
    posixm.add_function(wrap_pyfunction!(posix_local_path_to_url, &posixm)?)?;
    posixm.add_function(wrap_pyfunction!(posix_local_path_from_url, &posixm)?)?;
    m.add_submodule(&posixm)?;

    // PyO3 submodule hack for proper import support
    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;
    let module_name = m.name()?;

    // Register submodules in sys.modules for dotted import support
    modules.set_item(format!("{}.win32", module_name), &win32m)?;
    modules.set_item(format!("{}.posix", module_name), &posixm)?;

    Ok(())
}
