//! SSH connection support for the Rust transport layer.
//!
//! This module mirrors `dromedary/ssh/__init__.py`. It exposes vendor
//! implementations (subprocess-based and library-based) that produce an
//! [`SSHConnection`] or an SFTP channel usable by the `sftp` submodule.
//!
//! The `SshLibrary` / `SshSession` traits below are an internal abstraction
//! that lets us plug in different crypto backends (russh today; libssh2 or
//! ssh2-rs in the future) without rewriting the PyO3-facing vendor layer.
//! They are deliberately not exposed to Python.

use pyo3::prelude::*;
use std::ffi::OsString;

#[cfg(feature = "russh")]
mod russh_vendor;
mod subprocess;
// TODO: add `libssh2` backend module gated on a future `libssh2` feature.
// TODO: add `ssh2-rs` backend module gated on a future `ssh2-rs` feature.

/// Parameters used to establish an SSH connection.
#[allow(dead_code)]
pub(crate) struct ConnectConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Backend-agnostic SSH session. Each crypto library (russh, libssh2, …)
/// provides its own implementation.
#[allow(dead_code)]
pub(crate) trait SshSession: Send {
    /// Open the `sftp` subsystem and return a bidirectional stream suitable
    /// for feeding into `sftp::SftpClient::from_stream` (to be added).
    fn open_sftp(&mut self) -> std::io::Result<Box<dyn ReadWrite>>;

    /// Execute a command on the remote host, returning its stdio as a stream.
    fn exec(&mut self, command: &str) -> std::io::Result<Box<dyn ReadWrite>>;
}

/// Marker trait combining `Read + Write + Send` so we can hand a trait object
/// to the SFTP client.
pub(crate) trait ReadWrite: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> ReadWrite for T {}

/// Library-level entry point. Each backend implements this to hand back a
/// fresh [`SshSession`] for the given connection parameters.
#[allow(dead_code)]
pub(crate) trait SshLibrary {
    fn connect(cfg: &ConnectConfig) -> std::io::Result<Box<dyn SshSession>>;
}

/// Classify an `ssh -V` version string into a vendor registry key.
/// Mirrors `dromedary.ssh.SSHVendorManager._get_vendor_by_version_string`.
#[pyfunction]
#[pyo3(signature = (version, progname))]
fn classify_ssh_version(version: &str, progname: &str) -> Option<&'static str> {
    dromedary::ssh::classify_ssh_version(version, progname)
}

/// Run `executable -V` and return the vendor registry key, or `None` if
/// the binary can't be run or the output isn't recognized. Mirrors the
/// combination of `_get_ssh_version_string` + `_get_vendor_from_path`.
#[pyfunction]
#[pyo3(signature = (executable))]
fn detect_ssh_vendor(py: Python, executable: OsString) -> Option<&'static str> {
    py.detach(|| dromedary::ssh::detect_ssh_vendor(&executable))
}

pub(crate) fn register(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    subprocess::register(py, m)?;
    #[cfg(feature = "russh")]
    russh_vendor::register(py, m)?;
    m.add_function(wrap_pyfunction!(classify_ssh_version, m)?)?;
    m.add_function(wrap_pyfunction!(detect_ssh_vendor, m)?)?;
    Ok(())
}
