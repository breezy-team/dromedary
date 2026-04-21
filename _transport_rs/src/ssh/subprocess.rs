//! Subprocess-based SSH vendors (OpenSSH, PLink, LSH) plus the loopback
//! "vendor" (plain TCP) and the connection wrapper they produce.
//!
//! These wrap an external `ssh` binary, exposing its stdio as a file
//! descriptor that the SFTP client can consume directly. No crypto library
//! involved; always compiled.
//!
//! The Rust surface is deliberately minimal: vendors hand back either an
//! fd (SFTP) or an [`SSHSubprocessConnection`] (command exec). Wrapping the
//! fd in `_transport_rs.sftp.SFTPClient` happens on the Python side —
//! mirrors how `SFTPClient(sock._sock.detach())` is called today and keeps
//! the `ssh` and `sftp` Rust submodules decoupled.

use dromedary::ssh::{build_argv, ArgvError, Flavor};
use pyo3::exceptions::PyRuntimeError;
use pyo3::import_exception;
use pyo3::prelude::*;
#[cfg(unix)]
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

import_exception!(dromedary.errors, StrangeHostname);
import_exception!(dromedary.errors, SocketConnectionError);

fn argv_err_to_py(err: ArgvError) -> PyErr {
    match err {
        ArgvError::StrangeHostname(h) => StrangeHostname::new_err((h,)),
        ArgvError::InvalidArguments => PyRuntimeError::new_err(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Connection wrapper
// ---------------------------------------------------------------------------

struct Inner {
    child: Option<Child>,
    #[cfg(unix)]
    sock_fd: Option<RawFd>,
}

/// Rust port of `dromedary.ssh.SSHSubprocessConnection`.
///
/// Does not expose `get_sock_or_pipes()` — that method was paramiko-only and
/// goes away with the russh migration. Callers use [`detach_fd`] for the
/// SFTP path and [`wait`] / [`close`] for command execution.
#[pyclass(
    module = "dromedary._transport_rs.ssh",
    name = "SSHSubprocessConnection"
)]
pub(crate) struct SSHSubprocessConnection {
    inner: Mutex<Inner>,
}

impl SSHSubprocessConnection {
    #[cfg(unix)]
    fn from_parts(child: Child, sock_fd: Option<RawFd>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                child: Some(child),
                sock_fd,
            }),
        }
    }

    #[cfg(not(unix))]
    fn from_parts(child: Child) -> Self {
        Self {
            inner: Mutex::new(Inner { child: Some(child) }),
        }
    }
}

#[pymethods]
impl SSHSubprocessConnection {
    /// Take ownership of the raw fd underlying this connection.
    ///
    /// Returns the socketpair fd when one was used, otherwise the child's
    /// stdout pipe fd. After this call the connection no longer owns the
    /// fd; `close` / `wait` still manage the child process itself.
    #[cfg(unix)]
    fn detach_fd(&self) -> PyResult<RawFd> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(fd) = inner.sock_fd.take() {
            return Ok(fd);
        }
        let child = inner
            .child
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("connection already closed"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("no stdout fd available"))?;
        Ok(stdout.into_raw_fd())
    }

    fn wait(&self) -> PyResult<Option<i32>> {
        let mut inner = self.inner.lock().unwrap();
        match inner.child.as_mut() {
            Some(child) => child
                .wait()
                .map(|s| s.code())
                .map_err(|e| PyRuntimeError::new_err(format!("wait failed: {e}"))),
            None => Ok(None),
        }
    }

    fn close(&self) -> PyResult<()> {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(unix)]
        if let Some(fd) = inner.sock_fd.take() {
            // SAFETY: we owned this fd; `nix::unistd::close` consumes it,
            // so it's closed exactly once. Errors are ignored to match the
            // best-effort semantics of Python's `_close_ssh_proc`.
            let _ = nix::unistd::close(fd);
        }
        if let Some(mut child) = inner.child.take() {
            drop(child.stdin.take());
            drop(child.stdout.take());
            let _ = child.wait();
        }
        Ok(())
    }
}

impl Drop for SSHSubprocessConnection {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// ---------------------------------------------------------------------------
// Spawn helper
// ---------------------------------------------------------------------------

/// Spawn the ssh subprocess, preferring a `socketpair` for its stdio (matches
/// the Python comment: "we prefer sockets to pipes because they support
/// non-blocking short reads").
#[cfg(unix)]
fn spawn(argv: &[String], host: &str, port: Option<u16>) -> PyResult<SSHSubprocessConnection> {
    // Apple targets' `SockFlag` doesn't expose SOCK_CLOEXEC (the OS itself
    // lacks atomic CLOEXEC on socketpair), so on those we create the pair
    // without the flag and set FD_CLOEXEC on our half via fcntl below.
    #[cfg(not(target_vendor = "apple"))]
    let cloexec = nix::sys::socket::SockFlag::SOCK_CLOEXEC;
    #[cfg(target_vendor = "apple")]
    let cloexec = nix::sys::socket::SockFlag::empty();

    let pair = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        cloexec,
    )
    .ok();

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    let my_sock: Option<OwnedFd> = if let Some((mine, theirs)) = pair {
        // Dup twice: once for child stdin, once for stdout. The child
        // inherits them via `Command::stdin` / `stdout`; the parent keeps
        // its half (`mine`) with CLOEXEC set.
        let dup_in = nix::unistd::dup(&theirs)
            .map_err(|e| PyRuntimeError::new_err(format!("dup failed: {e}")))?;
        let dup_out = nix::unistd::dup(&theirs)
            .map_err(|e| PyRuntimeError::new_err(format!("dup failed: {e}")))?;
        cmd.stdin(Stdio::from(dup_in));
        cmd.stdout(Stdio::from(dup_out));
        // `theirs` is closed in the parent when this `OwnedFd` drops.
        drop(theirs);
        // On Apple targets, socketpair() can't atomically set CLOEXEC, so do it now.
        #[cfg(target_vendor = "apple")]
        nix::fcntl::fcntl(
            &mine,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("fcntl(FD_CLOEXEC) failed: {e}")))?;
        Some(mine)
    } else {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        None
    };
    cmd.stderr(Stdio::inherit());

    let child = cmd.spawn().map_err(|e| {
        SocketConnectionError::new_err((
            host.to_string(),
            port.map(|p| format!(":{p}")).unwrap_or_default(),
            "Failed to connect to",
            e.to_string(),
        ))
    })?;

    let my_raw: Option<RawFd> = my_sock.map(|fd| fd.into_raw_fd());
    Ok(SSHSubprocessConnection::from_parts(child, my_raw))
}

#[cfg(not(unix))]
fn spawn(argv: &[String], host: &str, port: Option<u16>) -> PyResult<SSHSubprocessConnection> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let child = cmd.spawn().map_err(|e| {
        SocketConnectionError::new_err((
            host.to_string(),
            port.map(|p| format!(":{p}")).unwrap_or_default(),
            "Failed to connect to",
            e.to_string(),
        ))
    })?;
    Ok(SSHSubprocessConnection::from_parts(child))
}

// ---------------------------------------------------------------------------
// Vendor classes exposed to Python
// ---------------------------------------------------------------------------

macro_rules! subprocess_vendor {
    ($name:ident, $flavor:expr, $pyname:literal) => {
        #[pyclass(module = "dromedary._transport_rs.ssh", name = $pyname)]
        pub(crate) struct $name {
            executable_path: Mutex<Option<String>>,
        }

        #[pymethods]
        impl $name {
            #[new]
            fn new() -> Self {
                Self {
                    executable_path: Mutex::new(None),
                }
            }

            /// Override the ssh binary. Matches the Python
            /// `SSHVendorManager._get_vendor_from_path` flow, where
            /// `BRZ_SSH=/path/to/ssh` assigns `vendor.executable_path` on
            /// the detected vendor.
            #[setter]
            fn set_executable_path(&self, path: Option<String>) {
                *self.executable_path.lock().unwrap() = path;
            }

            #[getter]
            fn executable_path(&self) -> Option<String> {
                self.executable_path.lock().unwrap().clone()
            }

            /// Spawn the ssh binary with the "sftp" subsystem and return
            /// the raw fd to use with `_transport_rs.sftp.SFTPClient(fd)`.
            /// The vendor no longer owns the fd after this call.
            #[cfg(unix)]
            #[pyo3(signature = (username, host, port=None))]
            fn spawn_sftp(
                &self,
                username: Option<&str>,
                host: &str,
                port: Option<u16>,
            ) -> PyResult<RawFd> {
                let exe = self.executable_path.lock().unwrap().clone();
                let argv = build_argv(
                    $flavor,
                    exe.as_deref(),
                    username,
                    host,
                    port,
                    Some("sftp"),
                    None,
                )
                .map_err(argv_err_to_py)?;
                let conn = spawn(&argv, host, port)?;
                conn.detach_fd()
            }

            /// Spawn the ssh binary to execute `command` on the remote
            /// host, returning an [`SSHSubprocessConnection`] for the
            /// caller to drive.
            #[pyo3(signature = (username, host, command, port=None))]
            fn connect_ssh(
                &self,
                username: Option<&str>,
                host: &str,
                command: Vec<String>,
                port: Option<u16>,
            ) -> PyResult<SSHSubprocessConnection> {
                let exe = self.executable_path.lock().unwrap().clone();
                let argv = build_argv(
                    $flavor,
                    exe.as_deref(),
                    username,
                    host,
                    port,
                    None,
                    Some(&command),
                )
                .map_err(argv_err_to_py)?;
                spawn(&argv, host, port)
            }
        }
    };
}

subprocess_vendor!(
    OpenSSHSubprocessVendor,
    Flavor::OpenSSH,
    "OpenSSHSubprocessVendor"
);
subprocess_vendor!(LSHSubprocessVendor, Flavor::Lsh, "LSHSubprocessVendor");
subprocess_vendor!(
    PLinkSubprocessVendor,
    Flavor::PLink,
    "PLinkSubprocessVendor"
);

// ---------------------------------------------------------------------------
// Loopback "vendor" (plain TCP, no ssh)
// ---------------------------------------------------------------------------

/// Rust port of `dromedary.ssh.LoopbackVendor`. Used by the test suite via
/// `stub_sftp.py` to talk to a local SFTP server over a TCP socket with no
/// SSH transport in between.
#[pyclass(module = "dromedary._transport_rs.ssh", name = "LoopbackVendor")]
pub(crate) struct LoopbackVendor;

#[pymethods]
impl LoopbackVendor {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Open a TCP connection and return the raw fd. Caller wraps it in
    /// `_transport_rs.sftp.SFTPClient(fd)`.
    #[cfg(unix)]
    #[pyo3(signature = (host, port))]
    fn spawn_sftp(&self, host: &str, port: u16) -> PyResult<RawFd> {
        let sock = std::net::TcpStream::connect((host, port)).map_err(|e| {
            SocketConnectionError::new_err((
                host.to_string(),
                format!(":{port}"),
                "Failed to connect to",
                e.to_string(),
            ))
        })?;
        // Convert to OwnedFd so we can release ownership cleanly.
        let owned: OwnedFd = sock.into();
        Ok(owned.into_raw_fd())
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<SSHSubprocessConnection>()?;
    m.add_class::<OpenSSHSubprocessVendor>()?;
    m.add_class::<LSHSubprocessVendor>()?;
    m.add_class::<PLinkSubprocessVendor>()?;
    m.add_class::<LoopbackVendor>()?;
    Ok(())
}

// Argv construction and tests live in the top-level `dromedary::ssh`
// module so they're unit-testable without needing the Python extension
// linker symbols (which block `cargo test` on this `cdylib` crate).
