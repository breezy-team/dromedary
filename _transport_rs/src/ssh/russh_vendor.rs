//! russh-backed SSH vendor.
//!
//! Replaces `dromedary/ssh/paramiko.py`. Gated behind the `russh` Cargo
//! feature (on by default).
//!
//! Progress through the migration sub-steps:
//!   * 5a ✓ — TCP, password auth, trust-on-first-use host-key acceptance,
//!     SFTP subsystem + `exec` command channel.
//!   * 5b ✓ — SSH agent authentication via `$SSH_AUTH_SOCK`.
//!   * 5c ✓ — `~/.ssh/id_rsa` / `id_dsa` key-file auth with passphrase prompt.
//!   * 5d ✓ — `known_hosts` load/save and host-key mismatch rejection.
//!   * 5e ✓ — `auth_none` probe + `_config.get_auth_password` fallback +
//!     keyboard-interactive with the password as sole response.

use crate::sftp::{BoxedChannel, SFTPClient};
use pyo3::exceptions::PyRuntimeError;
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

import_exception!(dromedary.errors, SocketConnectionError);
import_exception!(dromedary.errors, TransportError);

// ---------------------------------------------------------------------------
// Host-key verification handler
// ---------------------------------------------------------------------------

/// Records *why* `check_server_key` returned `Ok(false)` so the caller can
/// raise the right Python exception after russh collapses the rejection
/// into `Error::UnknownKey`.
#[derive(Default)]
struct HostKeyVerdict {
    mismatch: Option<HostKeyMismatch>,
}

struct HostKeyMismatch {
    host: String,
    expected_fp: String,
    actual_fp: String,
    system_path: PathBuf,
    dromedary_path: PathBuf,
}

/// Client-side handler that verifies the remote server key against the
/// user's `~/.ssh/known_hosts` **and** dromedary's `<config_dir>/
/// ssh_host_keys`, trust-on-first-use into the dromedary file. Mirrors
/// `ParamikoVendor._connect` at paramiko.py:240 so both stores stay in
/// sync between the two backends during the migration.
struct VerifyingHandler {
    host: String,
    port: u16,
    system_path: PathBuf,
    dromedary_path: PathBuf,
    verdict: Arc<Mutex<HostKeyVerdict>>,
}

impl russh::client::Handler for VerifyingHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match check_host_key(
            &self.host,
            self.port,
            server_public_key,
            &self.system_path,
            &self.dromedary_path,
        ) {
            HostKeyCheck::Match => Ok(true),
            HostKeyCheck::Unknown => {
                // Trust-on-first-use: store into dromedary's file only
                // (same as paramiko's `BRZ_HOSTKEYS.add` + `save_host_keys`).
                log::warn!(
                    "Adding {} host key for {}: {}",
                    server_public_key.algorithm(),
                    self.host,
                    server_public_key.fingerprint(Default::default())
                );
                if let Err(e) = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    &self.dromedary_path,
                ) {
                    log::debug!(
                        "failed to save host key to {}: {}",
                        self.dromedary_path.display(),
                        e
                    );
                }
                Ok(true)
            }
            HostKeyCheck::Mismatch { expected_fp } => {
                self.verdict.lock().unwrap().mismatch = Some(HostKeyMismatch {
                    host: self.host.clone(),
                    expected_fp,
                    actual_fp: server_public_key
                        .fingerprint(Default::default())
                        .to_string(),
                    system_path: self.system_path.clone(),
                    dromedary_path: self.dromedary_path.clone(),
                });
                Ok(false)
            }
        }
    }
}

enum HostKeyCheck {
    Match,
    Unknown,
    Mismatch { expected_fp: String },
}

/// Check both the system file and dromedary's file. A mismatch in either
/// file is fatal (it shadows a prior trusted entry). An entry only in the
/// system file is acceptable without writing to the dromedary file.
fn check_host_key(
    host: &str,
    port: u16,
    key: &russh::keys::ssh_key::PublicKey,
    system_path: &Path,
    dromedary_path: &Path,
) -> HostKeyCheck {
    for path in [system_path, dromedary_path] {
        match russh::keys::check_known_hosts_path(host, port, key, path) {
            Ok(true) => return HostKeyCheck::Match,
            Ok(false) => continue,
            Err(russh::keys::Error::KeyChanged { line }) => {
                // Surface the recorded key so we can include its fingerprint
                // in the error message.
                let expected_fp = lookup_recorded_fingerprint(host, port, path, line);
                return HostKeyCheck::Mismatch { expected_fp };
            }
            Err(e) => {
                log::debug!("reading {}: {}", path.display(), e);
            }
        }
    }
    HostKeyCheck::Unknown
}

/// Pull the fingerprint of the *recorded* key on a specific line so a
/// mismatch error can show "expected X, got Y". Returns `<unknown>` if the
/// file can't be reread — the caller still raises `TransportError`.
fn lookup_recorded_fingerprint(host: &str, port: u16, path: &Path, line: usize) -> String {
    match russh::keys::known_hosts::known_host_keys_path(host, port, path) {
        Ok(entries) => entries
            .into_iter()
            .find(|(l, _)| *l == line)
            .map(|(_, k)| k.fingerprint(Default::default()).to_string())
            .unwrap_or_else(|| "<unknown>".to_string()),
        Err(_) => "<unknown>".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Blocking bridge: async russh ChannelStream -> sync Read + Write
// ---------------------------------------------------------------------------

/// Wraps an async `ChannelStream` so it can be driven by synchronous SFTP
/// code. Each `read` / `write` call `block_on`s the owned runtime.
///
/// The `Runtime` is held in an `Arc` so the same runtime that performed the
/// SSH handshake also services subsequent channel I/O — otherwise the inner
/// tokio tasks spawned by russh would be orphaned.
struct BlockingChannel {
    runtime: Arc<Runtime>,
    stream: russh::ChannelStream<russh::client::Msg>,
}

impl Read for BlockingChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.runtime.block_on(self.stream.read(buf))
    }
}

impl Write for BlockingChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.runtime.block_on(self.stream.write(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.runtime.block_on(self.stream.flush())
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn connect_err(host: &str, port: Option<u16>, e: impl std::fmt::Display) -> PyErr {
    SocketConnectionError::new_err((
        host.to_string(),
        port.map(|p| format!(":{p}")).unwrap_or_default(),
        "Failed to connect to",
        e.to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Connection wrapper for `exec`-style SSH sessions
// ---------------------------------------------------------------------------

/// Counterpart to `SSHSubprocessConnection` for the russh transport. Unlike
/// the subprocess variant it doesn't expose a raw fd — the remote command's
/// stdio is read/written through the same async runtime that performed the
/// handshake.
#[pyclass(module = "dromedary._transport_rs.ssh", name = "RusshSSHConnection")]
pub(crate) struct RusshSSHConnection {
    inner: Mutex<Option<BlockingChannel>>,
}

#[pymethods]
impl RusshSSHConnection {
    fn send(&self, py: Python, data: &[u8]) -> PyResult<usize> {
        py.detach(|| {
            let mut guard = self.inner.lock().unwrap();
            let ch = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("connection closed"))?;
            ch.write(data)
                .map_err(|e| PyRuntimeError::new_err(format!("send failed: {e}")))
        })
    }

    fn recv(&self, py: Python, count: usize) -> PyResult<Vec<u8>> {
        py.detach(|| {
            let mut guard = self.inner.lock().unwrap();
            let ch = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("connection closed"))?;
            let mut buf = vec![0u8; count];
            let n = ch
                .read(&mut buf)
                .map_err(|e| PyRuntimeError::new_err(format!("recv failed: {e}")))?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    fn close(&self) -> PyResult<()> {
        // Drops the underlying stream; russh will send channel_close when
        // the Channel's write half is dropped.
        let _ = self.inner.lock().unwrap().take();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Vendor
// ---------------------------------------------------------------------------

#[pyclass(module = "dromedary._transport_rs.ssh", name = "RusshVendor")]
pub(crate) struct RusshVendor;

impl RusshVendor {
    /// Shared connection path: TCP connect, SSH handshake, password auth,
    /// return an open session handle plus the runtime that owns it.
    ///
    /// `key_files` is loaded (with a GIL-requiring passphrase prompt on
    /// encrypted keys) *before* we enter async, so the passphrase prompt
    /// never races the tokio runtime.
    fn connect(
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> PyResult<(Arc<Runtime>, russh::client::Handle<VerifyingHandler>)> {
        let user = username
            .map(str::to_string)
            .unwrap_or_else(|| resolve_username(py, host, port));

        // Load key files while we still hold the GIL: decoding an
        // encrypted key needs to call back into Python's `_ui.get_password`.
        let key_files = load_default_keyfiles(py);

        // Resolve host-key paths while holding the GIL too:
        // `dromedary._bedding.config_dir` is an embedder-overridable
        // function on the Python side.
        let system_path = system_known_hosts_path();
        let dromedary_path = dromedary_host_keys_path(py);

        let port_nr = port.unwrap_or(22);
        let host_owned = host.to_string();
        let verdict = Arc::new(Mutex::new(HostKeyVerdict::default()));
        let password = password.map(str::to_string);

        // Phase 1: connect + agent/keys/probe/supplied-password. Runs with
        // GIL released.
        type Phase1 = (
            Arc<Runtime>,
            russh::client::Handle<VerifyingHandler>,
            AuthPhaseOutcome,
        );
        let phase1: Result<Phase1, AuthError> = py.detach({
            let verdict = verdict.clone();
            let host_owned = host_owned.clone();
            let user = user.clone();
            move || {
                let runtime = Arc::new(
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            AuthError::Russh(russh::Error::IO(std::io::Error::other(format!(
                                "runtime build: {e}"
                            ))))
                        })?,
                );

                let addr = (host_owned.clone(), port_nr);
                let config = Arc::new(russh::client::Config {
                    inactivity_timeout: Some(Duration::from_secs(3600)),
                    ..Default::default()
                });
                let handler = VerifyingHandler {
                    host: host_owned,
                    port: port_nr,
                    system_path,
                    dromedary_path,
                    verdict,
                };

                runtime
                    .block_on(async move {
                        let mut session = russh::client::connect(config, addr, handler)
                            .await
                            .map_err(AuthError::Russh)?;
                        let outcome = authenticate_pre_prompt(
                            &mut session,
                            &user,
                            password.as_deref(),
                            &key_files,
                        )
                        .await?;
                        Ok::<_, AuthError>((session, outcome))
                    })
                    .map(|(session, outcome)| (runtime, session, outcome))
            }
        });

        let (runtime, handle, outcome) =
            phase1.map_err(|e| connect_or_hostkey_err(&host_owned, Some(port_nr), &verdict, e))?;

        if matches!(outcome, AuthPhaseOutcome::Authenticated) {
            return Ok((runtime, handle));
        }

        // Phase 2 (GIL held): ask Python for a password. `None` means the
        // user cancelled — paramiko.py:138 treats that as a hard failure.
        let Some(prompt_pw) = prompt_auth_password(py, host, port, &user) else {
            return Err(connect_or_hostkey_err(
                &host_owned,
                Some(port_nr),
                &verdict,
                AuthError::NoMethodsSucceeded,
            ));
        };

        // Phase 3 (GIL released): try the prompted password. The handle
        // moves into the closure and comes back out with the result so
        // the caller can still use it.
        let (handle, result) = py.detach({
            let runtime = runtime.clone();
            move || {
                let mut handle = handle;
                let r = runtime.block_on(try_password_phase(&mut handle, &user, &prompt_pw));
                (handle, r)
            }
        });

        match result {
            Ok(()) => Ok((runtime, handle)),
            Err(e) => Err(connect_or_hostkey_err(
                &host_owned,
                Some(port_nr),
                &verdict,
                e,
            )),
        }
    }
}

/// Translate an `AuthError` into the right Python exception. `UnknownKey`
/// paired with a recorded mismatch becomes a `TransportError`; everything
/// else stays a `SocketConnectionError` (consistent with paramiko.py).
fn connect_or_hostkey_err(
    host: &str,
    port: Option<u16>,
    verdict: &Mutex<HostKeyVerdict>,
    e: AuthError,
) -> PyErr {
    if let AuthError::Russh(russh::Error::UnknownKey) = &e {
        if let Some(m) = verdict.lock().unwrap().mismatch.take() {
            return TransportError::new_err((
                format!(
                    "Host keys for {} do not match!  {} != {}",
                    m.host, m.expected_fp, m.actual_fp
                ),
                format!(
                    "Try editing {} or {}",
                    m.system_path.display(),
                    m.dromedary_path.display()
                ),
            ));
        }
    }
    connect_err(host, port, e)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum AuthError {
    Russh(russh::Error),
    /// All authentication methods we tried were rejected by the server.
    NoMethodsSucceeded,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Russh(e) => write!(f, "{e}"),
            AuthError::NoMethodsSucceeded => f.write_str("no SSH authentication method succeeded"),
        }
    }
}

impl From<russh::Error> for AuthError {
    fn from(e: russh::Error) -> Self {
        AuthError::Russh(e)
    }
}

/// Outcome of the first authentication phase (agent → keys → auth_none
/// probe → supplied password). If we return `NeedsPrompt`, the caller
/// must re-acquire the GIL, call `_config.get_auth_password`, and invoke
/// [`try_password_phase`] to finish authenticating.
enum AuthPhaseOutcome {
    Authenticated,
    NeedsPrompt,
}

/// Phase 1: agent → key files → `auth_none` probe → supplied password.
///
/// Matches paramiko.py:68-126. Returns `NeedsPrompt` when the server
/// advertises `password` / `keyboard-interactive` but we haven't
/// authenticated yet, so the caller can solicit a password.
async fn authenticate_pre_prompt(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
    password: Option<&str>,
    key_files: &[russh::keys::PrivateKey],
) -> Result<AuthPhaseOutcome, AuthError> {
    if try_agent_auth(session, user).await? {
        return Ok(AuthPhaseOutcome::Authenticated);
    }

    if try_keyfile_auth(session, user, key_files).await? {
        return Ok(AuthPhaseOutcome::Authenticated);
    }

    // auth_none probe: unlikely to succeed, but its `remaining_methods`
    // tells us whether password-style auth is even accepted. If it's not,
    // paramiko.py:116 raises ConnectionError — we mirror that by bailing
    // out with `NoMethodsSucceeded`.
    let remaining = match session.authenticate_none(user.to_string()).await? {
        russh::client::AuthResult::Success => return Ok(AuthPhaseOutcome::Authenticated),
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    if !password_style_accepted(&remaining) {
        log::debug!(
            "server does not accept password or keyboard-interactive; remaining: {:?}",
            remaining
        );
        return Err(AuthError::NoMethodsSucceeded);
    }

    // Try the explicitly-supplied password first, so a caller that passes
    // one doesn't also get a prompt.
    if let Some(pw) = password {
        if try_password_or_interactive(session, user, pw).await? {
            return Ok(AuthPhaseOutcome::Authenticated);
        }
    }

    Ok(AuthPhaseOutcome::NeedsPrompt)
}

/// Phase 3: try a password obtained from `_config.get_auth_password`.
async fn try_password_phase(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
    password: &str,
) -> Result<(), AuthError> {
    if try_password_or_interactive(session, user, password).await? {
        Ok(())
    } else {
        Err(AuthError::NoMethodsSucceeded)
    }
}

fn password_style_accepted(methods: &russh::MethodSet) -> bool {
    methods.iter().any(|m| {
        matches!(
            m,
            russh::MethodKind::Password | russh::MethodKind::KeyboardInteractive
        )
    })
}

/// Try `authenticate_password`; on failure, fall back to
/// `keyboard-interactive` with the password as the sole response. This
/// mirrors paramiko's `auth_password` which transparently does the same.
async fn try_password_or_interactive(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
    password: &str,
) -> Result<bool, AuthError> {
    match session
        .authenticate_password(user.to_string(), password)
        .await?
    {
        russh::client::AuthResult::Success => return Ok(true),
        russh::client::AuthResult::Failure { .. } => {}
    }

    // Keyboard-interactive fallback. We blindly respond to the first
    // InfoRequest with one copy of the password per prompt. Servers that
    // ask anything beyond a password aren't supported (paramiko has the
    // same limitation — see the XXX at paramiko.py:109).
    match session
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await?
    {
        russh::client::KeyboardInteractiveAuthResponse::Success => Ok(true),
        russh::client::KeyboardInteractiveAuthResponse::Failure { .. } => Ok(false),
        russh::client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
            let responses = vec![password.to_string(); prompts.len()];
            match session
                .authenticate_keyboard_interactive_respond(responses)
                .await?
            {
                russh::client::KeyboardInteractiveAuthResponse::Success => Ok(true),
                _ => Ok(false),
            }
        }
    }
}

/// Enumerate keys from the SSH agent and try each in turn. Silent no-op
/// when the agent is unreachable — matches paramiko's behavior (agent
/// failures never block other auth methods). On Unix this uses
/// `$SSH_AUTH_SOCK`; on Windows it talks to Pageant.
#[cfg(unix)]
async fn try_agent_auth(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
) -> Result<bool, AuthError> {
    let agent = match russh::keys::agent::client::AgentClient::connect_env().await {
        Ok(a) => a,
        Err(e) => {
            log::debug!("SSH agent unavailable: {e}");
            return Ok(false);
        }
    };
    try_agent_auth_with(session, user, agent).await
}

#[cfg(windows)]
async fn try_agent_auth(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
) -> Result<bool, AuthError> {
    // `connect_pageant` in russh 0.54 returns the client directly (no
    // `Result`); a missing/unreachable Pageant surfaces later when we
    // actually request identities, where it's already handled as a silent
    // no-op below.
    let agent = russh::keys::agent::client::AgentClient::connect_pageant().await;
    try_agent_auth_with(session, user, agent).await
}

async fn try_agent_auth_with<S>(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<bool, AuthError>
where
    S: russh::keys::agent::client::AgentStream + Unpin + Send + 'static,
{
    let identities = match agent.request_identities().await {
        Ok(ids) => ids,
        Err(e) => {
            log::debug!("SSH agent request_identities failed: {e}");
            return Ok(false);
        }
    };

    for key in identities {
        log::debug!(
            "Trying SSH agent key {} ({})",
            key.fingerprint(Default::default()),
            key.algorithm()
        );
        match session
            .authenticate_publickey_with(user.to_string(), key, None, &mut agent)
            .await
        {
            Ok(auth) if auth.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                // `authenticate_publickey_with` can fail for signer
                // problems even while other agent keys might still work.
                log::debug!("agent key auth attempt failed: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

/// Try each preloaded key file in turn. RSA keys negotiate the strongest
/// hash algorithm the server advertises (falling back to SHA-1 when the
/// server doesn't send `server-sig-algs`).
async fn try_keyfile_auth(
    session: &mut russh::client::Handle<VerifyingHandler>,
    user: &str,
    key_files: &[russh::keys::PrivateKey],
) -> Result<bool, AuthError> {
    if key_files.is_empty() {
        return Ok(false);
    }

    // `Some(Some(alg))` = server wants this hash; `Some(None)` = server
    // only supports SHA-1; `None` = server didn't advertise, try SHA-1.
    let rsa_hash = session
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();

    for key in key_files {
        let with_hash = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key.clone()), rsa_hash);
        log::debug!(
            "Trying key file ({}) fingerprint {}",
            key.algorithm(),
            key.fingerprint(Default::default())
        );
        match session
            .authenticate_publickey(user.to_string(), with_hash)
            .await
        {
            Ok(auth) if auth.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                log::debug!("key file auth attempt failed: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

/// Synchronous helper that loads `~/.ssh/id_rsa` and `~/.ssh/id_dsa`,
/// prompting the user via `dromedary._ui.get_password` for a passphrase
/// when a key is encrypted. Missing files are silently skipped.
///
/// Runs with the GIL held because the passphrase prompt is Python-side.
fn load_default_keyfiles(py: Python) -> Vec<russh::keys::PrivateKey> {
    let Some(home) = home_dir() else {
        log::debug!("no home directory; skipping key-file auth");
        return Vec::new();
    };

    let mut keys = Vec::new();
    for name in ["id_rsa", "id_dsa"] {
        let path = home.join(".ssh").join(name);
        if !path.exists() {
            continue;
        }
        match load_one_keyfile(py, &path) {
            Ok(Some(k)) => keys.push(k),
            Ok(None) => {}
            Err(e) => log::debug!("load key {}: {}", path.display(), e),
        }
    }
    keys
}

/// Load a single private key file, prompting once for a passphrase on
/// `KeyIsEncrypted`. Returns `Ok(None)` if the user cancels the prompt or
/// the second attempt also fails.
fn load_one_keyfile(
    py: Python,
    path: &Path,
) -> Result<Option<russh::keys::PrivateKey>, russh::keys::Error> {
    match russh::keys::load_secret_key(path, None) {
        Ok(k) => Ok(Some(k)),
        Err(russh::keys::Error::KeyIsEncrypted) => {
            let Some(pw) = prompt_key_password(py, path) else {
                log::debug!(
                    "encrypted key {} skipped (no passphrase provided)",
                    path.display()
                );
                return Ok(None);
            };
            match russh::keys::load_secret_key(path, Some(&pw)) {
                Ok(k) => Ok(Some(k)),
                Err(e) => {
                    log::debug!(
                        "decrypting {} with supplied passphrase failed: {}",
                        path.display(),
                        e
                    );
                    Ok(None)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Call `dromedary._ui.get_password(prompt, filename=<path>)`, matching
/// paramiko.py's prompt format. Returns `None` if the call fails or the
/// result is `None`.
fn prompt_key_password(py: Python, path: &Path) -> Option<String> {
    let ui = match py.import("dromedary._ui") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._ui failed: {e}");
            return None;
        }
    };
    let kwargs = PyDict::new(py);
    if let Err(e) = kwargs.set_item("filename", path.display().to_string()) {
        log::debug!("building get_password kwargs failed: {e}");
        return None;
    }
    let result = ui.call_method(
        "get_password",
        ("SSH %(filename)s password",),
        Some(&kwargs),
    );
    match result {
        Ok(v) if v.is_none() => None,
        Ok(v) => v.extract::<String>().ok(),
        Err(e) => {
            log::debug!("_ui.get_password raised: {e}");
            None
        }
    }
}

/// Resolve a default username via `dromedary._config.get_auth_user("ssh",
/// host, port=port, default=getpass.getuser())`, falling back to `$USER`
/// if the Python layer is unavailable. Mirrors paramiko.py:64-67.
fn resolve_username(py: Python, host: &str, port: Option<u16>) -> String {
    let fallback = whoami_or_default();
    let cfg = match py.import("dromedary._config") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._config failed: {e}");
            return fallback;
        }
    };
    let kwargs = PyDict::new(py);
    if let Err(e) = kwargs.set_item("default", &fallback) {
        log::debug!("building get_auth_user kwargs failed: {e}");
        return fallback;
    }
    if let Some(p) = port {
        if let Err(e) = kwargs.set_item("port", p) {
            log::debug!("building get_auth_user kwargs failed: {e}");
            return fallback;
        }
    }
    match cfg.call_method("get_auth_user", ("ssh", host), Some(&kwargs)) {
        Ok(v) if v.is_none() => fallback,
        Ok(v) => v.extract::<String>().unwrap_or(fallback),
        Err(e) => {
            log::debug!("_config.get_auth_user raised: {e}");
            fallback
        }
    }
}

/// Prompt for an auth password via `dromedary._config.get_auth_password(
/// "ssh", host, user, port=port)`. Returns `None` if the call fails or
/// the user cancels.
fn prompt_auth_password(py: Python, host: &str, port: Option<u16>, user: &str) -> Option<String> {
    let cfg = match py.import("dromedary._config") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._config failed: {e}");
            return None;
        }
    };
    let kwargs = PyDict::new(py);
    if let Some(p) = port {
        if let Err(e) = kwargs.set_item("port", p) {
            log::debug!("building get_auth_password kwargs failed: {e}");
            return None;
        }
    }
    match cfg.call_method("get_auth_password", ("ssh", host, user), Some(&kwargs)) {
        Ok(v) if v.is_none() => None,
        Ok(v) => v.extract::<String>().ok(),
        Err(e) => {
            log::debug!("_config.get_auth_password raised: {e}");
            None
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `~/.ssh/known_hosts` (on Windows: `~/ssh/known_hosts` — matches
/// russh's own `known_hosts_path`). Falls back to a sentinel path inside
/// a non-existent temp dir when `$HOME` is unset; `check_known_hosts_path`
/// returns `Ok(false)` on missing files so this is harmless.
fn system_known_hosts_path() -> PathBuf {
    match home_dir() {
        Some(h) => {
            if cfg!(windows) {
                h.join("ssh").join("known_hosts")
            } else {
                h.join(".ssh").join("known_hosts")
            }
        }
        None => PathBuf::from("/nonexistent/known_hosts"),
    }
}

/// Resolve `<dromedary._bedding.config_dir()>/ssh_host_keys` via the
/// Python side so embedder overrides are honored. Also calls
/// `_bedding.ensure_config_dir_exists()` so the later `learn_*` write
/// doesn't fail on a missing parent directory.
fn dromedary_host_keys_path(py: Python) -> PathBuf {
    let fallback = || {
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        xdg.join("breezy").join("ssh_host_keys")
    };
    let bedding = match py.import("dromedary._bedding") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._bedding failed: {e}");
            return fallback();
        }
    };
    if let Err(e) = bedding.call_method0("ensure_config_dir_exists") {
        log::debug!("ensure_config_dir_exists failed: {e}");
    }
    match bedding.call_method0("config_dir") {
        Ok(v) => match v.extract::<String>() {
            Ok(s) => PathBuf::from(s).join("ssh_host_keys"),
            Err(e) => {
                log::debug!("config_dir() returned non-string: {e}");
                fallback()
            }
        },
        Err(e) => {
            log::debug!("_bedding.config_dir() raised: {e}");
            fallback()
        }
    }
}

#[pymethods]
impl RusshVendor {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Open an SFTP session. Returns a fully-constructed `SFTPClient` that
    /// the caller can use directly (same object as `_transport_rs.sftp.
    /// SFTPClient`).
    #[pyo3(signature = (username, password, host, port=None))]
    fn connect_sftp(
        &self,
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> PyResult<SFTPClient> {
        let (runtime, handle) = Self::connect(py, username, password, host, port)?;

        py.detach(move || {
            let (runtime_for_stream, stream) = runtime.block_on({
                let runtime = runtime.clone();
                async move {
                    let channel = handle
                        .channel_open_session()
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("open session: {e}")))?;
                    channel.request_subsystem(true, "sftp").await.map_err(|e| {
                        PyRuntimeError::new_err(format!("request sftp subsystem: {e}"))
                    })?;
                    Ok::<_, PyErr>((runtime, channel.into_stream()))
                }
            })?;

            let channel: BoxedChannel = Box::new(BlockingChannel {
                runtime: runtime_for_stream,
                stream,
            });
            SFTPClient::from_channel(channel)
                .map_err(|e| PyRuntimeError::new_err(format!("sftp init: {e}")))
        })
    }

    /// Execute a remote command and return a connection whose `send` / `recv`
    /// drive the command's stdio. Parallels paramiko's
    /// `_ParamikoSSHConnection`.
    #[pyo3(signature = (username, password, host, command, port=None))]
    fn connect_ssh(
        &self,
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        command: Vec<String>,
        port: Option<u16>,
    ) -> PyResult<RusshSSHConnection> {
        let (runtime, handle) = Self::connect(py, username, password, host, port)?;

        py.detach(move || {
            let (runtime_for_stream, stream) = runtime.block_on({
                let runtime = runtime.clone();
                async move {
                    let channel = handle
                        .channel_open_session()
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("open session: {e}")))?;
                    let cmdline = command.join(" ");
                    channel
                        .exec(true, cmdline.as_str())
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("exec: {e}")))?;
                    Ok::<_, PyErr>((runtime, channel.into_stream()))
                }
            })?;

            Ok(RusshSSHConnection {
                inner: Mutex::new(Some(BlockingChannel {
                    runtime: runtime_for_stream,
                    stream,
                })),
            })
        })
    }
}

/// Minimal fallback when no username is supplied. `_config.get_auth_user`
/// on the Python side gives a richer lookup; 5e wires that in. For now use
/// the `$USER` env var or "unknown".
fn whoami_or_default() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<RusshVendor>()?;
    m.add_class::<RusshSSHConnection>()?;
    Ok(())
}
