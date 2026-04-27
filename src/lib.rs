use crate::lock::{Lock, LockError};
use std::collections::HashMap;
use std::fs::{Metadata, Permissions};
use std::io::{Read, Seek};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::UNIX_EPOCH;
use url::Url;

#[derive(Debug)]
pub enum Error {
    InProcessTransport,

    NotLocalUrl(String),

    NoSuchFile(Option<String>),

    FileExists(Option<String>),

    TransportNotPossible(Option<String>),

    UrlError(url::ParseError),

    UrlutilsError(crate::urlutils::Error),

    PermissionDenied(Option<String>),

    Io(std::io::Error),

    PathNotChild,

    UnexpectedEof,

    ShortReadvError(String, u64, u64, u64),

    LockContention(std::path::PathBuf),

    LockFailed(std::path::PathBuf, String),

    IsADirectoryError(Option<String>),

    NotADirectoryError(Option<String>),

    DirectoryNotEmptyError(Option<String>),

    ResourceBusy(Option<String>),

    /// HTTP server returned a status code we couldn't interpret, or
    /// the response body was malformed beyond what RangeFile could
    /// parse. Maps to `dromedary.errors.InvalidHttpResponse`.
    InvalidHttpResponse {
        path: String,
        msg: String,
    },

    /// HTTP server returned a status code we *can* interpret but
    /// didn't expect at this point. Maps to
    /// `dromedary.errors.UnexpectedHttpStatus`.
    UnexpectedHttpStatus {
        path: String,
        code: u16,
        extra: Option<String>,
    },

    /// HTTP server's response to a Range request was malformed or
    /// rejected our range. Maps to `dromedary.errors.InvalidHttpRange`.
    InvalidHttpRange {
        path: String,
        range: String,
        msg: String,
    },

    /// HTTP server returned 400 (Bad Request) without us asking for
    /// a Range — usually a client-side bug or malformed URL. Maps to
    /// `dromedary.errors.BadHttpRequest`.
    BadHttpRequest {
        path: String,
        reason: String,
    },

    /// HTTP server redirected us but we weren't asked to follow.
    /// Carries the original and target URLs so callers can retry on
    /// a fresh transport. Maps to `dromedary.errors.RedirectRequested`.
    RedirectRequested {
        source: String,
        target: String,
        is_permanent: bool,
    },

    /// HTTP server tried to redirect us somewhere that doesn't fit
    /// the transport's URL shape (e.g. a different scheme). Maps to
    /// `dromedary.errors.UnusableRedirect`.
    UnusableRedirect {
        source: String,
        target: String,
        reason: String,
    },

    /// Network-level failure talking to the server — DNS, TCP,
    /// TLS handshake — distinct from an `Io` error during a
    /// successful exchange. Maps to `dromedary.errors.ConnectionError`.
    ConnectionError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub type UrlFragment = str;

pub fn map_io_err_to_transport_err(err: std::io::Error, path: Option<&str>) -> Error {
    match err.kind() {
        std::io::ErrorKind::NotFound => Error::NoSuchFile(path.map(|p| p.to_string())),
        std::io::ErrorKind::AlreadyExists => Error::FileExists(path.map(|p| p.to_string())),
        std::io::ErrorKind::PermissionDenied => {
            Error::PermissionDenied(path.map(|p| p.to_string()))
        }
        // use of unstable library feature 'io_error_more'
        // https://github.com/rust-lang/rust/issues/86442
        //
        // std::io::ErrorKind::NotADirectoryError => Error::NotADirectoryError(None),
        // std::io::ErrorKind::IsADirectoryError => Error::IsADirectoryError(None),
        _ => {
            #[cfg(unix)]
            {
                match err.raw_os_error() {
                    Some(e) if e == libc::ENOTDIR => {
                        Error::NotADirectoryError(path.map(|p| p.to_string()))
                    }
                    Some(e) if e == libc::EISDIR => {
                        Error::IsADirectoryError(path.map(|p| p.to_string()))
                    }
                    Some(e) if e == libc::ENOTEMPTY => {
                        Error::DirectoryNotEmptyError(path.map(|p| p.to_string()))
                    }
                    _ => Error::Io(err),
                }
            }
            #[cfg(windows)]
            {
                // Windows error codes from winerror.h. Mirror the unix
                // mapping above for the equivalents that show up via
                // `std::fs` operations.
                const ERROR_DIRECTORY: i32 = 267; // The directory name is invalid.
                const ERROR_DIR_NOT_EMPTY: i32 = 145;
                match err.raw_os_error() {
                    Some(e) if e == ERROR_DIRECTORY => {
                        Error::NotADirectoryError(path.map(|p| p.to_string()))
                    }
                    Some(e) if e == ERROR_DIR_NOT_EMPTY => {
                        Error::DirectoryNotEmptyError(path.map(|p| p.to_string()))
                    }
                    _ => Error::Io(err),
                }
            }
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::UrlError(err)
    }
}

impl From<crate::urlutils::Error> for Error {
    fn from(err: crate::urlutils::Error) -> Self {
        Error::UrlutilsError(err)
    }
}

/// Compute a relative path for `abspath` against `base`.
///
/// Mirrors the Python `Transport.relpath` base-class implementation:
/// accepts `base` with or without its trailing slash, and strips any
/// trailing slash from the returned relpath. Transports whose URL
/// scheme doesn't need special handling can call this directly from
/// their `relpath` impl.
pub fn relpath_against_base(base: &Url, abspath: &Url) -> Result<String> {
    let base_str = base.as_str();
    let target = abspath.as_str();
    // Accept the exact base, or the base with its trailing slash stripped.
    let base_no_slash = base_str.strip_suffix('/').unwrap_or(base_str);
    if target == base_no_slash {
        return Ok(String::new());
    }
    match target.strip_prefix(base_str) {
        Some(rest) => Ok(rest.trim_end_matches('/').to_string()),
        None => Err(Error::PathNotChild),
    }
}

/// Coarse file kind. Mirrors `std::fs::FileType` but is cross-platform and
/// sidesteps the Unix-only mode-bit parsing the old implementation relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

pub struct Stat {
    pub size: usize,
    /// Unix permission bits. Not present on Windows — see
    /// `memory/project_windows_port.md` for the design rationale.
    #[cfg(unix)]
    pub mode: u32,
    pub kind: FileKind,
    pub mtime: Option<f64>,
}

impl From<Metadata> for Stat {
    fn from(metadata: Metadata) -> Self {
        let ft = metadata.file_type();
        let kind = if ft.is_dir() {
            FileKind::Dir
        } else if ft.is_file() {
            FileKind::File
        } else if ft.is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Other
        };
        Stat {
            size: metadata.len() as usize,
            #[cfg(unix)]
            mode: metadata.permissions().mode(),
            kind,
            mtime: metadata.modified().map_or(None, |t| {
                Some(t.duration_since(UNIX_EPOCH).unwrap().as_secs_f64())
            }),
        }
    }
}

impl Stat {
    pub fn is_dir(&self) -> bool {
        self.kind == FileKind::Dir
    }

    pub fn is_file(&self) -> bool {
        self.kind == FileKind::File
    }
}

pub trait WriteStream: std::io::Write {
    fn sync_data(&self) -> std::io::Result<()>;
}

pub trait ReadStream: Read + Seek {}

pub trait Transport: std::fmt::Debug + 'static + Send + Sync {
    /// Return a URL for self that can be given to an external process.
    ///
    /// There is no guarantee that the URL can be accessed from a different
    /// machine - e.g. file:/// urls are only usable on the local machine,
    /// sftp:/// urls when the server is only bound to localhost are only
    /// usable from localhost etc.
    ///
    /// NOTE: This method may remove security wrappers (e.g. on chroot
    /// transports) and thus should *only* be used when the result will not
    /// be used to obtain a new transport within breezy. Ideally chroot
    /// transports would know enough to cause the external url to be the exact
    /// one used that caused the chrooting in the first place, but that is not
    /// currently the case.
    ///
    /// Returns: A URL that can be given to another process.
    /// Raises:InProcessTransport: If the transport is one that cannot be
    ///     accessed out of the current process (e.g. a MemoryTransport)
    ///     then InProcessTransport is raised.
    fn external_url(&self) -> Result<Url>;

    fn can_roundtrip_unix_modebits(&self) -> bool;

    fn get_bytes(&self, relpath: &UrlFragment) -> Result<Vec<u8>> {
        let mut file = self.get(relpath)?;
        let mut result = Vec::new();
        file.read_to_end(&mut result)
            .map_err(|err| map_io_err_to_transport_err(err, Some(relpath)))?;
        Ok(result)
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>>;

    fn base(&self) -> Url;

    /// Ensure that the directory this transport references exists.
    ///
    /// This will create a directory if it doesn't exist.
    /// Returns: True if the directory was created, False otherwise.
    fn ensure_base(&self, permissions: Option<Permissions>) -> Result<bool> {
        if let Err(err) = self.mkdir(".", permissions) {
            match err {
                Error::FileExists(_) => Ok(false),
                Error::PermissionDenied(_) => Ok(false),
                Error::TransportNotPossible(_) => {
                    if self.has(".")? {
                        Ok(false)
                    } else {
                        Err(err)
                    }
                }
                _ => Err(err),
            }
        } else {
            Ok(true)
        }
    }

    fn create_prefix(&self, permissions: Option<Permissions>) -> Result<()> {
        let mut cur_transport = self.clone(None)?;
        let mut needed = vec![];
        loop {
            match cur_transport.mkdir(".", permissions.clone()) {
                Err(Error::NoSuchFile(_)) => {
                    let new_transport = Transport::clone(cur_transport.as_ref(), Some(".."))?;
                    assert_ne!(
                        new_transport.base(),
                        cur_transport.base(),
                        "Failed to create path prefix for {}",
                        cur_transport.base()
                    );
                    needed.push(cur_transport);
                    cur_transport = new_transport;
                }
                Err(Error::FileExists(_)) | Ok(()) => {
                    break;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        while let Some(transport) = needed.pop() {
            transport.ensure_base(permissions.clone())?;
        }

        Ok(())
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool>;

    fn has_any(&self, relpaths: &[&UrlFragment]) -> Result<bool> {
        for relpath in relpaths {
            if self.has(relpath)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn mkdir(&self, relpath: &UrlFragment, permissions: Option<Permissions>) -> Result<()>;

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat>;

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>>;

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url>;

    fn relpath(&self, abspath: &Url) -> Result<String>;

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64>;

    fn put_bytes(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<()> {
        let mut f = std::io::Cursor::new(data);
        self.put_file(relpath, &mut f, permissions)?;
        Ok(())
    }

    fn put_file_non_atomic(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        match self.put_file(relpath, f, permissions.clone()) {
            Ok(_) => Ok(()),
            Err(Error::NoSuchFile(filename)) => {
                if create_parent_dir.unwrap_or(false) {
                    if let Some(parent) = relpath.rsplit_once('/').map(|x| x.0) {
                        self.mkdir(parent, dir_permissions)?;
                        self.put_file(relpath, f, permissions)?;
                        Ok(())
                    } else {
                        Err(Error::NoSuchFile(filename))
                    }
                } else {
                    Err(Error::NoSuchFile(filename))
                }
            }
            Err(err) => Err(err),
        }
    }

    fn put_bytes_non_atomic(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        let mut f = std::io::Cursor::new(data);
        self.put_file_non_atomic(
            relpath,
            &mut f,
            permissions,
            create_parent_dir,
            dir_permissions,
        )
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()>;

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()>;

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()>;

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()>;

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>>;

    /// Return the recommended page size for this transport.
    ///
    /// This is potentially different for every path in a given namespace.
    /// For example, local transports might use an operating system call to
    /// get the block size for a given path, which can vary due to mount
    /// points.
    ///
    /// Returns: The page size in bytes.
    fn recommended_page_size(&self) -> usize {
        4 * 1024
    }

    fn is_readonly(&self) -> bool {
        false
    }

    fn readv<'a>(
        &self,
        relpath: &'a UrlFragment,
        offsets: Vec<(u64, usize)>,
        adjust_for_latency: bool,
        upper_limit: Option<u64>,
    ) -> Box<dyn Iterator<Item = Result<(u64, Vec<u8>)>> + Send + 'a> {
        let offsets = if adjust_for_latency {
            crate::readv::sort_expand_and_combine(
                offsets,
                upper_limit,
                self.recommended_page_size(),
            )
        } else {
            offsets
        };
        let buf = match self.get_bytes(relpath) {
            Err(err) => return Box::new(std::iter::once(Err(err))),
            Ok(file) => file,
        };
        let mut file = std::io::Cursor::new(buf);
        Box::new(
            offsets
                .into_iter()
                .map(move |(offset, length)| -> Result<(u64, Vec<u8>)> {
                    let mut buf = vec![0; length];
                    match file.seek(std::io::SeekFrom::Start(offset)) {
                        Ok(_) => {}
                        Err(err) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof => {
                                return Err(Error::ShortReadvError(
                                    relpath.to_owned(),
                                    offset,
                                    length as u64,
                                    file.position().saturating_sub(offset),
                                ))
                            }
                            _ => return Err(map_io_err_to_transport_err(err, Some(relpath))),
                        },
                    }
                    match file.read_exact(&mut buf) {
                        Ok(_) => Ok((offset, buf)),
                        Err(err) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof => Err(Error::ShortReadvError(
                                relpath.to_owned(),
                                offset,
                                length as u64,
                                file.position().saturating_sub(offset),
                            )),
                            _ => Err(map_io_err_to_transport_err(err, Some(relpath))),
                        },
                    }
                }),
        )
    }

    fn append_bytes(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let mut f = std::io::Cursor::new(data);
        self.append_file(relpath, &mut f, permissions)
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64>;

    fn readlink(&self, relpath: &UrlFragment) -> Result<String>;

    fn hardlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()>;

    fn symlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()>;

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>>;

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>>;

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()>;

    /// Move an entry, overwriting the destination if it exists.
    ///
    /// Mirrors Python's Transport.move default: delegates to copy/copy_tree
    /// then delete/delete_tree, which handles overwrite via copy's
    /// replace-on-write semantics. Transports with a native atomic move
    /// should override.
    fn r#move(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        if self.stat(rel_from)?.is_dir() {
            self.copy_tree(rel_from, rel_to)?;
            self.delete_tree(rel_from)?;
        } else {
            self.copy(rel_from, rel_to)?;
            self.delete(rel_from)?;
        }
        Ok(())
    }

    fn copy_tree(&self, from_relpath: &UrlFragment, to_relpath: &UrlFragment) -> Result<()> {
        let source = self.clone(Some(from_relpath))?;
        let target = self.clone(Some(to_relpath))?;

        // create target directory with the same rwx bits as source
        // use umask to ensure bits other than rwx are ignored
        let stat = self.stat(from_relpath)?;
        #[cfg(unix)]
        let perms = Some(Permissions::from_mode(stat.mode));
        #[cfg(not(unix))]
        let perms: Option<Permissions> = {
            let _ = stat;
            None
        };
        target.mkdir(".", perms)?;
        source.copy_tree_to_transport(target.as_ref())?;
        Ok(())
    }

    fn copy_tree_to_transport(&self, to_transport: &dyn Transport) -> Result<()> {
        let mut files = Vec::new();
        let mut directories = vec![".".to_string()];
        while let Some(dir) = directories.pop() {
            if dir != "." {
                to_transport.mkdir(dir.as_str(), None)?;
            }
            for entry in self.list_dir(dir.as_str()) {
                let entry = entry?;
                let full_path = format!("{}/{}", dir, entry);
                let stat = self.stat(&full_path)?;
                if stat.is_dir() {
                    directories.push(full_path);
                } else {
                    files.push(full_path);
                }
            }
        }
        self.copy_to(
            files
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<_>>()
                .as_slice(),
            to_transport,
            None,
        )?;
        Ok(())
    }

    fn copy_to(
        &self,
        relpaths: &[&UrlFragment],
        to_transport: &dyn Transport,
        permissions: Option<Permissions>,
    ) -> Result<usize> {
        copy_to(self, to_transport, relpaths, permissions)
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>>;

    fn listable(&self) -> bool {
        true
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>>;

    fn lock_write(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>>;

    fn local_abspath(&self, relpath: &UrlFragment) -> Result<std::path::PathBuf>;

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()>;
}

/// Transport that connects to a remote server.
///
/// Provides a common shape for transports that need to expose their
/// connection endpoint (host, port, credentials) so higher-level code
/// can reason about connection sharing — notably
/// `get_transport_from_url(possible_transports=…)`, which walks existing
/// transports looking for one that already talks to the same origin.
///
/// The default implementations all parse `Transport::base()` via the
/// `connected_url_*` helpers below, so concrete transports rarely need
/// to override anything; declaring `impl ConnectedTransport for MyT {}`
/// is usually enough.
pub trait ConnectedTransport: Transport {
    fn scheme(&self) -> String {
        connected_url_scheme(&self.base())
    }

    fn host(&self) -> Option<String> {
        connected_url_host(&self.base())
    }

    fn port(&self) -> Option<u16> {
        connected_url_port(&self.base())
    }

    fn user(&self) -> Option<String> {
        connected_url_user(&self.base())
    }

    fn password(&self) -> Option<String> {
        connected_url_password(&self.base())
    }

    fn path(&self) -> String {
        connected_url_path(&self.base())
    }

    /// Drop any cached connection state. Default no-op — transports
    /// with an explicit connection handle (SSH sessions, SFTP
    /// channels) override this to tear it down.
    fn disconnect(&self) -> Result<()> {
        Ok(())
    }
}

/// URL scheme (`"http"`, `"https"`, `"sftp"`, …).
pub fn connected_url_scheme(url: &Url) -> String {
    url.scheme().to_string()
}

/// Host portion of the URL, or `None` for URLs without a host
/// component (e.g. `file:///`).
pub fn connected_url_host(url: &Url) -> Option<String> {
    url.host_str().map(|s| s.to_string())
}

/// TCP port if explicitly present in the URL. Callers that want the
/// default port for the scheme should fall back themselves.
pub fn connected_url_port(url: &Url) -> Option<u16> {
    url.port()
}

/// URL-decoded username, or `None` if the URL has no userinfo.
pub fn connected_url_user(url: &Url) -> Option<String> {
    let raw = url.username();
    if raw.is_empty() {
        return None;
    }
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// URL-decoded password, or `None` if the URL has no password.
pub fn connected_url_password(url: &Url) -> Option<String> {
    let raw = url.password()?;
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// Path portion of the URL (always starts with `/`).
pub fn connected_url_path(url: &Url) -> String {
    url.path().to_string()
}

/// Result of comparing a connected transport's base URL against
/// another URL. Drives the `_reuse_for` / connection-pooling logic.
#[derive(Debug, PartialEq, Eq)]
pub enum ReuseMatch {
    /// `other_base` addresses the same origin and the same path as
    /// the base URL — callers return `self` unchanged.
    Same,
    /// `other_base` addresses the same origin but a different path.
    /// Callers construct a sibling transport at `other_base` sharing
    /// this transport's connection state.
    Sibling,
    /// Different origin (or unparseable URL). No reuse possible.
    None,
}

/// Decide whether a transport at `base` can be reused for
/// `other_base`. Pure function over URLs so the PyO3 layer and any
/// pure-Rust caller share the same comparison rules. An unparseable
/// `other_base` is treated as `None` rather than an error — reuse is
/// advisory and the caller will construct a fresh transport.
pub fn classify_reuse_for(base: &Url, other_base: &str) -> ReuseMatch {
    let other = match Url::parse(other_base) {
        Ok(u) => u,
        Err(_) => return ReuseMatch::None,
    };
    // Compare against the unqualified form of `other`'s scheme so
    // `http+urllib://` and `http://` are treated as equivalent for
    // reuse purposes — they'd produce the same underlying transport.
    let other_scheme = connected_url_scheme(&other);
    let other_scheme_unqualified = other_scheme
        .split_once('+')
        .map(|(s, _)| s.to_string())
        .unwrap_or(other_scheme);
    if connected_url_scheme(base) != other_scheme_unqualified
        || connected_url_host(base) != connected_url_host(&other)
        || connected_url_port(base) != connected_url_port(&other)
        || connected_url_user(base) != connected_url_user(&other)
    {
        return ReuseMatch::None;
    }
    // Normalise trailing slash so `/foo` and `/foo/` compare equal —
    // `get_transport_from_url` can see either form from caller input.
    let ensure_slash = |mut s: String| {
        if !s.ends_with('/') {
            s.push('/');
        }
        s
    };
    let self_path = ensure_slash(base.path().to_string());
    let other_path = ensure_slash(other.path().to_string());
    if self_path == other_path {
        ReuseMatch::Same
    } else {
        ReuseMatch::Sibling
    }
}

pub fn copy_to<T: Transport + ?Sized>(
    from_transport: &T,
    to_transport: &dyn Transport,
    relpaths: &[&UrlFragment],
    permissions: Option<Permissions>,
) -> Result<usize> {
    let mut count = 0;
    relpaths.iter().try_for_each(|relpath| -> Result<()> {
        let mut src = from_transport.get(relpath)?;
        let mut target = to_transport.open_write_stream(relpath, permissions.clone())?;
        std::io::copy(&mut src, &mut target)
            .map_err(|e| map_io_err_to_transport_err(e, Some(relpath)))?;
        count += 1;
        Ok(())
    })?;
    Ok(count)
}

pub mod local;

pub mod brokenrename;

pub mod chroot;

pub mod decorator;

pub mod fakenfs;

pub mod fakevfat;

#[cfg(feature = "gio")]
pub mod gio;

pub mod http;

#[cfg(feature = "webdav")]
pub mod webdav;

pub mod log;

pub mod memory;

pub mod pathfilter;

pub mod readonly;

pub mod ssh;

#[cfg(feature = "sftp")]
pub mod sftp;

pub mod registry;

pub mod unlistable;

pub mod osutils;

#[cfg(feature = "pyo3")]
pub mod pyo3;
pub mod readv;

#[cfg(unix)]
#[path = "fcntl-locks.rs"]
pub mod filelock;

#[cfg(target_os = "windows")]
#[path = "win32-locks.rs"]
pub mod filelock;

pub mod lock;

pub mod urlutils;
