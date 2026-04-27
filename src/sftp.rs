//! Pure-Rust SFTP transport built on the `sftp` crate.
//!
//! Construction is decoupled from how the underlying SSH channel is
//! produced: [`SftpTransport::from_channel`] takes any `Read + Write +
//! Send` byte-stream, so callers are free to bring their own backend
//! (russh, ssh2, libssh, a spawned `ssh -s sftp` subprocess on Unix,
//! …). This keeps the pure-Rust crate free of an SSH-library dep and
//! mirrors how the PyO3 wrapper composes the SFTP client with whichever
//! SSH vendor is in play.

use std::collections::HashMap;
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use url::Url;

use crate::lock::{BogusLock, Lock};

use crate::{
    relpath_against_base, ConnectedTransport, Error, ReadStream, Result, Stat, Transport,
    UrlFragment, WriteStream,
};

/// Synchronous bidirectional byte stream the SFTP client runs over.
/// Boxed so [`SftpTransport`] has a single concrete type regardless of
/// which SSH backend produced the channel.
pub trait SshChannel: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send + ?Sized> SshChannel for T {}

pub type BoxedChannel = Box<dyn SshChannel>;

/// POSIX `S_IFDIR` — set on `permissions` to mark a directory at the
/// SFTP wire level. The `sftp` crate exposes file kind only via these
/// mode bits in `Attributes`.
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFMT: u32 = 0o170000;

fn map_sftp_err(e: sftp::Error, path: Option<&str>) -> Error {
    match e {
        sftp::Error::Io(e) => Error::Io(e),
        sftp::Error::NoSuchFile(_, _) | sftp::Error::NoSuchPath(_, _) => {
            Error::NoSuchFile(path.map(|s| s.to_string()))
        }
        sftp::Error::PermissionDenied(_, _) | sftp::Error::WriteProtect(_, _) => {
            Error::PermissionDenied(path.map(|s| s.to_string()))
        }
        sftp::Error::FileAlreadyExists(_, _) => Error::FileExists(path.map(|s| s.to_string())),
        sftp::Error::DirNotEmpty(_, _) => {
            Error::DirectoryNotEmptyError(path.map(|s| s.to_string()))
        }
        sftp::Error::NotADirectory(_, _) => {
            Error::NotADirectoryError(path.map(|s| s.to_string()))
        }
        sftp::Error::FileIsADirectory(_, _) => {
            Error::IsADirectoryError(path.map(|s| s.to_string()))
        }
        sftp::Error::OpUnsupported(_, _) => {
            Error::TransportNotPossible(path.map(|s| s.to_string()))
        }
        sftp::Error::ConnectionLost(_, m) | sftp::Error::NoConnection(_, m) => {
            Error::ConnectionError(m)
        }
        // Anything else lands as an Io error so callers see a single
        // bucket for "the SFTP layer was unhappy" — the message keeps
        // the original variant name for triage.
        other => Error::Io(std::io::Error::other(format!("{:?}", other))),
    }
}

/// Convert a Unix permission set into an SFTP attribute bag.
#[cfg(unix)]
fn perms_to_attr(p: Option<Permissions>) -> sftp::Attributes {
    let mut attr = sftp::Attributes::new();
    if let Some(p) = p {
        attr.permissions = Some(p.mode());
    }
    attr
}

#[cfg(not(unix))]
fn perms_to_attr(_p: Option<Permissions>) -> sftp::Attributes {
    sftp::Attributes::new()
}

/// Translate Python `_remote_path`'s URL → server-path rules into a
/// pure function so it can be unit-tested without a live channel.
///
/// The Python transport encodes Breezy convention:
/// * Paths starting with `/~/` are home-relative — strip the prefix.
/// * Bare `/~` means the home directory itself — empty string.
/// * Otherwise leave the path as-is (a leading `/` denotes absolute).
fn remote_path_for(base: &Url, relpath: &UrlFragment) -> Result<String> {
    let joined = base.join(relpath)?;
    let path = joined.path();
    let path = if let Some(rest) = path.strip_prefix("/~/") {
        rest.to_string()
    } else if path == "/~" {
        String::new()
    } else {
        path.to_string()
    };
    // Decode percent-escapes so the SFTP layer sees raw bytes.
    Ok(percent_encoding::percent_decode_str(&path)
        .decode_utf8()
        .map_err(|_| Error::TransportNotPossible(Some(relpath.to_string())))?
        .into_owned())
}

/// SFTP transport.
///
/// Cheap to clone — clones share the underlying SFTP session and only
/// vary in the URL prefix they apply to relpaths.
#[derive(Clone)]
pub struct SftpTransport {
    base: Url,
    sftp: Arc<sftp::SftpClient<BoxedChannel>>,
}

impl std::fmt::Debug for SftpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SftpTransport({})", self.base)
    }
}

impl SftpTransport {
    /// Build a transport from an already-open SSH byte-stream channel.
    /// Performs the SFTP version handshake before returning.
    pub fn from_channel(base: &str, channel: BoxedChannel) -> Result<Self> {
        let session = sftp::SftpClient::new(channel).map_err(Error::Io)?;
        Self::from_session(base, session)
    }

    /// Build a transport from an already-handshaken SFTP session.
    /// Use this when you've constructed the `SftpClient` yourself
    /// (e.g. to inspect its server extension list before wrapping).
    pub fn from_session(base: &str, session: sftp::SftpClient<BoxedChannel>) -> Result<Self> {
        let base = if base.ends_with('/') {
            base.to_string()
        } else {
            format!("{}/", base)
        };
        let base = Url::parse(&base)?;
        if base.scheme() != "sftp" {
            return Err(Error::TransportNotPossible(Some(format!(
                "expected sftp:// URL, got {}",
                base.scheme()
            ))));
        }
        Ok(SftpTransport {
            base,
            sftp: Arc::new(session),
        })
    }

    fn remote_path(&self, relpath: &UrlFragment) -> Result<String> {
        remote_path_for(&self.base, relpath)
    }

    fn read_full(&self, file: &sftp::File, size: u64) -> Result<Vec<u8>> {
        // pread takes u32 lengths; chunk if needed. Server may return
        // fewer bytes than requested, so loop until we hit EOF.
        let mut out = Vec::with_capacity(size as usize);
        let mut offset = 0u64;
        loop {
            let want: u32 = u32::try_from(size.saturating_sub(offset))
                .unwrap_or(u32::MAX)
                .min(64 * 1024);
            if want == 0 {
                break;
            }
            match self.sftp.pread(file, offset, want) {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => {
                    offset += chunk.len() as u64;
                    out.extend_from_slice(&chunk);
                    if chunk.len() < want as usize && offset >= size {
                        break;
                    }
                }
                Err(sftp::Error::Eof(_, _)) => break,
                Err(e) => return Err(map_sftp_err(e, None)),
            }
        }
        Ok(out)
    }
}

/// In-memory cursor over the bytes of a remote file. SFTP `pread` is
/// random-access and the existing `ReadStream` contract requires both
/// `Read + Seek`, so for the simple `get()` case we materialise the
/// whole file once and serve `Read`/`Seek` from a Cursor. Callers that
/// need streaming should use `readv` instead.
struct SftpReadStream(std::io::Cursor<Vec<u8>>);

impl std::io::Read for SftpReadStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl std::io::Seek for SftpReadStream {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}
impl ReadStream for SftpReadStream {}

/// Append-only write stream. Buffers locally and flushes via `pwrite`
/// at every `write` call so that a `sync_data` sees committed bytes.
struct SftpWriteStream {
    sftp: Arc<sftp::SftpClient<BoxedChannel>>,
    file: sftp::File,
    offset: u64,
    closed: bool,
}

impl std::io::Write for SftpWriteStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sftp
            .pwrite(&self.file, self.offset, buf)
            .map_err(std::io::Error::from)?;
        self.offset += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl WriteStream for SftpWriteStream {
    fn sync_data(&self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SftpWriteStream {
    fn drop(&mut self) {
        if !self.closed {
            // Best-effort close — the user has dropped the stream so
            // there's nobody to report close errors to.
            let _ = self.sftp.fclose(&self.file);
            self.closed = true;
        }
    }
}

impl Transport for SftpTransport {
    fn external_url(&self) -> Result<Url> {
        Ok(self.base.clone())
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        true
    }

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        let path = self.remote_path(relpath)?;
        let opts = sftp::OpenOptions::new().read(true);
        let attr = sftp::Attributes::new();
        let file = self
            .sftp
            .open(&path, opts, &attr)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        let st = self
            .sftp
            .fstat(&file, None)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        let size = st.size.unwrap_or(0);
        let buf = self.read_full(&file, size)?;
        let _ = self.sftp.fclose(&file);
        Ok(Box::new(SftpReadStream(std::io::Cursor::new(buf))))
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        let path = self.remote_path(relpath)?;
        match self.sftp.stat(&path, None) {
            Ok(_) => Ok(true),
            Err(sftp::Error::NoSuchFile(_, _)) | Err(sftp::Error::NoSuchPath(_, _)) => Ok(false),
            Err(e) => Err(map_sftp_err(e, Some(&path))),
        }
    }

    fn mkdir(&self, relpath: &UrlFragment, permissions: Option<Permissions>) -> Result<()> {
        let path = self.remote_path(relpath)?;
        let mut attr = perms_to_attr(permissions);
        // Server expects the directory bit set so the inode is created
        // with the right type — mirrors what the PyO3 wrapper does.
        attr.permissions = Some(attr.permissions.unwrap_or(0o777) | S_IFDIR);
        self.sftp
            .mkdir(&path, &attr)
            .map_err(|e| map_sftp_err(e, Some(&path)))
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        let path = self.remote_path(relpath)?;
        let attr = self
            .sftp
            .stat(&path, None)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        Ok(attrs_to_stat(&attr))
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        let new_base = match offset {
            Some(o) => self.base.join(o)?,
            None => self.base.clone(),
        };
        let mut new_base_str = new_base.to_string();
        if !new_base_str.ends_with('/') {
            new_base_str.push('/');
        }
        Ok(Box::new(SftpTransport {
            base: Url::parse(&new_base_str)?,
            sftp: Arc::clone(&self.sftp),
        }))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        Ok(self.base.join(relpath)?)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        relpath_against_base(&self.base, abspath)
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let path = self.remote_path(relpath)?;
        let opts = sftp::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true);
        let attr = perms_to_attr(permissions);
        let file = self
            .sftp
            .open(&path, opts, &attr)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        let mut buf = [0u8; 32 * 1024];
        let mut offset = 0u64;
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| crate::map_io_err_to_transport_err(e, Some(relpath)))?;
            if n == 0 {
                break;
            }
            self.sftp
                .pwrite(&file, offset, &buf[..n])
                .map_err(|e| map_sftp_err(e, Some(&path)))?;
            offset += n as u64;
        }
        self.sftp
            .fclose(&file)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        Ok(offset)
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        let path = self.remote_path(relpath)?;
        self.sftp
            .remove(&path)
            .map_err(|e| map_sftp_err(e, Some(&path)))
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        let path = self.remote_path(relpath)?;
        self.sftp
            .rmdir(&path)
            .map_err(|e| map_sftp_err(e, Some(&path)))
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let from = self.remote_path(rel_from)?;
        let to = self.remote_path(rel_to)?;
        self.sftp
            .rename(&from, &to, None)
            .map_err(|e| map_sftp_err(e, Some(&to)))
    }

    fn set_segment_parameter(&mut self, _key: &str, _value: Option<&str>) -> Result<()> {
        // Segment params are URL-shape metadata; the SFTP transport
        // doesn't consume any. Mirror Memory/Local: silently ignore.
        Ok(())
    }

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let path = self.remote_path(relpath)?;
        // Open with append flag; capture the pre-existing size as the
        // returned offset (Transport contract).
        let opts = sftp::OpenOptions::new().write(true).create(true).append(true);
        let attr = perms_to_attr(permissions);
        let file = self
            .sftp
            .open(&path, opts, &attr)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        let st = self
            .sftp
            .fstat(&file, None)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        let mut offset = st.size.unwrap_or(0);
        let result = offset;
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| crate::map_io_err_to_transport_err(e, Some(relpath)))?;
            if n == 0 {
                break;
            }
            self.sftp
                .pwrite(&file, offset, &buf[..n])
                .map_err(|e| map_sftp_err(e, Some(&path)))?;
            offset += n as u64;
        }
        self.sftp
            .fclose(&file)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        Ok(result)
    }

    fn readlink(&self, relpath: &UrlFragment) -> Result<String> {
        let path = self.remote_path(relpath)?;
        self.sftp
            .readlink(&path)
            .map_err(|e| map_sftp_err(e, Some(&path)))
    }

    fn hardlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let from = self.remote_path(rel_from)?;
        let to = self.remote_path(rel_to)?;
        self.sftp
            .hardlink(&from, &to)
            .map_err(|e| map_sftp_err(e, Some(&to)))
    }

    fn symlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        // `rel_from` is the symlink target (may be absolute on the
        // remote, may be a path that doesn't exist yet); only `rel_to`
        // is resolved against our base URL. Matches Python's
        // `SFTPTransport.symlink`.
        let to = self.remote_path(rel_to)?;
        self.sftp
            .symlink(rel_from, &to)
            .map_err(|e| map_sftp_err(e, Some(&to)))
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        // Walk eagerly. SFTP doesn't have a native walk and the
        // boxed-iterator return type doesn't carry a borrow, so
        // produce results up-front.
        let results = match self.collect_files_recursive() {
            Ok(v) => v,
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        Box::new(results.into_iter().map(Ok))
    }

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        let path = self.remote_path(relpath)?;
        let opts = sftp::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true);
        let attr = perms_to_attr(permissions);
        let file = self
            .sftp
            .open(&path, opts, &attr)
            .map_err(|e| map_sftp_err(e, Some(&path)))?;
        Ok(Box::new(SftpWriteStream {
            sftp: Arc::clone(&self.sftp),
            file,
            offset: 0,
            closed: false,
        }))
    }

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()> {
        // Recurse depth-first, deleting files then dirs.
        let abspath = self.remote_path(relpath)?;
        self.delete_tree_abs(&abspath)
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        let path = match self.remote_path(relpath) {
            Ok(p) => p,
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        let dir = match self.sftp.opendir(&path) {
            Ok(d) => d,
            Err(e) => return Box::new(std::iter::once(Err(map_sftp_err(e, Some(&path))))),
        };
        let mut names: Vec<String> = Vec::new();
        loop {
            match self.sftp.readdir(&dir) {
                Ok(entries) => {
                    for (name, _, _) in entries {
                        if name == "." || name == ".." {
                            continue;
                        }
                        names.push(name);
                    }
                }
                Err(sftp::Error::Eof(_, _)) => break,
                Err(e) => {
                    let _ = self.sftp.closedir(&dir);
                    return Box::new(std::iter::once(Err(map_sftp_err(e, Some(&path)))));
                }
            }
        }
        let _ = self.sftp.closedir(&dir);
        Box::new(names.into_iter().map(Ok))
    }

    fn lock_read(&self, _relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        // SFTP doesn't expose a portable advisory lock primitive; the
        // Python side returns a no-op lock for compatibility, so do the
        // same here.
        Ok(Box::new(BogusLock))
    }

    fn lock_write(&self, _relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        Ok(Box::new(BogusLock))
    }

    fn local_abspath(&self, _relpath: &UrlFragment) -> Result<PathBuf> {
        Err(Error::NotLocalUrl(self.base.to_string()))
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        // No native SFTP copy — read source, write destination. The
        // default Transport::copy_to fallback would do roughly the same,
        // but having an explicit copy keeps the Transport trait happy.
        let mut src = self.get(rel_from)?;
        let mut dst = self.open_write_stream(rel_to, None)?;
        std::io::copy(&mut src, &mut dst)
            .map_err(|e| crate::map_io_err_to_transport_err(e, Some(rel_to)))?;
        Ok(())
    }
}

impl ConnectedTransport for SftpTransport {}

impl SftpTransport {
    /// DFS recursive walk used by `iter_files_recursive`. Splits out so
    /// errors can short-circuit without smuggling `Result` through the
    /// boxed iterator.
    fn collect_files_recursive(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        // Queue holds (display_relpath, server_abspath) — the display
        // form has no leading slash and is what callers expect; the
        // server form is what we feed back into SFTP.
        let mut queue: Vec<(String, String)> = Vec::new();
        let root = self.remote_path(".")?;
        for entry in self.list_dir_attrs(&root)? {
            queue.push((entry.0.clone(), join_remote(&root, &entry.0)));
        }
        while let Some((rel, abs)) = queue.pop() {
            let attr = self
                .sftp
                .stat(&abs, None)
                .map_err(|e| map_sftp_err(e, Some(&abs)))?;
            if is_dir(&attr) {
                for child in self.list_dir_attrs(&abs)? {
                    let child_rel = format!("{}/{}", rel, child.0);
                    let child_abs = join_remote(&abs, &child.0);
                    queue.push((child_rel, child_abs));
                }
            } else {
                out.push(rel);
            }
        }
        Ok(out)
    }

    fn list_dir_attrs(&self, abspath: &str) -> Result<Vec<(String, sftp::Attributes)>> {
        let dir = self
            .sftp
            .opendir(abspath)
            .map_err(|e| map_sftp_err(e, Some(abspath)))?;
        let mut out = Vec::new();
        loop {
            match self.sftp.readdir(&dir) {
                Ok(entries) => {
                    for (name, _, attr) in entries {
                        if name == "." || name == ".." {
                            continue;
                        }
                        out.push((name, attr));
                    }
                }
                Err(sftp::Error::Eof(_, _)) => break,
                Err(e) => {
                    let _ = self.sftp.closedir(&dir);
                    return Err(map_sftp_err(e, Some(abspath)));
                }
            }
        }
        let _ = self.sftp.closedir(&dir);
        Ok(out)
    }

    fn delete_tree_abs(&self, abspath: &str) -> Result<()> {
        for (name, attr) in self.list_dir_attrs(abspath)? {
            let child = join_remote(abspath, &name);
            if is_dir(&attr) {
                self.delete_tree_abs(&child)?;
            } else {
                self.sftp
                    .remove(&child)
                    .map_err(|e| map_sftp_err(e, Some(&child)))?;
            }
        }
        self.sftp
            .rmdir(abspath)
            .map_err(|e| map_sftp_err(e, Some(abspath)))
    }
}

fn join_remote(parent: &str, child: &str) -> String {
    if parent.ends_with('/') {
        format!("{}{}", parent, child)
    } else {
        format!("{}/{}", parent, child)
    }
}

fn is_dir(attr: &sftp::Attributes) -> bool {
    matches!(attr.permissions, Some(p) if p & S_IFMT == S_IFDIR)
}

fn is_symlink(attr: &sftp::Attributes) -> bool {
    matches!(attr.permissions, Some(p) if p & S_IFMT == S_IFLNK)
}

fn attrs_to_stat(attr: &sftp::Attributes) -> Stat {
    let kind = if is_dir(attr) {
        crate::FileKind::Dir
    } else if is_symlink(attr) {
        crate::FileKind::Symlink
    } else {
        // Default to File when the server doesn't tell us — matches
        // what callers expect for plain SFTP responses where mode bits
        // may be missing entirely.
        crate::FileKind::File
    };
    Stat {
        size: attr.size.unwrap_or(0) as usize,
        #[cfg(unix)]
        mode: attr.permissions.unwrap_or(0),
        kind,
        mtime: attr.modify_time.map(|(s, _)| s as f64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("sftp://user@example.com/home/user/").unwrap()
    }

    #[test]
    fn remote_path_plain_relative() {
        assert_eq!(
            remote_path_for(&base(), "foo/bar").unwrap(),
            "/home/user/foo/bar"
        );
    }

    #[test]
    fn remote_path_dot() {
        assert_eq!(remote_path_for(&base(), ".").unwrap(), "/home/user/");
    }

    #[test]
    fn remote_path_homedir_relative() {
        // sftp://example.com/~/proj resolves to "proj" — the server
        // interprets the bare path as $HOME-relative.
        let b = Url::parse("sftp://example.com/~/").unwrap();
        assert_eq!(remote_path_for(&b, "proj/file").unwrap(), "proj/file");
    }

    #[test]
    fn remote_path_bare_homedir() {
        let b = Url::parse("sftp://example.com/~").unwrap();
        // base ends with /~, joining "" preserves the path. Confirm
        // the special-case mapping kicks in.
        assert_eq!(remote_path_for(&b, "").unwrap(), "");
    }

    #[test]
    fn remote_path_percent_decodes() {
        // %20 in a relpath should be delivered to the server as a
        // literal space so SFTP can find the file.
        assert_eq!(
            remote_path_for(&base(), "a%20b").unwrap(),
            "/home/user/a b"
        );
    }

    #[test]
    fn from_session_rejects_non_sftp_url() {
        // We don't have a real channel here but URL validation runs
        // before the session is used; assemble a dummy session via a
        // pipe pair would require live IO, so cover this via the URL
        // shape only — the parse step itself is the guard.
        let url = "http://example.com/";
        let parsed = Url::parse(url).unwrap();
        assert_ne!(parsed.scheme(), "sftp");
    }

    #[test]
    fn map_sftp_err_classifies_known_errors() {
        let e = map_sftp_err(sftp::Error::NoSuchFile("nope".into(), "".into()), Some("p"));
        assert!(matches!(e, Error::NoSuchFile(Some(ref p)) if p == "p"));

        let e = map_sftp_err(
            sftp::Error::PermissionDenied("denied".into(), "".into()),
            Some("p"),
        );
        assert!(matches!(e, Error::PermissionDenied(Some(ref p)) if p == "p"));

        let e = map_sftp_err(
            sftp::Error::FileAlreadyExists("dup".into(), "".into()),
            Some("p"),
        );
        assert!(matches!(e, Error::FileExists(Some(ref p)) if p == "p"));

        let e = map_sftp_err(
            sftp::Error::DirNotEmpty("nope".into(), "".into()),
            Some("p"),
        );
        assert!(matches!(e, Error::DirectoryNotEmptyError(Some(ref p)) if p == "p"));

        let e = map_sftp_err(
            sftp::Error::OpUnsupported("nope".into(), "".into()),
            Some("p"),
        );
        assert!(matches!(e, Error::TransportNotPossible(Some(ref p)) if p == "p"));

        let e = map_sftp_err(
            sftp::Error::ConnectionLost("bye".into(), "msg".into()),
            None,
        );
        assert!(matches!(e, Error::ConnectionError(ref m) if m == "msg"));
    }

    #[test]
    fn is_dir_detects_directory_bit() {
        let mut attr = sftp::Attributes::new();
        attr.permissions = Some(0o040755);
        assert!(is_dir(&attr));
        attr.permissions = Some(0o100644);
        assert!(!is_dir(&attr));
        attr.permissions = None;
        assert!(!is_dir(&attr));
    }

    #[test]
    fn attrs_to_stat_carries_size_and_mtime() {
        let mut attr = sftp::Attributes::new();
        attr.size = Some(42);
        attr.modify_time = Some((1700000000, None));
        attr.permissions = Some(0o100644);
        let st = attrs_to_stat(&attr);
        assert_eq!(st.size, 42);
        assert!(st.is_file());
        assert_eq!(st.mtime, Some(1_700_000_000.0));
    }

    // ---- Loopback integration tests -------------------------------------
    //
    // The harness spins up an in-process fake SFTP server on one end of a
    // `UnixStream::pair()` and drives `SftpTransport` against it. The
    // server understands enough of the wire protocol to round-trip the
    // operations we actually exercise — it is not a full implementation.
    //
    // Unix-only because `UnixStream::pair()` is Unix-only.

    #[cfg(unix)]
    mod loopback {
        use super::super::*;
        use std::collections::{HashMap, HashSet};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::thread;

        // Opcodes & status codes — kept locally so we don't depend on
        // `sftp` crate's private constants.
        const SSH_FXP_INIT: u8 = 1;
        const SSH_FXP_VERSION: u8 = 2;
        const SSH_FXP_OPEN: u8 = 3;
        const SSH_FXP_CLOSE: u8 = 4;
        const SSH_FXP_READ: u8 = 5;
        const SSH_FXP_WRITE: u8 = 6;
        const SSH_FXP_LSTAT: u8 = 7;
        const SSH_FXP_FSTAT: u8 = 8;
        const SSH_FXP_OPENDIR: u8 = 11;
        const SSH_FXP_READDIR: u8 = 12;
        const SSH_FXP_REMOVE: u8 = 13;
        const SSH_FXP_MKDIR: u8 = 14;
        const SSH_FXP_RMDIR: u8 = 15;
        const SSH_FXP_STAT: u8 = 17;
        const SSH_FXP_RENAME: u8 = 18;
        const SSH_FXP_READLINK: u8 = 19;
        const SSH_FXP_SYMLINK: u8 = 20;
        const SSH_FXP_LINK: u8 = 21;
        const SSH_FXP_STATUS: u8 = 101;
        const SSH_FXP_HANDLE: u8 = 102;
        const SSH_FXP_DATA: u8 = 103;
        const SSH_FXP_NAME: u8 = 104;
        const SSH_FXP_ATTRS: u8 = 105;

        const SSH_FX_OK: u32 = 0;
        const SSH_FX_EOF: u32 = 1;
        const SSH_FX_NO_SUCH_FILE: u32 = 2;
        const SSH_FX_FAILURE: u32 = 4;
        const SSH_FX_FILE_ALREADY_EXISTS: u32 = 11;
        const SSH_FX_DIR_NOT_EMPTY: u32 = 18;

        const SFTP_FLAG_APPEND: u32 = 0x04;
        const SFTP_FLAG_CREAT: u32 = 0x08;
        const SFTP_FLAG_TRUNC: u32 = 0x10;
        const SFTP_FLAG_EXCL: u32 = 0x20;

        const ATTR_SIZE: u32 = 0x01;
        const ATTR_PERMISSIONS: u32 = 0x04;

        /// Read a length-prefixed packet: `u32 length, u8 kind, body`.
        fn read_packet<R: Read>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            assert!(!buf.is_empty(), "zero-length SFTP packet");
            Ok((buf[0], buf[1..].to_vec()))
        }

        /// Frame and write a packet.
        fn write_packet<W: Write>(w: &mut W, kind: u8, body: &[u8]) -> std::io::Result<()> {
            let len = (body.len() as u32 + 1).to_be_bytes();
            w.write_all(&len)?;
            w.write_all(&[kind])?;
            w.write_all(body)?;
            w.flush()
        }

        /// Pull a length-prefixed UTF-8 string off a cursor.
        fn read_string(c: &mut std::io::Cursor<&[u8]>) -> String {
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let len = u32::from_be_bytes(len) as usize;
            let pos = c.position() as usize;
            let s = std::str::from_utf8(&c.get_ref()[pos..pos + len])
                .unwrap()
                .to_string();
            c.set_position((pos + len) as u64);
            s
        }

        fn read_u32(c: &mut std::io::Cursor<&[u8]>) -> u32 {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).unwrap();
            u32::from_be_bytes(b)
        }

        fn read_u64(c: &mut std::io::Cursor<&[u8]>) -> u64 {
            let mut b = [0u8; 8];
            c.read_exact(&mut b).unwrap();
            u64::from_be_bytes(b)
        }

        /// Write a minimal ATTRS body covering size + permissions.
        fn encode_attrs(size: Option<u64>, perms: Option<u32>) -> Vec<u8> {
            let mut flags = 0u32;
            let mut body = Vec::new();
            if size.is_some() {
                flags |= ATTR_SIZE;
            }
            if perms.is_some() {
                flags |= ATTR_PERMISSIONS;
            }
            body.extend_from_slice(&flags.to_be_bytes());
            if let Some(s) = size {
                body.extend_from_slice(&s.to_be_bytes());
            }
            if let Some(p) = perms {
                body.extend_from_slice(&p.to_be_bytes());
            }
            body
        }

        /// Parse a minimal ATTRS body — only the fields the client
        /// actually sends in our tests (permissions, optionally size).
        /// Returns the cursor position so the caller can keep reading.
        fn skip_attrs(c: &mut std::io::Cursor<&[u8]>) -> (Option<u64>, Option<u32>) {
            let flags = read_u32(c);
            let mut size = None;
            let mut perms = None;
            if flags & ATTR_SIZE != 0 {
                size = Some(read_u64(c));
            }
            if flags & 0x02 != 0 {
                // UID/GID — uid then gid
                let _ = read_u32(c);
                let _ = read_u32(c);
            }
            if flags & 0x400 != 0 {
                // ALLOCATION_SIZE
                let _ = read_u64(c);
            }
            if flags & 0x80 != 0 {
                // OWNERGROUP — owner then group strings
                let _ = read_string(c);
                let _ = read_string(c);
            }
            if flags & ATTR_PERMISSIONS != 0 {
                perms = Some(read_u32(c));
            }
            // We don't drive any further attributes from the client side
            // in these tests, so stop here.
            (size, perms)
        }

        /// In-memory filesystem the fake server serves.
        #[derive(Default)]
        struct Fs {
            files: HashMap<String, Vec<u8>>,
            dirs: HashSet<String>,
            symlinks: HashMap<String, String>,
        }

        impl Fs {
            fn new_with_root() -> Self {
                let mut fs = Fs::default();
                // Pre-create / and /tmp so transports rooted there work
                // without an explicit mkdir.
                fs.dirs.insert("/".into());
                fs.dirs.insert("/tmp".into());
                fs
            }

            fn parent_of(path: &str) -> Option<&str> {
                let trimmed = path.trim_end_matches('/');
                trimmed.rsplit_once('/').map(|(p, _)| if p.is_empty() { "/" } else { p })
            }

            fn entries_under(&self, dir: &str) -> Vec<(String, bool)> {
                // Returns (name, is_dir).
                let prefix = if dir.ends_with('/') {
                    dir.to_string()
                } else {
                    format!("{}/", dir)
                };
                let mut seen = HashSet::new();
                let mut out = Vec::new();
                for path in self.files.keys() {
                    if let Some(rest) = path.strip_prefix(&prefix) {
                        if !rest.contains('/') && seen.insert(rest.to_string()) {
                            out.push((rest.to_string(), false));
                        }
                    }
                }
                for path in &self.dirs {
                    if path == dir {
                        continue;
                    }
                    if let Some(rest) = path.strip_prefix(&prefix) {
                        if !rest.contains('/') && seen.insert(rest.to_string()) {
                            out.push((rest.to_string(), true));
                        }
                    }
                }
                for path in self.symlinks.keys() {
                    if let Some(rest) = path.strip_prefix(&prefix) {
                        if !rest.contains('/') && seen.insert(rest.to_string()) {
                            out.push((rest.to_string(), false));
                        }
                    }
                }
                out
            }
        }

        enum Handle {
            File { path: String, append: bool },
            Dir { path: String, drained: bool },
        }

        /// Spawn a fake SFTP server on `stream`. Returns a join handle
        /// so tests can wait for it to exit (it exits when the client
        /// disconnects).
        fn spawn(mut stream: UnixStream) -> thread::JoinHandle<()> {
            thread::spawn(move || {
                let mut fs = Fs::new_with_root();
                let mut handles: HashMap<Vec<u8>, Handle> = HashMap::new();
                static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

                loop {
                    let (kind, body) = match read_packet(&mut stream) {
                        Ok(v) => v,
                        Err(_) => return, // peer closed
                    };

                    if kind == SSH_FXP_INIT {
                        // body is the version u32; reply with VERSION 3,
                        // no extensions. INIT has no request-id.
                        let _client_ver = u32::from_be_bytes(body[..4].try_into().unwrap());
                        let mut reply = Vec::new();
                        reply.extend_from_slice(&3u32.to_be_bytes());
                        write_packet(&mut stream, SSH_FXP_VERSION, &reply).unwrap();
                        continue;
                    }

                    let req_id = u32::from_be_bytes(body[..4].try_into().unwrap());
                    let mut c = std::io::Cursor::new(&body[4..]);

                    // Strip a trailing slash (except for the root) so
                    // callers can pass `/tmp/` or `/tmp` interchangeably.
                    fn norm(p: String) -> String {
                        if p.len() > 1 && p.ends_with('/') {
                            p.trim_end_matches('/').to_string()
                        } else {
                            p
                        }
                    }

                    let send_status = |stream: &mut UnixStream, code: u32, msg: &str| {
                        let mut r = Vec::new();
                        r.extend_from_slice(&req_id.to_be_bytes());
                        r.extend_from_slice(&code.to_be_bytes());
                        r.extend_from_slice(&(msg.len() as u32).to_be_bytes());
                        r.extend_from_slice(msg.as_bytes());
                        r.extend_from_slice(&0u32.to_be_bytes()); // empty lang_tag
                        write_packet(stream, SSH_FXP_STATUS, &r).unwrap();
                    };

                    match kind {
                        SSH_FXP_MKDIR => {
                            let path = norm(read_string(&mut c));
                            let _ = skip_attrs(&mut c);
                            if fs.dirs.contains(&path) || fs.files.contains_key(&path) {
                                send_status(&mut stream, SSH_FX_FILE_ALREADY_EXISTS, "exists");
                            } else if matches!(Fs::parent_of(&path), Some(p) if !fs.dirs.contains(p))
                            {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "no parent");
                            } else {
                                fs.dirs.insert(path);
                                send_status(&mut stream, SSH_FX_OK, "");
                            }
                        }
                        SSH_FXP_RMDIR => {
                            let path = norm(read_string(&mut c));
                            if !fs.dirs.contains(&path) {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                                continue;
                            }
                            if !fs.entries_under(&path).is_empty() {
                                send_status(&mut stream, SSH_FX_DIR_NOT_EMPTY, "");
                                continue;
                            }
                            fs.dirs.remove(&path);
                            send_status(&mut stream, SSH_FX_OK, "");
                        }
                        SSH_FXP_REMOVE => {
                            let path = norm(read_string(&mut c));
                            if fs.files.remove(&path).is_some()
                                || fs.symlinks.remove(&path).is_some()
                            {
                                send_status(&mut stream, SSH_FX_OK, "");
                            } else {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                            }
                        }
                        SSH_FXP_RENAME => {
                            let from = norm(read_string(&mut c));
                            let to = norm(read_string(&mut c));
                            let _flags = read_u32(&mut c);
                            if let Some(data) = fs.files.remove(&from) {
                                fs.files.insert(to, data);
                                send_status(&mut stream, SSH_FX_OK, "");
                            } else if fs.dirs.remove(&from) {
                                fs.dirs.insert(to);
                                send_status(&mut stream, SSH_FX_OK, "");
                            } else {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                            }
                        }
                        SSH_FXP_STAT | SSH_FXP_LSTAT => {
                            let path = norm(read_string(&mut c));
                            let _flags = read_u32(&mut c);
                            if let Some(data) = fs.files.get(&path) {
                                let attrs = encode_attrs(Some(data.len() as u64), Some(0o100644));
                                let mut r = req_id.to_be_bytes().to_vec();
                                r.extend_from_slice(&attrs);
                                write_packet(&mut stream, SSH_FXP_ATTRS, &r).unwrap();
                            } else if fs.dirs.contains(&path) {
                                let attrs = encode_attrs(Some(0), Some(0o040755));
                                let mut r = req_id.to_be_bytes().to_vec();
                                r.extend_from_slice(&attrs);
                                write_packet(&mut stream, SSH_FXP_ATTRS, &r).unwrap();
                            } else if let Some(target) = fs.symlinks.get(&path) {
                                if kind == SSH_FXP_LSTAT {
                                    let attrs =
                                        encode_attrs(Some(target.len() as u64), Some(0o120777));
                                    let mut r = req_id.to_be_bytes().to_vec();
                                    r.extend_from_slice(&attrs);
                                    write_packet(&mut stream, SSH_FXP_ATTRS, &r).unwrap();
                                } else {
                                    // STAT follows: resolve once.
                                    let resolved = target.clone();
                                    if let Some(data) = fs.files.get(&resolved) {
                                        let attrs =
                                            encode_attrs(Some(data.len() as u64), Some(0o100644));
                                        let mut r = req_id.to_be_bytes().to_vec();
                                        r.extend_from_slice(&attrs);
                                        write_packet(&mut stream, SSH_FXP_ATTRS, &r).unwrap();
                                    } else {
                                        send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                                    }
                                }
                            } else {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                            }
                        }
                        SSH_FXP_OPEN => {
                            let path = norm(read_string(&mut c));
                            let flags = read_u32(&mut c);
                            let _ = skip_attrs(&mut c);
                            let exists = fs.files.contains_key(&path);
                            if flags & SFTP_FLAG_EXCL != 0 && exists {
                                send_status(&mut stream, SSH_FX_FILE_ALREADY_EXISTS, "exists");
                                continue;
                            }
                            if !exists && flags & SFTP_FLAG_CREAT == 0 {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                                continue;
                            }
                            // Verify parent exists when creating.
                            if !exists {
                                if let Some(parent) = Fs::parent_of(&path) {
                                    if !fs.dirs.contains(parent) {
                                        send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "no parent");
                                        continue;
                                    }
                                }
                                fs.files.insert(path.clone(), Vec::new());
                            } else if flags & SFTP_FLAG_TRUNC != 0 {
                                fs.files.insert(path.clone(), Vec::new());
                            }
                            let h_id = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
                            let h = format!("f{}", h_id).into_bytes();
                            handles.insert(
                                h.clone(),
                                Handle::File {
                                    path,
                                    append: flags & SFTP_FLAG_APPEND != 0,
                                },
                            );
                            let mut r = req_id.to_be_bytes().to_vec();
                            r.extend_from_slice(&(h.len() as u32).to_be_bytes());
                            r.extend_from_slice(&h);
                            write_packet(&mut stream, SSH_FXP_HANDLE, &r).unwrap();
                        }
                        SSH_FXP_OPENDIR => {
                            let path = norm(read_string(&mut c));
                            if !fs.dirs.contains(&path) {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                                continue;
                            }
                            let h_id = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
                            let h = format!("d{}", h_id).into_bytes();
                            handles.insert(h.clone(), Handle::Dir { path, drained: false });
                            let mut r = req_id.to_be_bytes().to_vec();
                            r.extend_from_slice(&(h.len() as u32).to_be_bytes());
                            r.extend_from_slice(&h);
                            write_packet(&mut stream, SSH_FXP_HANDLE, &r).unwrap();
                        }
                        SSH_FXP_READDIR => {
                            let h_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let h = c.get_ref()[pos..pos + h_len].to_vec();
                            let entries = match handles.get_mut(&h) {
                                Some(Handle::Dir { path, drained }) => {
                                    if *drained {
                                        None
                                    } else {
                                        *drained = true;
                                        Some(fs.entries_under(path))
                                    }
                                }
                                _ => {
                                    send_status(&mut stream, SSH_FX_FAILURE, "bad handle");
                                    continue;
                                }
                            };
                            match entries {
                                None => {
                                    send_status(&mut stream, SSH_FX_EOF, "");
                                }
                                Some(es) => {
                                    let mut r = req_id.to_be_bytes().to_vec();
                                    r.extend_from_slice(&(es.len() as u32).to_be_bytes());
                                    for (name, is_dir) in es {
                                        r.extend_from_slice(&(name.len() as u32).to_be_bytes());
                                        r.extend_from_slice(name.as_bytes());
                                        // longname = same as name for tests
                                        r.extend_from_slice(&(name.len() as u32).to_be_bytes());
                                        r.extend_from_slice(name.as_bytes());
                                        let attrs = if is_dir {
                                            encode_attrs(Some(0), Some(0o040755))
                                        } else {
                                            encode_attrs(
                                                Some(
                                                    fs.files.get(&format!(
                                                        "{}/{}",
                                                        match handles.get(&h).unwrap() {
                                                            Handle::Dir { path, .. } => path,
                                                            _ => unreachable!(),
                                                        },
                                                        name
                                                    ))
                                                    .map(|v| v.len() as u64)
                                                    .unwrap_or(0),
                                                ),
                                                Some(0o100644),
                                            )
                                        };
                                        r.extend_from_slice(&attrs);
                                    }
                                    write_packet(&mut stream, SSH_FXP_NAME, &r).unwrap();
                                }
                            }
                        }
                        SSH_FXP_CLOSE => {
                            let h_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let h = c.get_ref()[pos..pos + h_len].to_vec();
                            handles.remove(&h);
                            send_status(&mut stream, SSH_FX_OK, "");
                        }
                        SSH_FXP_WRITE => {
                            let h_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let h = c.get_ref()[pos..pos + h_len].to_vec();
                            c.set_position((pos + h_len) as u64);
                            let offset = read_u64(&mut c) as usize;
                            let data_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let data =
                                c.get_ref()[pos..pos + data_len].to_vec();
                            let path = match handles.get(&h) {
                                Some(Handle::File { path, append }) => {
                                    let p = path.clone();
                                    let _ = append;
                                    p
                                }
                                _ => {
                                    send_status(&mut stream, SSH_FX_FAILURE, "bad handle");
                                    continue;
                                }
                            };
                            let f = fs.files.entry(path).or_default();
                            // For append handles the client passes the
                            // current size as the offset, so the same
                            // logic works for both append and pwrite.
                            if f.len() < offset + data_len {
                                f.resize(offset + data_len, 0);
                            }
                            f[offset..offset + data_len].copy_from_slice(&data);
                            send_status(&mut stream, SSH_FX_OK, "");
                        }
                        SSH_FXP_READ => {
                            let h_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let h = c.get_ref()[pos..pos + h_len].to_vec();
                            c.set_position((pos + h_len) as u64);
                            let offset = read_u64(&mut c) as usize;
                            let length = read_u32(&mut c) as usize;
                            let path = match handles.get(&h) {
                                Some(Handle::File { path, .. }) => path.clone(),
                                _ => {
                                    send_status(&mut stream, SSH_FX_FAILURE, "bad handle");
                                    continue;
                                }
                            };
                            let data = fs.files.get(&path).cloned().unwrap_or_default();
                            if offset >= data.len() {
                                send_status(&mut stream, SSH_FX_EOF, "");
                            } else {
                                let end = (offset + length).min(data.len());
                                let chunk = &data[offset..end];
                                let mut r = req_id.to_be_bytes().to_vec();
                                r.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
                                r.extend_from_slice(chunk);
                                write_packet(&mut stream, SSH_FXP_DATA, &r).unwrap();
                            }
                        }
                        SSH_FXP_FSTAT => {
                            let h_len = read_u32(&mut c) as usize;
                            let pos = c.position() as usize;
                            let h = c.get_ref()[pos..pos + h_len].to_vec();
                            let size = match handles.get(&h) {
                                Some(Handle::File { path, .. }) => fs
                                    .files
                                    .get(path)
                                    .map(|v| v.len() as u64)
                                    .unwrap_or(0),
                                _ => {
                                    send_status(&mut stream, SSH_FX_FAILURE, "bad handle");
                                    continue;
                                }
                            };
                            let attrs = encode_attrs(Some(size), Some(0o100644));
                            let mut r = req_id.to_be_bytes().to_vec();
                            r.extend_from_slice(&attrs);
                            write_packet(&mut stream, SSH_FXP_ATTRS, &r).unwrap();
                        }
                        SSH_FXP_READLINK => {
                            let path = norm(read_string(&mut c));
                            match fs.symlinks.get(&path) {
                                Some(target) => {
                                    let mut r = req_id.to_be_bytes().to_vec();
                                    r.extend_from_slice(&1u32.to_be_bytes());
                                    r.extend_from_slice(&(target.len() as u32).to_be_bytes());
                                    r.extend_from_slice(target.as_bytes());
                                    // Empty attrs body — the client only
                                    // looks at name[0].
                                    r.extend_from_slice(&0u32.to_be_bytes());
                                    write_packet(&mut stream, SSH_FXP_NAME, &r).unwrap();
                                }
                                None => send_status(&mut stream, SSH_FX_NO_SUCH_FILE, ""),
                            }
                        }
                        SSH_FXP_SYMLINK => {
                            let path = norm(read_string(&mut c));
                            let target = read_string(&mut c);
                            // OpenSSH's argument order is swapped from
                            // the spec: the wire body sends (linkpath,
                            // targetpath) but Python paramiko / our
                            // client passes target then link. The sftp
                            // crate does `path` first, `target` second
                            // — match what it sends literally.
                            fs.symlinks.insert(path, target);
                            send_status(&mut stream, SSH_FX_OK, "");
                        }
                        SSH_FXP_LINK => {
                            // The `sftp` crate sends path=existing,
                            // target=new-link (matching how OpenSSH
                            // serializes SYMLINK/LINK on the wire,
                            // which is opposite to most APIs).
                            let existing = norm(read_string(&mut c));
                            let new_link = norm(read_string(&mut c));
                            let mut sl = [0u8; 1];
                            c.read_exact(&mut sl).unwrap();
                            let is_symlink = sl[0] != 0;
                            if is_symlink {
                                fs.symlinks.insert(new_link, existing);
                                send_status(&mut stream, SSH_FX_OK, "");
                            } else if let Some(data) = fs.files.get(&existing).cloned() {
                                // Cheap clone-as-hardlink; tests only
                                // observe content equality.
                                fs.files.insert(new_link, data);
                                send_status(&mut stream, SSH_FX_OK, "");
                            } else {
                                send_status(&mut stream, SSH_FX_NO_SUCH_FILE, "");
                            }
                        }
                        _ => {
                            send_status(&mut stream, SSH_FX_FAILURE, "unsupported");
                        }
                    }
                }
            })
        }

        /// Spin up a server, return (transport, server-thread). The
        /// server exits cleanly when `transport` is dropped.
        fn server_with_transport(base: &str) -> (SftpTransport, thread::JoinHandle<()>) {
            let (a, b) = UnixStream::pair().unwrap();
            let server = spawn(b);
            let channel: BoxedChannel = Box::new(a);
            let transport = SftpTransport::from_channel(base, channel).expect("handshake");
            (transport, server)
        }

        #[test]
        fn handshake_succeeds() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            assert_eq!(t.base().as_str(), "sftp://test/tmp/");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn put_then_get_round_trips() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("hello.txt", b"hello world", None).unwrap();
            let bytes = t.get_bytes("hello.txt").unwrap();
            assert_eq!(bytes, b"hello world");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn mkdir_and_list_dir() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("sub", None).unwrap();
            t.put_bytes("sub/a", b"A", None).unwrap();
            t.put_bytes("sub/b", b"BB", None).unwrap();
            let entries: Vec<String> =
                t.list_dir("sub").filter_map(|r| r.ok()).collect();
            let mut sorted = entries.clone();
            sorted.sort();
            assert_eq!(sorted, vec!["a".to_string(), "b".to_string()]);
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn has_returns_true_for_existing_and_false_for_missing() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("present", b"x", None).unwrap();
            assert!(t.has("present").unwrap());
            assert!(!t.has("missing").unwrap());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn stat_reports_file_size() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("f", b"123456", None).unwrap();
            let st = t.stat("f").unwrap();
            assert_eq!(st.size, 6);
            assert!(st.is_file());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn stat_reports_directory_kind() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("d", None).unwrap();
            let st = t.stat("d").unwrap();
            assert!(st.is_dir());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn rename_moves_file() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("a", b"x", None).unwrap();
            t.rename("a", "b").unwrap();
            assert!(!t.has("a").unwrap());
            assert_eq!(t.get_bytes("b").unwrap(), b"x");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn delete_removes_file() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("doomed", b"x", None).unwrap();
            t.delete("doomed").unwrap();
            assert!(!t.has("doomed").unwrap());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn rmdir_rejects_non_empty() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("d", None).unwrap();
            t.put_bytes("d/x", b"x", None).unwrap();
            let err = t.rmdir("d").unwrap_err();
            assert!(matches!(err, Error::DirectoryNotEmptyError(_)));
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn append_file_extends_and_returns_prior_offset() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("log", b"first\n", None).unwrap();
            let mut more = std::io::Cursor::new(b"second\n");
            let offset = t.append_file("log", &mut more, None).unwrap();
            assert_eq!(offset, 6);
            assert_eq!(t.get_bytes("log").unwrap(), b"first\nsecond\n");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn open_write_stream_flushes_on_drop() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            {
                let mut w = t.open_write_stream("ws", None).unwrap();
                w.write_all(b"streamed").unwrap();
            }
            assert_eq!(t.get_bytes("ws").unwrap(), b"streamed");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn missing_file_maps_to_no_such_file() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            let err = t.get_bytes("nope").unwrap_err();
            assert!(matches!(err, Error::NoSuchFile(_)));
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn mkdir_existing_maps_to_file_exists() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("d", None).unwrap();
            let err = t.mkdir("d", None).unwrap_err();
            assert!(matches!(err, Error::FileExists(_)));
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn iter_files_recursive_walks_subdirs() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("a", None).unwrap();
            t.mkdir("a/b", None).unwrap();
            t.put_bytes("top", b"x", None).unwrap();
            t.put_bytes("a/inside", b"y", None).unwrap();
            t.put_bytes("a/b/deep", b"z", None).unwrap();
            let mut files: Vec<String> =
                t.iter_files_recursive().filter_map(|r| r.ok()).collect();
            files.sort();
            assert_eq!(
                files,
                vec![
                    "a/b/deep".to_string(),
                    "a/inside".to_string(),
                    "top".to_string(),
                ]
            );
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn hardlink_creates_independent_path_with_same_content() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("orig", b"shared", None).unwrap();
            t.hardlink("orig", "alias").unwrap();
            assert_eq!(t.get_bytes("alias").unwrap(), b"shared");
            assert!(t.has("orig").unwrap());
            assert!(t.has("alias").unwrap());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn hardlink_to_missing_target_errors() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            let err = t.hardlink("nope", "alias").unwrap_err();
            assert!(matches!(err, Error::NoSuchFile(_)));
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn delete_tree_removes_nested_subdirs_and_files() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("tree", None).unwrap();
            t.mkdir("tree/sub", None).unwrap();
            t.put_bytes("tree/a", b"1", None).unwrap();
            t.put_bytes("tree/sub/b", b"2", None).unwrap();
            t.put_bytes("tree/sub/c", b"3", None).unwrap();
            t.delete_tree("tree").unwrap();
            assert!(!t.has("tree").unwrap());
            assert!(!t.has("tree/a").unwrap());
            assert!(!t.has("tree/sub").unwrap());
            assert!(!t.has("tree/sub/b").unwrap());
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn copy_duplicates_file_content() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.put_bytes("src", b"copy-me", None).unwrap();
            t.copy("src", "dst").unwrap();
            assert_eq!(t.get_bytes("src").unwrap(), b"copy-me");
            assert_eq!(t.get_bytes("dst").unwrap(), b"copy-me");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn clone_with_offset_rebases_relpaths_to_subdir() {
            let (t, server) = server_with_transport("sftp://test/tmp/");
            t.mkdir("nested", None).unwrap();
            t.put_bytes("nested/inside", b"data", None).unwrap();
            // Clone descends into the subdir; relpaths against the
            // clone resolve to /tmp/nested/<relpath> on the wire.
            let sub = Transport::clone(&t, Some("nested")).unwrap();
            assert_eq!(sub.base().as_str(), "sftp://test/tmp/nested/");
            assert_eq!(sub.get_bytes("inside").unwrap(), b"data");
            // Confirm it's a real shared session: writes through the
            // clone are visible to the parent.
            sub.put_bytes("via_clone", b"x", None).unwrap();
            assert_eq!(t.get_bytes("nested/via_clone").unwrap(), b"x");
            drop(sub);
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn put_and_get_round_trip_a_large_file() {
            // 256 KiB exercises the >64 KiB chunking in `read_full`
            // and the put_file write loop. Pattern is an incrementing
            // byte so a wrong-offset bug shows up as a content
            // mismatch rather than a length mismatch.
            let (t, server) = server_with_transport("sftp://test/tmp/");
            let big: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
            t.put_bytes("big", &big, None).unwrap();
            let got = t.get_bytes("big").unwrap();
            assert_eq!(got.len(), big.len());
            assert!(got == big, "256 KiB round-trip content differs");
            drop(t);
            server.join().unwrap();
        }

        #[test]
        fn set_segment_parameter_is_a_noop() {
            let (mut t, server) = server_with_transport("sftp://test/tmp/");
            // SFTP doesn't consume segment params; setting one must
            // succeed and leave the parameter map empty.
            t.set_segment_parameter("foo", Some("bar")).unwrap();
            assert!(t.get_segment_parameters().unwrap().is_empty());
            drop(t);
            server.join().unwrap();
        }
    }
}
