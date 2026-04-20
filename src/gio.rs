//! GIO Transport, ported from dromedary/gio_transport.py.
//!
//! Wraps `gio::File` to expose the dromedary [`Transport`] trait over
//! anything gvfs can mount: `gio+file://`, `gio+sftp://`, `gio+smb://`,
//! `gio+dav://`, `gio+ftp://`, `gio+ssh://`, `gio+obex://`.
//!
//! `gio::File` is `!Send`/`!Sync`, so we never store one on the struct;
//! every method reconstructs files via `gio::File::for_uri` from the
//! `String` base URL and a relpath. This sidesteps the threading
//! constraints `Transport` imposes (`Send + Sync`).
//!
//! Mounting volumes that need credentials currently isn't implemented —
//! v1 only handles URLs that gvfs can already enumerate. See the TODO
//! near `ensure_mounted` for the path forward.

use crate::lock::{Lock, LockError};
use crate::urlutils::escape;
use crate::{Error, FileKind, ReadStream, Result, Stat, Transport, UrlFragment, WriteStream};
use ::gio::prelude::*;
use ::gio::{FileCopyFlags, FileQueryInfoFlags, IOErrorEnum};
use std::collections::HashMap;
use std::fs::Permissions;
use std::io::{Cursor, Read};
use std::sync::mpsc;
use std::thread;
use url::Url;

const GIO_BACKENDS: &[&str] = &["dav", "file", "ftp", "obex", "sftp", "ssh", "smb"];

/// A transport that proxies through a gvfs mount.
pub struct GioTransport {
    /// Public dromedary base, including the `gio+` scheme prefix and a
    /// trailing slash.
    base: Url,
    /// URL stripped of the `gio+` prefix and any embedded credentials,
    /// suitable to pass to `gio::File::for_uri`.
    backend_url: String,
}

impl std::fmt::Debug for GioTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "GioTransport({})", self.base)
    }
}

impl GioTransport {
    pub fn new(base: &str) -> Result<Self> {
        let mut base = base.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let stripped = base
            .strip_prefix("gio+")
            .ok_or_else(|| Error::NotLocalUrl(base.clone()))?;

        let parsed = Url::parse(stripped).map_err(Error::from)?;
        if !GIO_BACKENDS.contains(&parsed.scheme()) {
            return Err(Error::UrlError(url::ParseError::IdnaError));
        }

        // Reconstruct the backend URL with any embedded user/password
        // stripped — gvfs handles credentials via MountOperation, not
        // via the URL.
        let mut backend = parsed.clone();
        let _ = backend.set_username("");
        let _ = backend.set_password(None);
        let backend_url = backend.to_string();

        let public_base = Url::parse(&base).map_err(Error::from)?;

        Ok(Self {
            base: public_base,
            backend_url,
        })
    }

    fn child_url(&self, relpath: &UrlFragment) -> Result<String> {
        // The backend URL ends with `/` so url::Url::join treats it as a
        // directory and resolves relpaths relative to it. An empty or
        // `.` relpath returns the directory itself.
        let base = Url::parse(&self.backend_url).map_err(Error::from)?;
        let trimmed = if relpath == "." || relpath.is_empty() {
            ""
        } else {
            relpath
        };
        let joined = base.join(trimmed).map_err(Error::from)?;
        Ok(joined.to_string())
    }

    fn file_for(&self, relpath: &UrlFragment) -> Result<::gio::File> {
        let url = self.child_url(relpath)?;
        Ok(::gio::File::for_uri(&url))
    }

    /// Translate a gvfs error into the dromedary error vocabulary.
    fn translate(err: glib::Error, relpath: Option<&UrlFragment>) -> Error {
        let path = relpath.map(|p| p.to_string());
        match err.kind::<IOErrorEnum>() {
            Some(IOErrorEnum::NotFound) => Error::NoSuchFile(path),
            Some(IOErrorEnum::Exists) => Error::FileExists(path),
            Some(IOErrorEnum::NotDirectory) => Error::NotADirectoryError(path),
            Some(IOErrorEnum::IsDirectory) => Error::IsADirectoryError(path),
            Some(IOErrorEnum::NotEmpty) => Error::DirectoryNotEmptyError(path),
            Some(IOErrorEnum::PermissionDenied) => Error::PermissionDenied(path),
            Some(IOErrorEnum::Busy) => Error::ResourceBusy(path),
            Some(IOErrorEnum::NotMounted) => Error::TransportNotPossible,
            Some(IOErrorEnum::ReadOnly) => Error::PermissionDenied(path),
            // Everything else folds into a generic IO error so the caller
            // gets *something* useful instead of a panic.
            _ => Error::Io(std::io::Error::other(err.to_string())),
        }
    }
}

struct GioReadStream(Cursor<Vec<u8>>);

impl Read for GioReadStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Seek for GioReadStream {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ReadStream for GioReadStream {}

/// Commands sent from the public `GioWriteStream` handle to the worker
/// thread that owns the underlying `gio::FileOutputStream`. The worker
/// is necessary because `FileOutputStream` is `!Send`, but `WriteStream`
/// requires `Send + Sync`.
enum WriterCmd {
    Write(Vec<u8>),
    Flush,
    Close,
}

/// Reply payload returned over a one-shot reply channel for each command.
/// `glib::Error` is `!Send`, so any error is converted to a string here.
type WriterReply = std::result::Result<usize, String>;

/// Send+Sync handle to a writer thread that owns a gvfs output stream.
struct GioWriteStream {
    tx: Option<mpsc::Sender<(WriterCmd, mpsc::Sender<WriterReply>)>>,
    join: Option<thread::JoinHandle<()>>,
}

impl GioWriteStream {
    fn spawn(url: String) -> Result<Self> {
        // The worker creates the output stream itself so the !Send
        // `gio::File` / `FileOutputStream` never crosses thread boundaries.
        // Open synchronously via a one-shot channel so we can surface
        // errors before returning the handle.
        let (open_tx, open_rx) = mpsc::channel::<std::result::Result<(), String>>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<(WriterCmd, mpsc::Sender<WriterReply>)>();

        let join = thread::spawn(move || {
            let file = ::gio::File::for_uri(&url);
            let stream = match file.replace(
                None,
                false,
                ::gio::FileCreateFlags::REPLACE_DESTINATION,
                ::gio::Cancellable::NONE,
            ) {
                Ok(s) => {
                    if open_tx.send(Ok(())).is_err() {
                        // Caller went away; clean up and exit.
                        let _ = s.close(::gio::Cancellable::NONE);
                        return;
                    }
                    s
                }
                Err(e) => {
                    let _ = open_tx.send(Err(e.to_string()));
                    return;
                }
            };

            while let Ok((cmd, reply)) = cmd_rx.recv() {
                match cmd {
                    WriterCmd::Write(buf) => {
                        let res = match stream.write_all(&buf, ::gio::Cancellable::NONE) {
                            Ok((written, None)) => Ok(written),
                            Ok((_, Some(e))) => Err(e.to_string()),
                            Err(e) => Err(e.to_string()),
                        };
                        let _ = reply.send(res);
                    }
                    WriterCmd::Flush => {
                        let res = stream
                            .flush(::gio::Cancellable::NONE)
                            .map(|_| 0usize)
                            .map_err(|e| e.to_string());
                        let _ = reply.send(res);
                    }
                    WriterCmd::Close => {
                        let res = stream
                            .close(::gio::Cancellable::NONE)
                            .map(|_| 0usize)
                            .map_err(|e| e.to_string());
                        let _ = reply.send(res);
                        return;
                    }
                }
            }

            // Sender dropped without an explicit Close — best-effort close.
            let _ = stream.close(::gio::Cancellable::NONE);
        });

        match open_rx.recv() {
            Ok(Ok(())) => Ok(GioWriteStream {
                tx: Some(cmd_tx),
                join: Some(join),
            }),
            Ok(Err(msg)) => {
                let _ = join.join();
                Err(Error::Io(std::io::Error::other(msg)))
            }
            Err(_) => {
                let _ = join.join();
                Err(Error::Io(std::io::Error::other(
                    "gio writer thread exited before opening stream",
                )))
            }
        }
    }

    fn dispatch(&self, cmd: WriterCmd) -> std::io::Result<usize> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::other("gio write stream already closed"))?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send((cmd, reply_tx))
            .map_err(|_| std::io::Error::other("gio writer thread exited"))?;
        match reply_rx.recv() {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(msg)) => Err(std::io::Error::other(msg)),
            Err(_) => Err(std::io::Error::other("gio writer thread exited")),
        }
    }
}

impl std::io::Write for GioWriteStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // write_all on the worker drains the whole buffer or returns an error.
        self.dispatch(WriterCmd::Write(buf.to_vec()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.dispatch(WriterCmd::Flush).map(|_| ())
    }
}

impl WriteStream for GioWriteStream {
    fn sync_data(&self) -> std::io::Result<()> {
        // gvfs has no fsync; OutputStream::flush is the strongest durability
        // primitive available, matching what the Python port did.
        self.dispatch(WriterCmd::Flush).map(|_| ())
    }
}

impl Drop for GioWriteStream {
    fn drop(&mut self) {
        // Best-effort close. Errors here have nowhere to go.
        if let Some(tx) = self.tx.take() {
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx.send((WriterCmd::Close, reply_tx)).is_ok() {
                let _ = reply_rx.recv();
            }
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// gvfs offers no real lock primitive, matching the Python implementation
/// which returned a no-op lock. We do the same.
struct BogusLock;

impl Lock for BogusLock {
    fn unlock(&mut self) -> std::result::Result<(), LockError> {
        Ok(())
    }
}

impl Transport for GioTransport {
    fn external_url(&self) -> Result<Url> {
        Ok(self.base.clone())
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        false
    }

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        let f = self.file_for(relpath)?;
        let input = f
            .read(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))?;
        let mut buf = Vec::new();
        loop {
            let chunk = input
                .read_bytes(64 * 1024, ::gio::Cancellable::NONE)
                .map_err(|e| Self::translate(e, Some(relpath)))?;
            if chunk.is_empty() {
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        let _ = input.close(::gio::Cancellable::NONE);
        Ok(Box::new(GioReadStream(Cursor::new(buf))))
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        let f = self.file_for(relpath)?;
        match f.query_info(
            "standard::type",
            FileQueryInfoFlags::NONE,
            ::gio::Cancellable::NONE,
        ) {
            Ok(info) => Ok(matches!(
                info.file_type(),
                ::gio::FileType::Regular | ::gio::FileType::Directory
            )),
            Err(e) if e.kind::<IOErrorEnum>() == Some(IOErrorEnum::NotFound) => Ok(false),
            Err(e) => Err(Self::translate(e, Some(relpath))),
        }
    }

    fn mkdir(&self, relpath: &UrlFragment, _permissions: Option<Permissions>) -> Result<()> {
        let f = self.file_for(relpath)?;
        f.make_directory(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        let f = self.file_for(relpath)?;
        let info = f
            .query_info(
                "standard::size,standard::type",
                FileQueryInfoFlags::NONE,
                ::gio::Cancellable::NONE,
            )
            .map_err(|e| Self::translate(e, Some(relpath)))?;
        let kind = match info.file_type() {
            ::gio::FileType::Regular => FileKind::File,
            ::gio::FileType::Directory => FileKind::Dir,
            ::gio::FileType::SymbolicLink => FileKind::Symlink,
            _ => FileKind::Other,
        };
        Ok(Stat {
            size: info.size().max(0) as usize,
            #[cfg(unix)]
            mode: match kind {
                FileKind::Dir => 0o040755,
                FileKind::Symlink => 0o120777,
                _ => 0o100644,
            },
            kind,
            mtime: None,
        })
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        let new_backend = match offset {
            Some(o) if !o.is_empty() => {
                let base = Url::parse(&self.backend_url).map_err(Error::from)?;
                base.join(o).map_err(Error::from)?.to_string()
            }
            _ => self.backend_url.clone(),
        };
        let new_base = format!("gio+{}", new_backend);
        Ok(Box::new(GioTransport::new(&new_base)?))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        let trimmed = if relpath == "." || relpath.is_empty() {
            ""
        } else {
            relpath
        };
        self.base.join(trimmed).map_err(Error::from)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        let base = self.base.as_str();
        abspath
            .as_str()
            .strip_prefix(base)
            .map(|s| s.to_string())
            .ok_or(Error::PathNotChild)
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        // Mirror Python: write to a temp sibling, then move-with-overwrite.
        let tmp_rel = format!("{}.tmp.{}", relpath, std::process::id());
        let tmp_file = self.file_for(&tmp_rel)?;
        let dest_file = self.file_for(relpath)?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;

        let out = tmp_file
            .create(::gio::FileCreateFlags::NONE, ::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))?;
        // OutputStreamExtManual::write_all loops until the buffer drains.
        // Signature: Result<(written, Option<partial_err>), full_err>.
        match out.write_all(&buf, ::gio::Cancellable::NONE) {
            Ok((_, None)) => {}
            Ok((_, Some(e))) => return Err(Self::translate(e, Some(relpath))),
            Err(e) => return Err(Self::translate(e, Some(relpath))),
        }
        out.close(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))?;

        let move_result = tmp_file.move_(
            &dest_file,
            FileCopyFlags::OVERWRITE,
            ::gio::Cancellable::NONE,
            None,
        );
        if let Err(e) = move_result {
            // Best-effort cleanup; ignore secondary errors.
            let _ = tmp_file.delete(::gio::Cancellable::NONE);
            return Err(Self::translate(e, Some(relpath)));
        }
        Ok(buf.len() as u64)
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        let f = self.file_for(relpath)?;
        f.delete(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        let st = self.stat(relpath)?;
        if st.kind != FileKind::Dir {
            return Err(Error::NotADirectoryError(Some(relpath.to_string())));
        }
        let f = self.file_for(relpath)?;
        f.delete(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let from = self.file_for(rel_from)?;
        let to = self.file_for(rel_to)?;
        from.move_(&to, FileCopyFlags::NONE, ::gio::Cancellable::NONE, None)
            .map_err(|e| Self::translate(e, Some(rel_from)))
    }

    fn r#move(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let from = self.file_for(rel_from)?;
        let to = self.file_for(rel_to)?;
        from.move_(
            &to,
            FileCopyFlags::OVERWRITE,
            ::gio::Cancellable::NONE,
            None,
        )
        .map_err(|e| Self::translate(e, Some(rel_from)))
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let data = self.get_bytes(rel_from)?;
        let mut cur = Cursor::new(data);
        self.put_file(rel_to, &mut cur, None).map(|_| ())
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        // Python notes that GIO's append_to truncates instead of appending,
        // so it implements a manual read+rewrite-via-tempfile. Mirror that.
        let mut existing = match self.get_bytes(relpath) {
            Ok(b) => b,
            Err(Error::NoSuchFile(_)) => Vec::new(),
            Err(e) => return Err(e),
        };
        let original_len = existing.len() as u64;

        let mut to_append = Vec::new();
        f.read_to_end(&mut to_append)
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        existing.extend_from_slice(&to_append);

        let mut cur = Cursor::new(existing);
        self.put_file(relpath, &mut cur, None)?;
        Ok(original_len)
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        let f = match self.file_for(relpath) {
            Ok(f) => f,
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        let enumerator = match f.enumerate_children(
            "standard::name",
            FileQueryInfoFlags::NONE,
            ::gio::Cancellable::NONE,
        ) {
            Ok(e) => e,
            Err(e) => return Box::new(std::iter::once(Err(Self::translate(e, Some(relpath))))),
        };
        let mut entries: Vec<Result<String>> = Vec::new();
        loop {
            match enumerator.next_file(::gio::Cancellable::NONE) {
                Ok(Some(info)) => {
                    let name = info.name();
                    let name_str = name.to_string_lossy();
                    entries.push(Ok(escape(name_str.as_bytes(), None)));
                }
                Ok(None) => break,
                Err(e) => {
                    entries.push(Err(Self::translate(e, Some(relpath))));
                    break;
                }
            }
        }
        let _ = enumerator.close(::gio::Cancellable::NONE);
        Box::new(entries.into_iter())
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        let mut queue: Vec<String> = Vec::new();
        for entry in self.list_dir(".") {
            match entry {
                Ok(name) => queue.push(name),
                Err(e) => return Box::new(std::iter::once(Err(e))),
            }
        }

        let mut results: Vec<Result<String>> = Vec::new();
        while let Some(rel) = queue.pop() {
            match self.stat(&rel) {
                Ok(st) if st.kind == FileKind::Dir => {
                    for child in self.list_dir(&rel) {
                        match child {
                            Ok(name) => queue.push(format!("{}/{}", rel, name)),
                            Err(e) => {
                                results.push(Err(e));
                                break;
                            }
                        }
                    }
                }
                Ok(_) => results.push(Ok(rel)),
                Err(e) => results.push(Err(e)),
            }
        }
        Box::new(results.into_iter())
    }

    fn lock_read(&self, _relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        Ok(Box::new(BogusLock))
    }

    fn lock_write(&self, _relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        Ok(Box::new(BogusLock))
    }

    fn local_abspath(&self, relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        Err(Error::NotLocalUrl(format!("{}{}", self.base, relpath)))
    }

    fn listable(&self) -> bool {
        true
    }

    fn set_segment_parameter(&mut self, _key: &str, _value: Option<&str>) -> Result<()> {
        Err(Error::TransportNotPossible)
    }

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }

    fn readlink(&self, _relpath: &UrlFragment) -> Result<String> {
        // gvfs symlinks are exposed by query_info but resolving them
        // requires standard::symlink-target. The Python port did not
        // implement readlink either; keep parity.
        Err(Error::TransportNotPossible)
    }

    fn hardlink(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible)
    }

    fn symlink(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible)
    }

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()> {
        let st = self.stat(relpath)?;
        if st.kind != FileKind::Dir {
            return Err(Error::NotADirectoryError(Some(relpath.to_string())));
        }
        // Depth-first removal: enumerate entries, recurse into directories,
        // delete files, then delete the now-empty directory.
        let f = self.file_for(relpath)?;
        let enumerator = f
            .enumerate_children(
                "standard::name,standard::type",
                FileQueryInfoFlags::NOFOLLOW_SYMLINKS,
                ::gio::Cancellable::NONE,
            )
            .map_err(|e| Self::translate(e, Some(relpath)))?;
        loop {
            match enumerator.next_file(::gio::Cancellable::NONE) {
                Ok(Some(info)) => {
                    let name = info.name();
                    let name_str = name.to_string_lossy();
                    let child_rel = format!("{}/{}", relpath.trim_end_matches('/'), name_str);
                    match info.file_type() {
                        ::gio::FileType::Directory => self.delete_tree(&child_rel)?,
                        _ => {
                            let child = self.file_for(&child_rel)?;
                            child
                                .delete(::gio::Cancellable::NONE)
                                .map_err(|e| Self::translate(e, Some(&child_rel)))?;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(Self::translate(e, Some(relpath))),
            }
        }
        let _ = enumerator.close(::gio::Cancellable::NONE);
        f.delete(::gio::Cancellable::NONE)
            .map_err(|e| Self::translate(e, Some(relpath)))
    }

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        _permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        // gio::FileOutputStream is !Send. We dedicate one worker thread per
        // open stream — the worker owns the underlying handle and we drive
        // it via a synchronous command channel.
        let url = self.child_url(relpath)?;
        let stream = GioWriteStream::spawn(url)?;
        Ok(Box::new(stream))
    }
}

// `gio::File` and friends are `!Send + !Sync`. Our struct only stores
// owned `String`/`Url`, which are Send+Sync, and `GioWriteStream` keeps
// its !Send `gio::FileOutputStream` pinned to a worker thread.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_transport() -> (TempDir, GioTransport) {
        let dir = TempDir::new().unwrap();
        // gio::File::for_uri wants file:///abs/path — build it via Url so
        // path escaping is handled for us.
        let file_url = url::Url::from_directory_path(dir.path()).unwrap();
        let base = format!("gio+{}", file_url.as_str());
        let t = GioTransport::new(&base).unwrap();
        (dir, t)
    }

    #[test]
    fn rejects_unknown_scheme() {
        match GioTransport::new("gio+nope:///x/") {
            Err(Error::UrlError(_)) => {}
            other => panic!("expected UrlError, got {:?}", other),
        }
    }

    #[test]
    fn requires_gio_prefix() {
        match GioTransport::new("file:///does/not/matter/") {
            Err(Error::NotLocalUrl(_)) => {}
            other => panic!("expected NotLocalUrl, got {:?}", other),
        }
    }

    #[test]
    fn put_get_has_round_trip() {
        let (_dir, t) = temp_transport();
        assert!(!t.has("hello").unwrap());
        t.put_bytes("hello", b"world", None).unwrap();
        assert!(t.has("hello").unwrap());
        assert_eq!(t.get_bytes("hello").unwrap(), b"world");
    }

    #[test]
    fn mkdir_stat_list_round_trip() {
        let (_dir, t) = temp_transport();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/a", b"1", None).unwrap();
        t.put_bytes("d/b", b"22", None).unwrap();
        let mut entries: Vec<String> = t.list_dir("d").filter_map(|r| r.ok()).collect();
        entries.sort();
        assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(t.stat("d").unwrap().kind, FileKind::Dir);
    }

    #[test]
    fn rename_and_delete() {
        let (_dir, t) = temp_transport();
        t.put_bytes("a", b"hi", None).unwrap();
        t.rename("a", "b").unwrap();
        assert!(!t.has("a").unwrap());
        assert_eq!(t.get_bytes("b").unwrap(), b"hi");
        t.delete("b").unwrap();
        assert!(!t.has("b").unwrap());
    }

    #[test]
    fn append_extends_file() {
        let (_dir, t) = temp_transport();
        t.put_bytes("f", b"abc", None).unwrap();
        let mut more = Cursor::new(b"DEF".to_vec());
        let offset = t.append_file("f", &mut more, None).unwrap();
        assert_eq!(offset, 3);
        assert_eq!(t.get_bytes("f").unwrap(), b"abcDEF");
    }

    #[test]
    fn missing_file_get_returns_no_such_file() {
        let (_dir, t) = temp_transport();
        match t.get_bytes("nope") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn open_write_stream_round_trip() {
        use std::io::Write;
        let (_dir, t) = temp_transport();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"hello ").unwrap();
        stream.write_all(b"world").unwrap();
        stream.flush().unwrap();
        drop(stream);
        assert_eq!(t.get_bytes("w").unwrap(), b"hello world");
    }

    #[test]
    fn open_write_stream_visible_after_flush() {
        // After explicit flush, a concurrent read on the same path must see
        // the buffered writes — this is what the per_transport
        // test_get_with_open_write_stream_sees_all_content scenario asserts.
        use std::io::Write;
        let (_dir, t) = temp_transport();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"bcd").unwrap();
        stream.flush().unwrap();
        assert_eq!(t.get_bytes("w").unwrap(), b"bcd");
        drop(stream);
    }

    #[test]
    fn open_write_stream_overwrites_existing() {
        use std::io::Write;
        let (_dir, t) = temp_transport();
        t.put_bytes("w", b"old contents", None).unwrap();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"new").unwrap();
        drop(stream);
        assert_eq!(t.get_bytes("w").unwrap(), b"new");
    }

    #[test]
    fn delete_tree_removes_nested() {
        let (_dir, t) = temp_transport();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/a", b"1", None).unwrap();
        t.mkdir("d/sub", None).unwrap();
        t.put_bytes("d/sub/b", b"2", None).unwrap();
        t.delete_tree("d").unwrap();
        assert!(!t.has("d").unwrap());
    }

    #[test]
    fn delete_tree_rejects_non_directory() {
        let (_dir, t) = temp_transport();
        t.put_bytes("f", b"x", None).unwrap();
        match t.delete_tree("f") {
            Err(Error::NotADirectoryError(_)) => {}
            other => panic!("expected NotADirectoryError, got {:?}", other),
        }
    }

    #[test]
    fn iter_files_recursive_walks() {
        let (_dir, t) = temp_transport();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/a", b"1", None).unwrap();
        t.mkdir("d/sub", None).unwrap();
        t.put_bytes("d/sub/b", b"2", None).unwrap();
        let mut files: Vec<String> = t.iter_files_recursive().filter_map(|r| r.ok()).collect();
        files.sort();
        assert_eq!(files, vec!["d/a".to_string(), "d/sub/b".to_string()]);
    }
}
