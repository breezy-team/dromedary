//! In-memory Transport implementation, ported from dromedary/memory.py.
//!
//! Storage is shared across clones via `Arc<Mutex<MemoryStore>>`, matching
//! the Python semantics where `clone()` passes the same dict references.

use crate::lock::{Lock, LockError};
use crate::urlutils::{escape, unescape};
use crate::{
    map_io_err_to_transport_err, Error, FileKind, ReadStream, Result, Stat, Transport, UrlFragment,
    WriteStream,
};
use std::collections::HashMap;
use std::fs::Permissions;
use std::io::{Cursor, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use url::Url;

/// Raw mode bits stored alongside each entry. On Unix we round-trip the full
/// `Permissions` value; on Windows the concept is largely meaningless so we
/// simply track the u32 that the caller supplied (if any), same as the
/// Python implementation.
type Mode = Option<u32>;

fn perms_to_mode(p: Option<Permissions>) -> Mode {
    #[cfg(unix)]
    {
        p.map(|p| p.mode())
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        None
    }
}

#[derive(Default)]
pub struct MemoryStore {
    files: HashMap<String, (Vec<u8>, Mode)>,
    dirs: HashMap<String, Mode>,
    symlinks: HashMap<String, Vec<String>>,
    locks: HashMap<String, ()>,
}

impl MemoryStore {
    fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert("/".to_string(), None);
        Self {
            files: HashMap::new(),
            dirs,
            symlinks: HashMap::new(),
            locks: HashMap::new(),
        }
    }
}

pub struct MemoryTransport {
    base: Url,
    scheme: String,
    cwd: String,
    store: Arc<Mutex<MemoryStore>>,
}

impl std::fmt::Debug for MemoryTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MemoryTransport({})", self.base)
    }
}

impl MemoryTransport {
    pub fn new(url: &str) -> Result<Self> {
        let mut url = url.to_string();
        if url.is_empty() {
            url = "memory:///".to_string();
        }
        if !url.ends_with('/') {
            url.push('/');
        }
        let split = url
            .find(':')
            .ok_or_else(|| Error::NotLocalUrl(url.clone()))?
            + 3;
        if split > url.len() {
            return Err(Error::NotLocalUrl(url));
        }
        let scheme = url[..split].to_string();
        let cwd = url[split..].to_string();
        let parsed = Url::parse(&url).map_err(Error::from)?;
        Ok(Self {
            base: parsed,
            scheme,
            cwd,
            store: Arc::new(Mutex::new(MemoryStore::new())),
        })
    }

    /// Construct a MemoryTransport that shares storage with `other`.
    /// Used by `clone()` and by `MemoryServer` to hand out multiple
    /// transports sharing a single backing store.
    pub fn with_shared_store(url: &str, store: Arc<Mutex<MemoryStore>>) -> Result<Self> {
        let mut t = Self::new(url)?;
        t.store = store;
        Ok(t)
    }

    pub fn shared_store(&self) -> Arc<Mutex<MemoryStore>> {
        self.store.clone()
    }

    fn abspath_internal(&self, relpath: &UrlFragment) -> Result<String> {
        let relpath = unescape(relpath).map_err(Error::from)?;
        if relpath.starts_with('/') {
            return Ok(relpath);
        }
        let cwd_parts = self.cwd.split('/');
        let rel_parts = relpath.split('/');
        let mut r: Vec<String> = Vec::new();
        let store = self.store.lock().unwrap();
        for part in cwd_parts.chain(rel_parts) {
            if part == ".." {
                if r.is_empty() {
                    return Err(Error::PathNotChild);
                }
                r.pop();
            } else if part == "." || part.is_empty() {
                // skip
            } else {
                r.push(part.to_string());
                // Match Python memory.py _abspath: look up by joined key
                // without leading slash. Stored symlink keys include a leading
                // slash, so this effectively never matches; symlink following
                // happens in resolve_symlinks instead. Kept for byte-for-byte
                // parity with the Python implementation.
                let key = r.join("/");
                if let Some(target) = store.symlinks.get(&key) {
                    r = target.clone();
                }
            }
        }
        Ok(format!("/{}", r.join("/")))
    }

    fn resolve_symlinks(&self, relpath: &UrlFragment) -> Result<String> {
        let mut path = self.abspath_internal(relpath)?;
        let store = self.store.lock().unwrap();
        while let Some(target) = store.symlinks.get(&path) {
            path = target.join("/");
            if !path.starts_with('/') {
                path = format!("/{}", path);
            }
        }
        Ok(path)
    }

    fn check_parent(store: &MemoryStore, abspath: &str) -> Result<()> {
        let parent = match abspath.rsplit_once('/') {
            Some((head, _)) if head.is_empty() => "/".to_string(),
            Some((head, _)) => head.to_string(),
            None => "/".to_string(),
        };
        if parent != "/" && !store.dirs.contains_key(&parent) {
            return Err(Error::NoSuchFile(Some(abspath.to_string())));
        }
        Ok(())
    }
}

struct MemoryReadStream(Cursor<Vec<u8>>);

impl Read for MemoryReadStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Seek for MemoryReadStream {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ReadStream for MemoryReadStream {}

/// Write stream that appends straight into the shared MemoryStore so a
/// concurrent get_bytes on the same path sees the in-flight bytes
/// without an explicit flush — matching the per_transport
/// `get_with_open_write_stream_sees_all_content` contract.
struct MemoryWriteStream {
    store: Arc<Mutex<MemoryStore>>,
    abspath: String,
}

impl Write for MemoryWriteStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut store = self.store.lock().unwrap();
        match store.files.get_mut(&self.abspath) {
            Some((data, _)) => {
                data.extend_from_slice(buf);
                Ok(buf.len())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "memory file removed while write stream was open",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl WriteStream for MemoryWriteStream {
    fn sync_data(&self) -> std::io::Result<()> {
        Ok(())
    }
}

struct MemoryLock {
    path: String,
    store: Arc<Mutex<MemoryStore>>,
}

impl Lock for MemoryLock {
    fn unlock(&mut self) -> std::result::Result<(), LockError> {
        let mut store = self.store.lock().unwrap();
        store.locks.remove(&self.path);
        Ok(())
    }
}

fn acquire_lock(
    store: &Arc<Mutex<MemoryStore>>,
    path: &str,
) -> Result<Box<dyn Lock + Send + Sync>> {
    let mut s = store.lock().unwrap();
    if s.locks.contains_key(path) {
        return Err(Error::LockContention(std::path::PathBuf::from(path)));
    }
    s.locks.insert(path.to_string(), ());
    Ok(Box::new(MemoryLock {
        path: path.to_string(),
        store: store.clone(),
    }))
}

impl Transport for MemoryTransport {
    fn external_url(&self) -> Result<Url> {
        Err(Error::InProcessTransport)
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        false
    }

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        let abspath = self.resolve_symlinks(relpath)?;
        let store = self.store.lock().unwrap();
        if let Some((data, _mode)) = store.files.get(&abspath) {
            Ok(Box::new(MemoryReadStream(Cursor::new(data.clone()))))
        } else if store.dirs.contains_key(&abspath) {
            // Python returns a LateReadError here; we translate that into
            // an immediate IsADirectoryError for the Rust API.
            Err(Error::IsADirectoryError(Some(relpath.to_string())))
        } else {
            Err(Error::NoSuchFile(Some(relpath.to_string())))
        }
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        let abspath = self.abspath_internal(relpath)?;
        let store = self.store.lock().unwrap();
        Ok(store.files.contains_key(&abspath)
            || store.dirs.contains_key(&abspath)
            || store.symlinks.contains_key(&abspath))
    }

    fn mkdir(&self, relpath: &UrlFragment, permissions: Option<Permissions>) -> Result<()> {
        let abspath = self.resolve_symlinks(relpath)?;
        let mut store = self.store.lock().unwrap();
        Self::check_parent(&store, &abspath)?;
        if store.dirs.contains_key(&abspath) {
            return Err(Error::FileExists(Some(relpath.to_string())));
        }
        store.dirs.insert(abspath, perms_to_mode(permissions));
        Ok(())
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        let abspath = self.abspath_internal(relpath)?;
        let store = self.store.lock().unwrap();
        if let Some((data, mode)) = store.files.get(&abspath) {
            #[cfg(unix)]
            let stat_mode = (0o100000u32) | mode.unwrap_or(0o644);
            Ok(Stat {
                size: data.len(),
                #[cfg(unix)]
                mode: stat_mode,
                kind: FileKind::File,
                mtime: None,
            })
        } else if let Some(mode) = store.dirs.get(&abspath) {
            #[cfg(unix)]
            let stat_mode = (0o040000u32) | mode.unwrap_or(0o755);
            #[cfg(not(unix))]
            let _ = mode;
            Ok(Stat {
                size: 0,
                #[cfg(unix)]
                mode: stat_mode,
                kind: FileKind::Dir,
                mtime: None,
            })
        } else if store.symlinks.contains_key(&abspath) {
            #[cfg(unix)]
            let stat_mode = 0o120000u32;
            Ok(Stat {
                size: 0,
                #[cfg(unix)]
                mode: stat_mode,
                kind: FileKind::Symlink,
                mtime: None,
            })
        } else {
            Err(Error::NoSuchFile(Some(abspath)))
        }
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        let path = crate::urlutils::combine_paths(&self.cwd, offset.unwrap_or(""));
        let path = if path.is_empty() || !path.ends_with('/') {
            format!("{}/", path)
        } else {
            path
        };
        let url = format!("{}{}", self.scheme, path);
        let cloned = Self::with_shared_store(&url, self.store.clone())?;
        Ok(Box::new(cloned))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        // Mirror Python: clone(relpath).base, stripping trailing slash unless root.
        let cloned = self.clone(Some(relpath))?;
        let s = cloned.base().to_string();
        let url_str = if s.matches('/').count() == 3 {
            s
        } else {
            s.trim_end_matches('/').to_string()
        };
        Url::parse(&url_str).map_err(Error::from)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        crate::relpath_against_base(&self.base, abspath)
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let abspath = self.resolve_symlinks(relpath)?;
        // Validate the parent directory exists *before* reading the stream
        // so that a failed put_file leaves the reader untouched. This lets
        // the default put_file_non_atomic retry with the same stream after
        // creating the missing parent.
        {
            let store = self.store.lock().unwrap();
            Self::check_parent(&store, &abspath)?;
        }
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| map_io_err_to_transport_err(e, Some(relpath)))?;
        let mut store = self.store.lock().unwrap();
        Self::check_parent(&store, &abspath)?;
        let len = buf.len() as u64;
        store
            .files
            .insert(abspath, (buf, perms_to_mode(permissions)));
        Ok(len)
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        let abspath = self.abspath_internal(relpath)?;
        let mut store = self.store.lock().unwrap();
        if store.files.remove(&abspath).is_some() {
            Ok(())
        } else if store.symlinks.remove(&abspath).is_some() {
            Ok(())
        } else {
            Err(Error::NoSuchFile(Some(relpath.to_string())))
        }
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        let abspath = self.resolve_symlinks(relpath)?;
        let mut store = self.store.lock().unwrap();
        if store.files.contains_key(&abspath) {
            return Err(Error::NotADirectoryError(Some(relpath.to_string())));
        }
        let prefix = format!("{}/", abspath);
        for path in store.files.keys().chain(store.symlinks.keys()) {
            if path.starts_with(&prefix) {
                return Err(Error::DirectoryNotEmptyError(Some(relpath.to_string())));
            }
        }
        for path in store.dirs.keys() {
            if path.starts_with(&prefix) && path != &abspath {
                return Err(Error::DirectoryNotEmptyError(Some(relpath.to_string())));
            }
        }
        if store.dirs.remove(&abspath).is_none() {
            return Err(Error::NoSuchFile(Some(relpath.to_string())));
        }
        Ok(())
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let abs_from = self.resolve_symlinks(rel_from)?;
        let abs_to = self.resolve_symlinks(rel_to)?;
        let from_prefix = format!("{}/", abs_from);

        let replace = |x: &str| -> String {
            if x == abs_from {
                abs_to.clone()
            } else if let Some(rest) = x.strip_prefix(&from_prefix) {
                format!("{}/{}", abs_to, rest)
            } else {
                x.to_string()
            }
        };

        let mut store = self.store.lock().unwrap();

        // Work on copies so rename is atomic on error.
        let mut files_new = store.files.clone();
        let mut symlinks_new = store.symlinks.clone();
        let mut dirs_new = store.dirs.clone();

        // Collect renames across all three containers, checking for collisions.
        let mut file_renames: Vec<(String, String)> = Vec::new();
        for path in store.files.keys() {
            let np = replace(path);
            if np != *path {
                if files_new.contains_key(&np) {
                    return Err(Error::FileExists(Some(np)));
                }
                file_renames.push((path.clone(), np));
            }
        }
        let mut symlink_renames: Vec<(String, String)> = Vec::new();
        for path in store.symlinks.keys() {
            let np = replace(path);
            if np != *path {
                if symlinks_new.contains_key(&np) {
                    return Err(Error::FileExists(Some(np)));
                }
                symlink_renames.push((path.clone(), np));
            }
        }
        let mut dir_renames: Vec<(String, String)> = Vec::new();
        for path in store.dirs.keys() {
            let np = replace(path);
            if np != *path {
                if dirs_new.contains_key(&np) {
                    return Err(Error::FileExists(Some(np)));
                }
                dir_renames.push((path.clone(), np));
            }
        }

        for (old, new) in file_renames {
            let v = files_new.remove(&old).unwrap();
            files_new.insert(new, v);
        }
        for (old, new) in symlink_renames {
            let v = symlinks_new.remove(&old).unwrap();
            symlinks_new.insert(new, v);
        }
        for (old, new) in dir_renames {
            let v = dirs_new.remove(&old).unwrap();
            dirs_new.insert(new, v);
        }

        store.files = files_new;
        store.symlinks = symlinks_new;
        store.dirs = dirs_new;
        Ok(())
    }

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()> {
        let (raw, mut params) = crate::urlutils::split_segment_parameters(self.base.as_str())?;
        if let Some(value) = value {
            params.insert(key, value);
        } else {
            params.remove(key);
        }
        self.base = Url::parse(&crate::urlutils::join_segment_parameters(raw, &params)?)?;
        Ok(())
    }

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>> {
        let (_, params) = crate::urlutils::split_segment_parameters(self.base.as_str())?;
        Ok(params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let abspath = self.resolve_symlinks(relpath)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| map_io_err_to_transport_err(e, Some(relpath)))?;
        let mut store = self.store.lock().unwrap();
        Self::check_parent(&store, &abspath)?;
        let (orig, orig_mode) = store
            .files
            .get(&abspath)
            .cloned()
            .unwrap_or_else(|| (Vec::new(), None));
        let orig_len = orig.len() as u64;
        let mode = match perms_to_mode(permissions) {
            Some(m) => Some(m),
            None => orig_mode,
        };
        let mut combined = orig;
        combined.extend_from_slice(&buf);
        store.files.insert(abspath, (combined, mode));
        Ok(orig_len)
    }

    fn readlink(&self, relpath: &UrlFragment) -> Result<String> {
        let abspath = self.abspath_internal(relpath)?;
        let store = self.store.lock().unwrap();
        match store.symlinks.get(&abspath) {
            Some(parts) => Ok(parts.join("/")),
            None => Err(Error::NoSuchFile(Some(relpath.to_string()))),
        }
    }

    fn hardlink(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible)
    }

    fn symlink(&self, source: &UrlFragment, link_name: &UrlFragment) -> Result<()> {
        let abspath = self.abspath_internal(link_name)?;
        let mut store = self.store.lock().unwrap();
        Self::check_parent(&store, &abspath)?;
        let target: Vec<String> = source.split('/').map(|s| s.to_string()).collect();
        store.symlinks.insert(abspath, target);
        Ok(())
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        let store = self.store.lock().unwrap();
        let cwd = self.cwd.clone();
        let mut results: Vec<String> = Vec::new();
        for path in store.files.keys().chain(store.symlinks.keys()) {
            if path.starts_with(&cwd) {
                let rest = &path[cwd.len()..];
                match escape(rest.as_bytes(), None) {
                    s if !s.is_empty() => results.push(s),
                    _ => {}
                }
            }
        }
        Box::new(results.into_iter().map(Ok))
    }

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        let abspath = self.resolve_symlinks(relpath)?;
        let mode = perms_to_mode(permissions);
        // Truncate any existing file and validate the parent exists; this
        // matches LocalTransport semantics (write streams start empty).
        {
            let mut store = self.store.lock().unwrap();
            Self::check_parent(&store, &abspath)?;
            store.files.insert(abspath.clone(), (Vec::new(), mode));
        }
        Ok(Box::new(MemoryWriteStream {
            store: Arc::clone(&self.store),
            abspath,
        }))
    }

    fn delete_tree(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(Error::TransportNotPossible)
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        let abspath = match self.resolve_symlinks(relpath) {
            Ok(p) => p,
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        let store = self.store.lock().unwrap();
        if abspath != "/" && !store.dirs.contains_key(&abspath) {
            return Box::new(std::iter::once(Err(Error::NoSuchFile(Some(
                relpath.to_string(),
            )))));
        }
        let prefix = if abspath.ends_with('/') {
            abspath.clone()
        } else {
            format!("{}/", abspath)
        };
        let mut results: Vec<String> = Vec::new();
        for group in [
            store.files.keys().collect::<Vec<_>>(),
            store.dirs.keys().collect::<Vec<_>>(),
            store.symlinks.keys().collect::<Vec<_>>(),
        ] {
            for path in group {
                if let Some(trailing) = path.strip_prefix(&prefix) {
                    if !trailing.is_empty() && !trailing.contains('/') {
                        results.push(escape(trailing.as_bytes(), None));
                    }
                }
            }
        }
        Box::new(results.into_iter().map(Ok))
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        let abspath = self.abspath_internal(relpath)?;
        acquire_lock(&self.store, &abspath)
    }

    fn lock_write(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        let abspath = self.abspath_internal(relpath)?;
        acquire_lock(&self.store, &abspath)
    }

    fn local_abspath(&self, relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        Err(Error::NotLocalUrl(format!("{}{}", self.base, relpath)))
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let data = self.get_bytes(rel_from)?;
        let mut cur = Cursor::new(data);
        self.put_file(rel_to, &mut cur, None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> MemoryTransport {
        MemoryTransport::new("memory:///").unwrap()
    }

    #[test]
    fn new_defaults_and_normalises_url() {
        let t = MemoryTransport::new("").unwrap();
        assert_eq!(t.base().as_str(), "memory:///");
        let t = MemoryTransport::new("memory:///foo").unwrap();
        assert_eq!(t.base().as_str(), "memory:///foo/");
    }

    #[test]
    fn put_get_has_and_stat_file() {
        let t = t();
        assert_eq!(t.has("hello").unwrap(), false);
        t.put_bytes("hello", b"world", None).unwrap();
        assert_eq!(t.has("hello").unwrap(), true);
        assert_eq!(t.get_bytes("hello").unwrap(), b"world");
        let st = t.stat("hello").unwrap();
        assert_eq!(st.size, 5);
        assert_eq!(st.kind, FileKind::File);
    }

    #[test]
    fn get_missing_returns_no_such_file() {
        let t = t();
        match t.get_bytes("nope") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn put_file_into_missing_parent_fails() {
        let t = t();
        match t.put_bytes("missing/child", b"x", None) {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn mkdir_and_list_dir() {
        let t = t();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/a", b"1", None).unwrap();
        t.put_bytes("d/b", b"22", None).unwrap();
        let mut entries: Vec<String> = t.list_dir("d").filter_map(|r| r.ok()).collect();
        entries.sort();
        assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(t.stat("d").unwrap().kind, FileKind::Dir);
    }

    #[test]
    fn mkdir_existing_fails() {
        let t = t();
        t.mkdir("d", None).unwrap();
        match t.mkdir("d", None) {
            Err(Error::FileExists(_)) => {}
            other => panic!("expected FileExists, got {:?}", other),
        }
    }

    #[test]
    fn delete_and_rmdir() {
        let t = t();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/f", b"x", None).unwrap();
        t.delete("d/f").unwrap();
        assert_eq!(t.has("d/f").unwrap(), false);
        t.rmdir("d").unwrap();
        assert_eq!(t.has("d").unwrap(), false);
    }

    #[test]
    fn rmdir_nonempty_fails() {
        let t = t();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/f", b"x", None).unwrap();
        match t.rmdir("d") {
            Err(Error::DirectoryNotEmptyError(_)) => {}
            other => panic!("expected DirectoryNotEmptyError, got {:?}", other),
        }
    }

    #[test]
    fn rename_file() {
        let t = t();
        t.put_bytes("a", b"hi", None).unwrap();
        t.rename("a", "b").unwrap();
        assert_eq!(t.has("a").unwrap(), false);
        assert_eq!(t.get_bytes("b").unwrap(), b"hi");
    }

    #[test]
    fn append_file_extends_content_and_returns_offset() {
        let t = t();
        t.put_bytes("f", b"abc", None).unwrap();
        let mut more = Cursor::new(b"DEF".to_vec());
        let offset = t.append_file("f", &mut more, None).unwrap();
        assert_eq!(offset, 3);
        assert_eq!(t.get_bytes("f").unwrap(), b"abcDEF");
    }

    #[test]
    fn symlink_and_readlink() {
        let t = t();
        t.put_bytes("target", b"data", None).unwrap();
        t.symlink("target", "link").unwrap();
        assert_eq!(t.readlink("link").unwrap(), "target");
        assert_eq!(t.stat("link").unwrap().kind, FileKind::Symlink);
        assert_eq!(t.get_bytes("link").unwrap(), b"data");
    }

    #[test]
    fn lock_read_contention() {
        let t = t();
        t.put_bytes("f", b"", None).unwrap();
        let _l = t.lock_read("f").ok().expect("first lock");
        match t.lock_read("f") {
            Err(Error::LockContention(_)) => {}
            Err(other) => panic!("expected LockContention, got {:?}", other),
            Ok(_) => panic!("expected LockContention, got Ok"),
        }
    }

    #[test]
    fn lock_release_allows_reacquire() {
        let t = t();
        t.put_bytes("f", b"", None).unwrap();
        {
            let mut l = t.lock_read("f").ok().expect("first lock");
            l.unlock().ok().expect("unlock");
        }
        let _l2 = t.lock_read("f").ok().expect("reacquire");
    }

    #[test]
    fn clone_shares_storage() {
        let t = t();
        t.mkdir("sub", None).unwrap();
        let c = t.clone(Some("sub")).unwrap();
        t.put_bytes("sub/f", b"shared", None).unwrap();
        assert_eq!(c.get_bytes("f").unwrap(), b"shared");
    }

    #[test]
    fn external_url_errors_in_process() {
        let t = t();
        match t.external_url() {
            Err(Error::InProcessTransport) => {}
            other => panic!("expected InProcessTransport, got {:?}", other),
        }
    }

    #[test]
    fn iter_files_recursive_lists_files_and_symlinks() {
        let t = t();
        t.mkdir("d", None).unwrap();
        t.put_bytes("d/a", b"1", None).unwrap();
        t.put_bytes("d/b", b"2", None).unwrap();
        t.symlink("d/a", "d/link").unwrap();
        let sub = t.clone(Some("d")).unwrap();
        let mut files: Vec<String> = sub.iter_files_recursive().filter_map(|r| r.ok()).collect();
        files.sort();
        assert_eq!(
            files,
            vec!["a".to_string(), "b".to_string(), "link".to_string()]
        );
    }

    #[test]
    fn open_write_stream_round_trip() {
        let t = t();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"hello ").unwrap();
        stream.write_all(b"world").unwrap();
        drop(stream);
        assert_eq!(t.get_bytes("w").unwrap(), b"hello world");
    }

    #[test]
    fn open_write_stream_visible_without_flush() {
        // The per_transport contract: a concurrent get_bytes after write
        // (no explicit flush) sees the in-flight bytes.
        let t = t();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"abc").unwrap();
        assert_eq!(t.get_bytes("w").unwrap(), b"abc");
        stream.write_all(b"def").unwrap();
        assert_eq!(t.get_bytes("w").unwrap(), b"abcdef");
    }

    #[test]
    fn open_write_stream_truncates_existing() {
        let t = t();
        t.put_bytes("w", b"old contents", None).unwrap();
        let mut stream = t.open_write_stream("w", None).unwrap();
        stream.write_all(b"new").unwrap();
        drop(stream);
        assert_eq!(t.get_bytes("w").unwrap(), b"new");
    }

    #[test]
    fn open_write_stream_rejects_missing_parent() {
        let t = t();
        match t.open_write_stream("missing/child", None) {
            Ok(_) => panic!("expected NoSuchFile, got Ok"),
            Err(Error::NoSuchFile(_)) => {}
            Err(other) => panic!("expected NoSuchFile, got {:?}", other),
        }
    }
}
