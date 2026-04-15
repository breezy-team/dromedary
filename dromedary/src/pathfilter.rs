//! Path-filtering Transport decorator, ported from dromedary/pathfilter.py.
//!
//! Wraps a backing transport and passes every relpath through a filter
//! function before delegating. The filter rebases relpaths against a
//! "server root" path derived from the transport's base URL. An optional
//! user-supplied callable can further rewrite paths (chroot omits it).

use crate::lock::Lock;
use crate::urlutils::combine_paths;
use crate::{Error, ReadStream, Result, SmartMedium, Stat, Transport, UrlFragment, WriteStream};
use std::collections::HashMap;
use std::fs::Permissions;
use url::Url;

pub type FilterFunc = Box<dyn Fn(&str) -> String + Send + Sync>;

pub struct PathFilteringTransport {
    backing: Box<dyn Transport + Send + Sync>,
    base_path: String,
    scheme: String,
    base: Url,
    filter_func: Option<FilterFunc>,
}

impl PathFilteringTransport {
    /// Construct a PathFilteringTransport.
    ///
    /// `scheme` is the URL scheme this transport exposes (e.g. "filtered-42:///"
    /// or "chroot-42:///"), `base_path` is the path portion of the transport's
    /// base URL (must start with `/`), and `filter_func` is an optional
    /// rewriter applied after the server-root rebase.
    pub fn new(
        backing: Box<dyn Transport + Send + Sync>,
        scheme: impl Into<String>,
        base_path: impl Into<String>,
        filter_func: Option<FilterFunc>,
    ) -> Result<Self> {
        let scheme = scheme.into();
        let mut base_path = base_path.into();
        if !base_path.starts_with('/') {
            return Err(Error::PathNotChild);
        }
        if !base_path.ends_with('/') {
            base_path.push('/');
        }
        // scheme is expected to end with ":///"; base_path starts with "/",
        // so join by stripping the leading slash of base_path.
        let base_url = format!("{}{}", scheme, &base_path[1..]);
        let base = Url::parse(&base_url).map_err(Error::from)?;
        Ok(Self {
            backing,
            base_path,
            scheme,
            base,
            filter_func,
        })
    }

    fn relpath_from_server_root(&self, relpath: &str) -> Result<String> {
        let unfiltered = combine_paths(&self.base_path, relpath);
        if !unfiltered.starts_with('/') {
            return Err(Error::PathNotChild);
        }
        let base_trimmed = self.base_path.trim_end_matches('/');
        if !base_trimmed.is_empty()
            && unfiltered != base_trimmed
            && !unfiltered.starts_with(&format!("{}/", base_trimmed))
        {
            return Err(Error::PathNotChild);
        }
        Ok(unfiltered[1..].to_string())
    }

    fn filter(&self, relpath: &str) -> Result<String> {
        let p = self.relpath_from_server_root(relpath)?;
        match &self.filter_func {
            Some(f) => Ok(f(&p)),
            None => Ok(p),
        }
    }
}

impl std::fmt::Debug for PathFilteringTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PathFilteringTransport({})", self.base)
    }
}

impl Transport for PathFilteringTransport {
    fn external_url(&self) -> Result<Url> {
        self.backing.external_url()
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        self.backing.can_roundtrip_unix_modebits()
    }

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn is_readonly(&self) -> bool {
        self.backing.is_readonly()
    }

    fn listable(&self) -> bool {
        self.backing.listable()
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        self.backing.get(&self.filter(relpath)?)
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        self.backing.has(&self.filter(relpath)?)
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        self.backing.stat(&self.filter(relpath)?)
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        // Clone of a path-filtering transport returns a backing-transport clone
        // rebased to the filtered offset. This matches Python's
        // `self.__class__(self.server, self.abspath(relpath))` well enough for
        // in-process use, but loses the filter wrapping. Callers that need a
        // filtered clone should reconstruct one.
        let target_relpath = match offset {
            Some(o) => self.relpath_from_server_root(o)?,
            None => self.relpath_from_server_root("")?,
        };
        self.backing.clone(Some(&target_relpath))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        // Deliberately unfiltered: filtering happens when the base is
        // resolved against the backing transport, not at abspath time.
        let p = self.relpath_from_server_root(relpath)?;
        let url = format!("{}{}", self.scheme, p);
        Url::parse(&url).map_err(Error::from)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        let base = self.base.as_str();
        let target = abspath.as_str();
        target
            .strip_prefix(base)
            .map(|s| s.to_string())
            .ok_or(Error::PathNotChild)
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.backing
            .put_file(&self.filter(relpath)?, f, permissions)
    }

    fn mkdir(&self, relpath: &UrlFragment, permissions: Option<Permissions>) -> Result<()> {
        self.backing.mkdir(&self.filter(relpath)?, permissions)
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        self.backing.delete(&self.filter(relpath)?)
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        self.backing.rmdir(&self.filter(relpath)?)
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.backing
            .rename(&self.filter(rel_from)?, &self.filter(rel_to)?)
    }

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()> {
        self.backing.set_segment_parameter(key, value)
    }

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>> {
        self.backing.get_segment_parameters()
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.backing
            .append_file(&self.filter(relpath)?, f, permissions)
    }

    fn readlink(&self, relpath: &UrlFragment) -> Result<String> {
        self.backing.readlink(&self.filter(relpath)?)
    }

    fn hardlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.backing
            .hardlink(&self.filter(rel_from)?, &self.filter(rel_to)?)
    }

    fn symlink(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.backing
            .symlink(&self.filter(rel_from)?, &self.filter(rel_to)?)
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        // Clone the backing transport to the filtered "." path and let it
        // walk from there.
        let filtered = match self.filter(".") {
            Ok(p) => p,
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        match self.backing.clone(Some(&filtered)) {
            Ok(cloned) => cloned.iter_files_recursive(),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        self.backing
            .open_write_stream(&self.filter(relpath)?, permissions)
    }

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()> {
        self.backing.delete_tree(&self.filter(relpath)?)
    }

    fn r#move(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.backing
            .r#move(&self.filter(rel_from)?, &self.filter(rel_to)?)
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        match self.filter(relpath) {
            Ok(p) => self.backing.list_dir(&p),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        self.backing.lock_read(&self.filter(relpath)?)
    }

    fn lock_write(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        self.backing.lock_write(&self.filter(relpath)?)
    }

    fn local_abspath(&self, relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        self.backing.local_abspath(&self.filter(relpath)?)
    }

    fn get_smart_medium(&self) -> Result<Box<dyn SmartMedium>> {
        self.backing.get_smart_medium()
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.backing
            .copy(&self.filter(rel_from)?, &self.filter(rel_to)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn backing_with(files: &[(&str, &[u8])]) -> Box<dyn Transport + Send + Sync> {
        let mem = MemoryTransport::new("memory:///").unwrap();
        for (p, data) in files {
            // Ensure parents exist.
            if let Some(parent) = std::path::Path::new(p).parent() {
                let parent = parent.to_string_lossy().to_string();
                if !parent.is_empty() {
                    let _ = mem.mkdir(&parent, None);
                }
            }
            mem.put_bytes(p, data, None).unwrap();
        }
        Box::new(mem)
    }

    fn make(base_path: &str, filter: Option<FilterFunc>) -> PathFilteringTransport {
        let backing = backing_with(&[("a", b"A"), ("sub/b", b"B")]);
        PathFilteringTransport::new(backing, "filtered-1:///", base_path, filter).unwrap()
    }

    #[test]
    fn pass_through_filter_none() {
        let t = make("/", None);
        assert_eq!(t.get_bytes("a").unwrap(), b"A");
        assert_eq!(t.has("sub/b").unwrap(), true);
    }

    #[test]
    fn rebases_under_subdirectory() {
        let t = make("/sub/", None);
        assert_eq!(t.get_bytes("b").unwrap(), b"B");
        match t.get_bytes("a") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn filter_func_rewrites_path() {
        // Filter prepends "sub/" to every relpath; starting from root that
        // means every get effectively reads from /sub/...
        let filter: FilterFunc = Box::new(|p: &str| format!("sub/{}", p));
        let t = make("/", Some(filter));
        assert_eq!(t.get_bytes("b").unwrap(), b"B");
    }

    #[test]
    fn mkdir_and_delete_round_trip() {
        let t = make("/", None);
        t.mkdir("new", None).unwrap();
        t.put_bytes("new/f", b"x", None).unwrap();
        assert_eq!(t.get_bytes("new/f").unwrap(), b"x");
        t.delete("new/f").unwrap();
        assert_eq!(t.has("new/f").unwrap(), false);
        t.rmdir("new").unwrap();
    }

    #[test]
    fn list_dir_passes_through() {
        let t = make("/", None);
        let mut entries: Vec<String> = t.list_dir("sub").filter_map(|r| r.ok()).collect();
        entries.sort();
        assert_eq!(entries, vec!["b".to_string()]);
    }

    #[test]
    fn iter_files_recursive_uses_filtered_root() {
        let t = make("/sub/", None);
        let mut files: Vec<String> = t.iter_files_recursive().filter_map(|r| r.ok()).collect();
        files.sort();
        assert_eq!(files, vec!["b".to_string()]);
    }

    #[test]
    fn abspath_is_not_filtered() {
        let filter: FilterFunc = Box::new(|p: &str| format!("sub/{}", p));
        let t = make("/", Some(filter));
        let u = t.abspath("x").unwrap();
        assert!(u.as_str().ends_with("/x"), "got {}", u);
    }

    #[test]
    fn is_readonly_forwards() {
        let t = make("/", None);
        assert_eq!(t.is_readonly(), false);
    }

    #[test]
    fn base_path_must_start_with_slash() {
        let backing = backing_with(&[]);
        match PathFilteringTransport::new(backing, "filtered-1:///", "sub", None) {
            Err(Error::PathNotChild) => {}
            other => panic!("expected PathNotChild, got {:?}", other),
        }
    }
}
