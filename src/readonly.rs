//! Readonly Transport decorator, ported from dromedary/readonly.py.
//!
//! Wraps any Transport and rejects every mutation with TransportNotPossible,
//! forwarding read-only operations unchanged.

use crate::lock::Lock;
use crate::{Error, ReadStream, Result, Stat, Transport, UrlFragment, WriteStream};
use std::collections::HashMap;
use std::fs::Permissions;
use url::Url;

pub struct ReadonlyTransport {
    decorated: Box<dyn Transport + Send + Sync>,
    base: Url,
}

impl ReadonlyTransport {
    const PREFIX: &'static str = "readonly+";

    pub fn new(decorated: Box<dyn Transport + Send + Sync>) -> Self {
        let inner_base = decorated.base();
        let base =
            Url::parse(&format!("{}{}", Self::PREFIX, inner_base)).unwrap_or(inner_base.clone());
        Self { decorated, base }
    }
}

impl std::fmt::Debug for ReadonlyTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ReadonlyTransport({})", self.base)
    }
}

fn not_possible() -> Error {
    Error::TransportNotPossible
}

impl Transport for ReadonlyTransport {
    fn external_url(&self) -> Result<Url> {
        self.decorated.external_url()
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        self.decorated.can_roundtrip_unix_modebits()
    }

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn is_readonly(&self) -> bool {
        true
    }

    crate::fwd_listable!(decorated);

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        self.decorated.get(relpath)
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        self.decorated.has(relpath)
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        self.decorated.stat(relpath)
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        let inner_clone = self.decorated.clone(offset)?;
        Ok(Box::new(ReadonlyTransport::new(inner_clone)))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        crate::decorator::prefixed_abspath(Self::PREFIX, self.decorated.as_ref(), relpath)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        crate::decorator::stripped_relpath(Self::PREFIX, self.decorated.as_ref(), abspath)
    }

    fn put_file(
        &self,
        _relpath: &UrlFragment,
        _f: &mut dyn std::io::Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        Err(not_possible())
    }

    fn mkdir(&self, _relpath: &UrlFragment, _permissions: Option<Permissions>) -> Result<()> {
        Err(not_possible())
    }

    fn delete(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn rmdir(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn rename(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()> {
        // Forwarding a &mut call to the inner transport is awkward with a
        // Box<dyn Transport>; defer to the inner via the mutable reference
        // we hold.
        self.decorated.set_segment_parameter(key, value)
    }

    fn get_segment_parameters(&self) -> Result<HashMap<String, String>> {
        self.decorated.get_segment_parameters()
    }

    fn append_file(
        &self,
        _relpath: &UrlFragment,
        _f: &mut dyn std::io::Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        Err(not_possible())
    }

    fn readlink(&self, relpath: &UrlFragment) -> Result<String> {
        self.decorated.readlink(relpath)
    }

    fn hardlink(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn symlink(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        self.decorated.iter_files_recursive()
    }

    fn open_write_stream(
        &self,
        _relpath: &UrlFragment,
        _permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        Err(not_possible())
    }

    fn delete_tree(&self, _relpath: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn r#move(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        self.decorated.list_dir(relpath)
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        self.decorated.lock_read(relpath)
    }

    fn lock_write(&self, _relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        Err(not_possible())
    }

    fn local_abspath(&self, relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        self.decorated.local_abspath(relpath)
    }

    fn copy(&self, _rel_from: &UrlFragment, _rel_to: &UrlFragment) -> Result<()> {
        Err(not_possible())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn ro() -> ReadonlyTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("hello", b"world", None).unwrap();
        ReadonlyTransport::new(Box::new(mem))
    }

    #[test]
    fn reads_pass_through() {
        let t = ro();
        assert_eq!(t.get_bytes("hello").unwrap(), b"world");
        assert_eq!(t.has("hello").unwrap(), true);
        assert_eq!(t.has("missing").unwrap(), false);
    }

    #[test]
    fn is_readonly_returns_true() {
        assert!(ro().is_readonly());
    }

    #[test]
    fn put_bytes_rejected() {
        match ro().put_bytes("x", b"y", None) {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn mkdir_rejected() {
        match ro().mkdir("d", None) {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn delete_rejected() {
        match ro().delete("hello") {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn rename_rejected() {
        match ro().rename("hello", "world") {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn lock_read_passes_but_lock_write_rejected() {
        let t = ro();
        let _l = t.lock_read("hello").ok().expect("read lock");
        match t.lock_write("hello") {
            Err(Error::TransportNotPossible) => {}
            Err(other) => panic!("expected TransportNotPossible, got {:?}", other),
            Ok(_) => panic!("expected TransportNotPossible, got Ok"),
        }
    }

    #[test]
    fn base_has_readonly_prefix() {
        let t = ro();
        assert!(t.base().as_str().starts_with("readonly+"));
    }

    #[test]
    fn abspath_carries_prefix() {
        // The Python decorator contract is: decorator.base + relpath ==
        // decorator.abspath(relpath). Regression guard for a bug where
        // abspath used to forward straight to the inner transport and
        // dropped the `readonly+` prefix.
        let t = ro();
        let abs = t.abspath("relpath").unwrap();
        assert_eq!(abs.as_str(), "readonly+memory:///relpath");
    }

    #[test]
    fn relpath_round_trips_through_abspath() {
        let t = ro();
        let abs = t.abspath("sub/file").unwrap();
        assert_eq!(t.relpath(&abs).unwrap(), "sub/file");
    }

    #[test]
    fn clone_keeps_readonly_wrapping() {
        // Cloning must return another readonly transport rather than
        // silently dropping down to the inner, otherwise callers can bypass
        // readonly enforcement just by cloning.
        let t = ro();
        let cloned = t.clone(Some("subdir")).unwrap();
        assert!(cloned.base().as_str().starts_with("readonly+"));
        assert!(cloned.is_readonly());
    }

    fn expect_not_possible<T: std::fmt::Debug>(r: Result<T>, label: &str) {
        match r {
            Err(Error::TransportNotPossible) => {}
            Err(other) => panic!("{}: expected TransportNotPossible, got {:?}", label, other),
            Ok(ok) => panic!("{}: expected TransportNotPossible, got Ok({:?})", label, ok),
        }
    }

    #[test]
    fn rmdir_rejected() {
        // Seed the inner store with a directory we could otherwise remove.
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.mkdir("d", None).unwrap();
        let t = ReadonlyTransport::new(Box::new(mem));
        expect_not_possible(t.rmdir("d"), "rmdir");
    }

    #[test]
    fn delete_tree_rejected() {
        expect_not_possible(ro().delete_tree("hello"), "delete_tree");
    }

    #[test]
    fn symlink_rejected() {
        expect_not_possible(ro().symlink("hello", "link"), "symlink");
    }

    #[test]
    fn hardlink_rejected() {
        expect_not_possible(ro().hardlink("hello", "link"), "hardlink");
    }

    #[test]
    fn append_file_rejected() {
        let mut cur = std::io::Cursor::new(b"more".to_vec());
        expect_not_possible(ro().append_file("hello", &mut cur, None), "append_file");
    }

    #[test]
    fn append_bytes_rejected() {
        expect_not_possible(ro().append_bytes("hello", b"more", None), "append_bytes");
    }

    #[test]
    fn open_write_stream_rejected() {
        match ro().open_write_stream("hello", None) {
            Err(Error::TransportNotPossible) => {}
            Err(other) => panic!("expected TransportNotPossible, got {:?}", other),
            Ok(_) => panic!("expected TransportNotPossible, got Ok"),
        }
    }

    #[test]
    fn move_rejected() {
        expect_not_possible(ro().r#move("hello", "world"), "move");
    }

    #[test]
    fn copy_rejected() {
        expect_not_possible(ro().copy("hello", "world"), "copy");
    }

    #[test]
    fn stat_passes_through() {
        let st = ro().stat("hello").unwrap();
        assert_eq!(st.size, 5);
    }

    #[test]
    fn list_dir_passes_through() {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.mkdir("d", None).unwrap();
        mem.put_bytes("d/a", b"1", None).unwrap();
        mem.put_bytes("d/b", b"2", None).unwrap();
        let t = ReadonlyTransport::new(Box::new(mem));
        let mut entries: Vec<String> = t.list_dir("d").filter_map(|r| r.ok()).collect();
        entries.sort();
        assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn iter_files_recursive_passes_through() {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("a", b"1", None).unwrap();
        mem.put_bytes("b", b"2", None).unwrap();
        let t = ReadonlyTransport::new(Box::new(mem));
        let mut files: Vec<String> = t.iter_files_recursive().filter_map(|r| r.ok()).collect();
        files.sort();
        assert_eq!(files, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn external_url_forwards_error() {
        // MemoryTransport returns InProcessTransport; readonly should forward it.
        match ro().external_url() {
            Err(Error::InProcessTransport) => {}
            other => panic!("expected InProcessTransport, got {:?}", other),
        }
    }

    #[test]
    fn get_missing_forwards_no_such_file() {
        match ro().get_bytes("nope") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }
}
