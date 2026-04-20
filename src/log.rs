//! Transport decorator that logs each operation, ported from
//! `dromedary/log.py`.
//!
//! [`LogTransport`] wraps any Transport and emits a debug line per call
//! via a user-supplied sink. The sink is a closure rather than a direct
//! dependency on Python's `logging` module so this module stays usable
//! from pure-Rust callers; the PyO3 wrapper in
//! `_transport_rs::log` supplies a sink that forwards to
//! `dromedary.log.logger.debug`.

use crate::lock::Lock;
use crate::{Error, ReadStream, Result, Stat, Transport, UrlFragment, WriteStream};
use std::fs::Permissions;
use std::io::Read;
use std::sync::Arc;
use url::Url;

/// Message sink for a LogTransport. Wrapped in `Arc` so that clones of a
/// LogTransport (produced via `Transport::clone`) can continue logging
/// through the same sink as the original.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

pub struct LogTransport {
    inner: Box<dyn Transport + Send + Sync>,
    base: Url,
    sink: LogSink,
}

impl LogTransport {
    pub const PREFIX: &'static str = "log+";

    pub fn new(inner: Box<dyn Transport + Send + Sync>, sink: LogSink) -> Self {
        let base = crate::decorator::prefixed_base(Self::PREFIX, inner.as_ref());
        Self { inner, base, sink }
    }

    fn log_call(&self, method: &str, relpath: &str, extra: &str) {
        let msg = if extra.is_empty() {
            format!("{} {} ", method, relpath)
        } else {
            format!("{} {} {}", method, relpath, extra)
        };
        (self.sink)(&msg);
    }

    fn log_result(&self, summary: &str) {
        (self.sink)(&format!("  --> {}", shorten(summary)));
    }

    fn log_error(&self, err: &Error) {
        (self.sink)(&format!("  --> {:?}", err));
    }
}

impl std::fmt::Debug for LogTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LogTransport({})", self.base)
    }
}

/// Trim long single-line repr output to match the Python `_shorten` helper.
pub fn shorten(s: &str) -> String {
    if s.chars().count() > 70 {
        // Match Python's character-based slice (s[:67] + "...").
        let end: usize = s.char_indices().nth(67).map(|(i, _)| i).unwrap_or(s.len());
        let mut out = String::with_capacity(end + 3);
        out.push_str(&s[..end]);
        out.push_str("...");
        out
    } else {
        s.to_string()
    }
}

/// Strip the enclosing parentheses of a Python tuple repr. Mirrors
/// `_strip_tuple_parens` in the Python implementation.
pub fn strip_tuple_parens(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'(' && bytes[bytes.len() - 1] == b')' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Method names that the Python decorator wraps with the per-call logger.
/// Exposed so the PyO3 layer (which owns the Python wrapper) can share the
/// same list instead of duplicating it.
pub const LOGGED_METHODS: &[&str] = &[
    "append_bytes",
    "append_file",
    "copy_to",
    "delete",
    "get",
    "has",
    "open_write_stream",
    "mkdir",
    "move",
    "put_bytes",
    "put_bytes_non_atomic",
    "put_file",
    "put_file_non_atomic",
    "list_dir",
    "lock_read",
    "lock_write",
    "readv",
    "rename",
    "rmdir",
    "stat",
    "ulock",
];

impl Transport for LogTransport {
    crate::fwd_external_url!(inner);
    crate::fwd_can_roundtrip_unix_modebits!(inner);
    crate::fwd_is_readonly!(inner);
    crate::fwd_listable!(inner);
    crate::fwd_set_segment_parameter!(inner);
    crate::fwd_get_segment_parameters!(inner);
    crate::fwd_readlink!(inner);
    crate::fwd_hardlink!(inner);
    crate::fwd_symlink!(inner);
    crate::fwd_local_abspath!(inner);

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        crate::decorator::prefixed_abspath(Self::PREFIX, self.inner.as_ref(), relpath)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        crate::decorator::stripped_relpath(Self::PREFIX, self.inner.as_ref(), abspath)
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        let inner_clone = self.inner.clone(offset)?;
        Ok(Box::new(LogTransport::new(
            inner_clone,
            Arc::clone(&self.sink),
        )))
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        self.log_call("get", relpath, "");
        match self.inner.get(relpath) {
            Ok(s) => {
                self.log_result("<stream>");
                Ok(s)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        self.log_call("has", relpath, "");
        match self.inner.has(relpath) {
            Ok(v) => {
                self.log_result(if v { "True" } else { "False" });
                Ok(v)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        self.log_call("stat", relpath, "");
        match self.inner.stat(relpath) {
            Ok(s) => {
                self.log_result("<stat>");
                Ok(s)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.log_call("put_file", relpath, "");
        match self.inner.put_file(relpath, f, permissions) {
            Ok(n) => {
                self.log_result(&n.to_string());
                Ok(n)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn mkdir(&self, relpath: &UrlFragment, permissions: Option<Permissions>) -> Result<()> {
        self.log_call("mkdir", relpath, "");
        match self.inner.mkdir(relpath, permissions) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        self.log_call("delete", relpath, "");
        match self.inner.delete(relpath) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        self.log_call("rmdir", relpath, "");
        match self.inner.rmdir(relpath) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.log_call("rename", rel_from, rel_to);
        match self.inner.rename(rel_from, rel_to) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.log_call("append_file", relpath, "");
        match self.inner.append_file(relpath, f, permissions) {
            Ok(n) => {
                self.log_result(&n.to_string());
                Ok(n)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        // Mirrors the Python override that logs without a relpath.
        (self.sink)(&format!("iter_files_recursive {}", self.base));
        let results: Vec<Result<String>> = self.inner.iter_files_recursive().collect();
        let summary = format!("{} entries", results.len());
        self.log_result(&summary);
        Box::new(results.into_iter())
    }

    fn open_write_stream(
        &self,
        relpath: &UrlFragment,
        permissions: Option<Permissions>,
    ) -> Result<Box<dyn WriteStream + Send + Sync>> {
        self.log_call("open_write_stream", relpath, "");
        match self.inner.open_write_stream(relpath, permissions) {
            Ok(s) => {
                self.log_result("<stream>");
                Ok(s)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()> {
        self.log_call("delete_tree", relpath, "");
        match self.inner.delete_tree(relpath) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn r#move(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.log_call("move", rel_from, rel_to);
        match self.inner.r#move(rel_from, rel_to) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        self.log_call("list_dir", relpath, "");
        let results: Vec<Result<String>> = self.inner.list_dir(relpath).collect();
        let summary = format!("{} entries", results.len());
        self.log_result(&summary);
        Box::new(results.into_iter())
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        self.log_call("lock_read", relpath, "");
        match self.inner.lock_read(relpath) {
            Ok(l) => {
                self.log_result("<lock>");
                Ok(l)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn lock_write(&self, relpath: &UrlFragment) -> Result<Box<dyn Lock + Send + Sync>> {
        self.log_call("lock_write", relpath, "");
        match self.inner.lock_write(relpath) {
            Ok(l) => {
                self.log_result("<lock>");
                Ok(l)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        self.log_call("copy", rel_from, rel_to);
        match self.inner.copy(rel_from, rel_to) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn readv<'a>(
        &self,
        relpath: &'a UrlFragment,
        offsets: Vec<(u64, usize)>,
        adjust_for_latency: bool,
        upper_limit: Option<u64>,
    ) -> Box<dyn Iterator<Item = Result<(u64, Vec<u8>)>> + Send + 'a> {
        self.log_call("readv", relpath, "");
        // Collect so we can log the summary before yielding. Matches the
        // Python decorator which consumes the generator eagerly and returns
        // a fresh iterator.
        let results: Vec<Result<(u64, Vec<u8>)>> = self
            .inner
            .readv(relpath, offsets, adjust_for_latency, upper_limit)
            .collect();
        let (hunks, bytes) = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .fold((0usize, 0usize), |(h, b), (_, d)| (h + 1, b + d.len()));
        let summary = format!("readv response, {} hunks, {} total bytes", hunks, bytes);
        self.log_result(&summary);
        Box::new(results.into_iter())
    }

    fn put_bytes(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<()> {
        self.log_call("put_bytes", relpath, "");
        match self.inner.put_bytes(relpath, data, permissions) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    fn append_bytes(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.log_call("append_bytes", relpath, "");
        match self.inner.append_bytes(relpath, data, permissions) {
            Ok(n) => {
                self.log_result(&n.to_string());
                Ok(n)
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }

    // Forward the *_non_atomic variants to the inner transport rather than
    // relying on the trait default. The default retries self.put_file after
    // a NoSuchFile, which would log twice and — when the inner is a
    // PyTransport — also consume the caller's stream on the first attempt,
    // leaving the retry with an empty reader. Delegating keeps the
    // non-atomic operation atomic from the inner's perspective.
    fn put_file_non_atomic(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        self.log_call("put_file_non_atomic", relpath, "");
        match self.inner.put_file_non_atomic(
            relpath,
            f,
            permissions,
            create_parent_dir,
            dir_permissions,
        ) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
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
        self.log_call("put_bytes_non_atomic", relpath, "");
        match self.inner.put_bytes_non_atomic(
            relpath,
            data,
            permissions,
            create_parent_dir,
            dir_permissions,
        ) {
            Ok(()) => {
                self.log_result("None");
                Ok(())
            }
            Err(e) => {
                self.log_error(&e);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;
    use std::sync::{Arc, Mutex};

    fn capturing_sink() -> (Arc<Mutex<Vec<String>>>, LogSink) {
        let buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_cl = Arc::clone(&buf);
        let sink: LogSink = Arc::new(move |msg: &str| buf_cl.lock().unwrap().push(msg.to_string()));
        (buf, sink)
    }

    fn wrap() -> (Arc<Mutex<Vec<String>>>, LogTransport) {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("hello", b"world", None).unwrap();
        let (buf, sink) = capturing_sink();
        (buf, LogTransport::new(Box::new(mem), sink))
    }

    #[test]
    fn base_has_log_prefix() {
        let (_buf, t) = wrap();
        assert!(t.base().as_str().starts_with("log+"));
    }

    #[test]
    fn mkdir_is_logged_with_result() {
        let (buf, t) = wrap();
        t.mkdir("subdir", None).unwrap();
        let log = buf.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.starts_with("mkdir subdir")));
        assert!(log.iter().any(|l| l == "  --> None"));
    }

    #[test]
    fn has_logs_true_and_false() {
        let (buf, t) = wrap();
        assert!(t.has("hello").unwrap());
        assert!(!t.has("missing").unwrap());
        let log = buf.lock().unwrap().clone();
        assert!(log.iter().any(|l| l == "  --> True"));
        assert!(log.iter().any(|l| l == "  --> False"));
    }

    #[test]
    fn readv_summary_matches_python_format() {
        let (buf, t) = wrap();
        let results: Vec<_> = t.readv("hello", vec![(0, 5)], false, None).collect();
        assert_eq!(results.len(), 1);
        let log = buf.lock().unwrap().clone();
        assert!(log
            .iter()
            .any(|l| l == "  --> readv response, 1 hunks, 5 total bytes"));
    }

    #[test]
    fn error_is_logged() {
        let (buf, t) = wrap();
        let _ = t.get_bytes("nope");
        let log = buf.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.starts_with("  --> ")));
        assert!(log.iter().any(|l| l.starts_with("get nope")));
    }

    #[test]
    fn shorten_truncates_long_strings() {
        let long: String = "a".repeat(100);
        let out = shorten(&long);
        assert_eq!(out.len(), 70);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn shorten_leaves_short_strings_alone() {
        assert_eq!(shorten("short"), "short");
    }

    #[test]
    fn strip_tuple_parens_strips_and_skips() {
        assert_eq!(strip_tuple_parens("(1, 2, 3)"), "1, 2, 3");
        assert_eq!(strip_tuple_parens("not a tuple"), "not a tuple");
        assert_eq!(strip_tuple_parens("()"), "");
    }

    #[test]
    fn list_dir_logs_entry_count() {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.mkdir("d", None).unwrap();
        mem.put_bytes("d/a", b"1", None).unwrap();
        mem.put_bytes("d/b", b"2", None).unwrap();
        let (buf, sink) = capturing_sink();
        let t = LogTransport::new(Box::new(mem), sink);
        let entries: Vec<_> = t.list_dir("d").filter_map(|r| r.ok()).collect();
        assert_eq!(entries.len(), 2);
        let log = buf.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.starts_with("list_dir d")));
        assert!(log.iter().any(|l| l == "  --> 2 entries"));
    }

    #[test]
    fn abspath_carries_prefix() {
        let (_buf, t) = wrap();
        assert_eq!(
            t.abspath("relpath").unwrap().as_str(),
            "log+memory:///relpath"
        );
    }

    #[test]
    fn clone_keeps_log_wrapping_and_shares_sink() {
        // The clone should continue emitting through the original sink so
        // that a single logger captures both the parent and cloned
        // transport's activity.
        let (buf, t) = wrap();
        let cloned = t.clone(Some("sub")).unwrap();
        assert!(cloned.base().as_str().starts_with("log+"));
        let _ = cloned.has("anything");
        let log = buf.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.starts_with("has anything")));
    }
}
