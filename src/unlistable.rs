//! Unlistable Transport decorator, ported from dromedary/unlistable.py.
//!
//! A transport that disables directory listing, to simulate HTTP cheaply
//! in tests. `listable()` returns false; `list_dir` and
//! `iter_files_recursive` both yield a single TransportNotPossible error.

use crate::{Error, Result, Transport, UrlFragment};
use url::Url;

pub struct UnlistableTransport {
    inner: Box<dyn Transport + Send + Sync>,
    base: Url,
}

impl UnlistableTransport {
    pub const PREFIX: &'static str = "unlistable+";

    pub fn new(inner: Box<dyn Transport + Send + Sync>) -> Self {
        let base = crate::decorator::prefixed_base(Self::PREFIX, inner.as_ref());
        Self { inner, base }
    }
}

impl std::fmt::Debug for UnlistableTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "UnlistableTransport({})", self.base)
    }
}

impl Transport for UnlistableTransport {
    crate::fwd_external_url!(inner);
    crate::fwd_can_roundtrip_unix_modebits!(inner);
    crate::fwd_is_readonly!(inner);
    crate::fwd_get!(inner);
    crate::fwd_has!(inner);
    crate::fwd_stat!(inner);
    crate::fwd_decorator_url!(inner, UnlistableTransport);
    crate::fwd_put_file!(inner);
    crate::fwd_mkdir!(inner);
    crate::fwd_delete!(inner);
    crate::fwd_rmdir!(inner);
    crate::fwd_rename!(inner);
    crate::fwd_set_segment_parameter!(inner);
    crate::fwd_get_segment_parameters!(inner);
    crate::fwd_append_file!(inner);
    crate::fwd_readlink!(inner);
    crate::fwd_hardlink!(inner);
    crate::fwd_symlink!(inner);
    crate::fwd_open_write_stream!(inner);
    crate::fwd_delete_tree!(inner);
    crate::fwd_move!(inner);
    crate::fwd_lock_read!(inner);
    crate::fwd_lock_write!(inner);
    crate::fwd_local_abspath!(inner);
    crate::fwd_copy!(inner);

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn listable(&self) -> bool {
        false
    }

    fn list_dir(&self, _relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        Box::new(std::iter::once(Err(Error::TransportNotPossible)))
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        Box::new(std::iter::once(Err(Error::TransportNotPossible)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn wrap() -> UnlistableTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("a", b"1", None).unwrap();
        mem.put_bytes("b", b"2", None).unwrap();
        UnlistableTransport::new(Box::new(mem))
    }

    #[test]
    fn base_prefix() {
        assert!(wrap().base().as_str().starts_with("unlistable+"));
    }

    #[test]
    fn listable_returns_false() {
        assert_eq!(wrap().listable(), false);
    }

    #[test]
    fn list_dir_yields_not_possible() {
        let t = wrap();
        let results: Vec<Result<String>> = t.list_dir(".").collect();
        assert_eq!(results.len(), 1);
        match &results[0] {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn iter_files_recursive_yields_not_possible() {
        let t = wrap();
        let results: Vec<Result<String>> = t.iter_files_recursive().collect();
        assert_eq!(results.len(), 1);
        match &results[0] {
            Err(Error::TransportNotPossible) => {}
            other => panic!("expected TransportNotPossible, got {:?}", other),
        }
    }

    #[test]
    fn reads_pass_through() {
        let t = wrap();
        assert_eq!(t.get_bytes("a").unwrap(), b"1");
    }

    #[test]
    fn abspath_carries_prefix() {
        let t = wrap();
        assert_eq!(
            t.abspath("relpath").unwrap().as_str(),
            "unlistable+memory:///relpath"
        );
    }

    #[test]
    fn clone_keeps_unlistable_wrapping() {
        let t = wrap();
        let cloned = t.clone(Some("sub")).unwrap();
        assert!(cloned.base().as_str().starts_with("unlistable+"));
        assert_eq!(cloned.listable(), false);
    }
}
