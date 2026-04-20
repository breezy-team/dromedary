//! FakeNFS Transport decorator, ported from dromedary/fakenfs.py.
//!
//! Adapts any Transport to behave like NFS for testing: rename against a
//! non-empty target directory raises ResourceBusy, and deleting a file
//! whose basename starts with ".nfs" raises ResourceBusy.

use crate::{Error, Result, Stat, Transport, UrlFragment};
use url::Url;

pub struct FakeNfsTransport {
    inner: Box<dyn Transport + Send + Sync>,
    base: Url,
}

impl FakeNfsTransport {
    pub const PREFIX: &'static str = "fakenfs+";

    pub fn new(inner: Box<dyn Transport + Send + Sync>) -> Self {
        let base = crate::decorator::prefixed_base(Self::PREFIX, inner.as_ref());
        Self { inner, base }
    }
}

impl std::fmt::Debug for FakeNfsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "FakeNfsTransport({})", self.base)
    }
}

fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, tail)) => tail,
        None => path,
    }
}

impl Transport for FakeNfsTransport {
    crate::fwd_external_url!(inner);
    crate::fwd_can_roundtrip_unix_modebits!(inner);
    crate::fwd_is_readonly!(inner);
    crate::fwd_listable!(inner);
    crate::fwd_get!(inner);
    crate::fwd_has!(inner);
    crate::fwd_stat!(inner);
    crate::fwd_decorator_url!(inner, FakeNfsTransport);
    crate::fwd_put_file!(inner);
    crate::fwd_put_bytes!(inner);
    crate::fwd_put_file_non_atomic!(inner);
    crate::fwd_put_bytes_non_atomic!(inner);
    crate::fwd_mkdir!(inner);
    crate::fwd_rmdir!(inner);
    crate::fwd_set_segment_parameter!(inner);
    crate::fwd_get_segment_parameters!(inner);
    crate::fwd_append_file!(inner);
    crate::fwd_readlink!(inner);
    crate::fwd_hardlink!(inner);
    crate::fwd_symlink!(inner);
    crate::fwd_iter_files_recursive!(inner);
    crate::fwd_open_write_stream!(inner);
    crate::fwd_delete_tree!(inner);
    crate::fwd_move!(inner);
    crate::fwd_list_dir!(inner);
    crate::fwd_lock_read!(inner);
    crate::fwd_lock_write!(inner);
    crate::fwd_local_abspath!(inner);
    crate::fwd_copy!(inner);

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        match self.inner.rename(rel_from, rel_to) {
            Ok(()) => Ok(()),
            Err(e @ Error::DirectoryNotEmptyError(_)) | Err(e @ Error::FileExists(_)) => {
                match self.inner.stat(rel_to) {
                    Ok(Stat { kind, .. }) if kind == crate::FileKind::Dir => {
                        Err(Error::ResourceBusy(Some(rel_to.to_string())))
                    }
                    _ => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        if basename(relpath).starts_with(".nfs") {
            return Err(Error::ResourceBusy(Some(relpath.to_string())));
        }
        self.inner.delete(relpath)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn wrap() -> FakeNfsTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("regular", b"x", None).unwrap();
        mem.put_bytes(".nfs1234", b"busy", None).unwrap();
        mem.mkdir("dir1", None).unwrap();
        mem.mkdir("dir2", None).unwrap();
        mem.put_bytes("f1", b"a", None).unwrap();
        mem.put_bytes("f2", b"b", None).unwrap();
        FakeNfsTransport::new(Box::new(mem))
    }

    #[test]
    fn base_has_fakenfs_prefix() {
        assert!(wrap().base().as_str().starts_with("fakenfs+"));
    }

    #[test]
    fn regular_delete_passes_through() {
        wrap().delete("regular").unwrap();
    }

    #[test]
    fn dotnfs_delete_is_busy() {
        match wrap().delete(".nfs1234") {
            Err(Error::ResourceBusy(_)) => {}
            other => panic!("expected ResourceBusy, got {:?}", other),
        }
    }

    #[test]
    fn rename_dir_over_dir_becomes_busy() {
        let t = wrap();
        match t.rename("dir1", "dir2") {
            Err(Error::ResourceBusy(_)) => {}
            other => panic!("expected ResourceBusy, got {:?}", other),
        }
    }

    #[test]
    fn rename_file_over_file_propagates_original_error() {
        // Destination is a file, so the translator's stat check falls through
        // and the original FileExists is re-raised.
        let t = wrap();
        match t.rename("f1", "f2") {
            Err(Error::FileExists(_)) => {}
            other => panic!("expected FileExists, got {:?}", other),
        }
    }

    #[test]
    fn reads_pass_through() {
        let t = wrap();
        assert_eq!(t.get_bytes("regular").unwrap(), b"x");
    }
}
