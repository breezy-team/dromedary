//! BrokenRename Transport decorator, ported from dromedary/brokenrename.py.
//!
//! A transport that fails to detect clashing renames: if the destination
//! exists, the rename is silently absorbed rather than raising an error.

use crate::{Result, Transport, UrlFragment};
use url::Url;

pub struct BrokenRenameTransport {
    inner: Box<dyn Transport + Send + Sync>,
    base: Url,
}

impl BrokenRenameTransport {
    pub const PREFIX: &'static str = "brokenrename+";

    pub fn new(inner: Box<dyn Transport + Send + Sync>) -> Self {
        let base = crate::decorator::prefixed_base(Self::PREFIX, inner.as_ref());
        Self { inner, base }
    }
}

impl std::fmt::Debug for BrokenRenameTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BrokenRenameTransport({})", self.base)
    }
}

impl Transport for BrokenRenameTransport {
    crate::fwd_external_url!(inner);
    crate::fwd_can_roundtrip_unix_modebits!(inner);
    crate::fwd_is_readonly!(inner);
    crate::fwd_listable!(inner);
    crate::fwd_get!(inner);
    crate::fwd_has!(inner);
    crate::fwd_stat!(inner);
    crate::fwd_clone!(inner);
    crate::fwd_abspath!(inner);
    crate::fwd_relpath!(inner);
    crate::fwd_put_file!(inner);
    crate::fwd_mkdir!(inner);
    crate::fwd_delete!(inner);
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
    crate::fwd_get_smart_medium!(inner);
    crate::fwd_copy!(inner);

    fn base(&self) -> Url {
        self.base.clone()
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        match self.inner.rename(rel_from, rel_to) {
            Ok(()) => Ok(()),
            // Absorb clashes silently — that's the whole point.
            Err(crate::Error::FileExists(_)) | Err(crate::Error::DirectoryNotEmptyError(_)) => {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn wrap() -> BrokenRenameTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.put_bytes("a", b"A", None).unwrap();
        mem.put_bytes("b", b"B", None).unwrap();
        BrokenRenameTransport::new(Box::new(mem))
    }

    #[test]
    fn base_prefix() {
        assert!(wrap().base().as_str().starts_with("brokenrename+"));
    }

    #[test]
    fn ok_rename_still_works() {
        let t = wrap();
        t.rename("a", "c").unwrap();
        assert_eq!(t.has("a").unwrap(), false);
        assert_eq!(t.get_bytes("c").unwrap(), b"A");
    }

    #[test]
    fn clashing_rename_is_absorbed() {
        let t = wrap();
        // Renaming a over existing b would normally raise FileExists.
        t.rename("a", "b").unwrap();
        // Both files should still exist because the rename was absorbed.
        assert_eq!(t.get_bytes("a").unwrap(), b"A");
        assert_eq!(t.get_bytes("b").unwrap(), b"B");
    }
}
