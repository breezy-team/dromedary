//! FakeVFAT Transport decorator, ported from dromedary/fakevfat.py.
//!
//! Simulates VFAT restrictions: filenames are squashed to lowercase, and
//! names containing any of `?*:;<>` are rejected. Only a subset of
//! Transport methods route through the squash; others forward unchanged.

use crate::{Error, Result, Transport, UrlFragment};
use std::fs::Permissions;
use url::Url;

pub struct FakeVfatTransport {
    inner: Box<dyn Transport + Send + Sync>,
}

impl FakeVfatTransport {
    pub const PREFIX: &'static str = "vfat+";

    pub fn new(inner: Box<dyn Transport + Send + Sync>) -> Self {
        Self { inner }
    }

    fn squash_name(name: &str) -> Result<String> {
        if name.contains(|c: char| matches!(c, '?' | '*' | ':' | ';' | '<' | '>')) {
            return Err(Error::PathNotChild);
        }
        Ok(name.to_lowercase())
    }
}

impl std::fmt::Debug for FakeVfatTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "FakeVfatTransport({})", self.base())
    }
}

impl Transport for FakeVfatTransport {
    crate::fwd_external_url!(inner);
    crate::fwd_is_readonly!(inner);
    crate::fwd_listable!(inner);
    crate::fwd_stat!(inner);
    crate::fwd_decorator_url!(inner, FakeVfatTransport);
    crate::fwd_delete!(inner);
    crate::fwd_rmdir!(inner);
    crate::fwd_rename!(inner);
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
        crate::decorator::prefixed_base(Self::PREFIX, self.inner.as_ref())
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        false
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn crate::ReadStream + Send + Sync>> {
        self.inner.get(&Self::squash_name(relpath)?)
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        self.inner.has(&Self::squash_name(relpath)?)
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        self.inner
            .put_file(&Self::squash_name(relpath)?, f, permissions)
    }

    fn put_bytes(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<()> {
        self.inner
            .put_bytes(&Self::squash_name(relpath)?, data, permissions)
    }

    fn put_file_non_atomic(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn std::io::Read,
        permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        self.inner.put_file_non_atomic(
            &Self::squash_name(relpath)?,
            f,
            permissions,
            create_parent_dir,
            dir_permissions,
        )
    }

    fn put_bytes_non_atomic(
        &self,
        relpath: &UrlFragment,
        data: &[u8],
        permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        self.inner.put_bytes_non_atomic(
            &Self::squash_name(relpath)?,
            data,
            permissions,
            create_parent_dir,
            dir_permissions,
        )
    }

    fn mkdir(&self, relpath: &UrlFragment, _permissions: Option<Permissions>) -> Result<()> {
        // Python hard-codes 0o755 for VFAT mkdir.
        #[cfg(unix)]
        let perms = {
            use std::os::unix::fs::PermissionsExt;
            Some(Permissions::from_mode(0o755))
        };
        #[cfg(not(unix))]
        let perms: Option<Permissions> = None;
        self.inner.mkdir(&Self::squash_name(relpath)?, perms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;

    fn wrap() -> FakeVfatTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        // Pre-seed lowercase names so squashed reads find them.
        mem.put_bytes("readme", b"hi", None).unwrap();
        FakeVfatTransport::new(Box::new(mem))
    }

    #[test]
    fn base_prefix() {
        assert!(wrap().base().as_str().starts_with("vfat+"));
    }

    #[test]
    fn uppercase_get_squashes_to_lowercase() {
        assert_eq!(wrap().get_bytes("README").unwrap(), b"hi");
    }

    #[test]
    fn illegal_character_rejected() {
        match wrap().put_bytes("bad:name", b"x", None) {
            Err(Error::PathNotChild) => {}
            other => panic!("expected PathNotChild, got {:?}", other),
        }
    }

    #[test]
    fn put_and_get_round_trip_lowercase() {
        let t = wrap();
        t.put_bytes("HELLO", b"world", None).unwrap();
        assert_eq!(t.get_bytes("hello").unwrap(), b"world");
        assert_eq!(t.get_bytes("Hello").unwrap(), b"world");
    }

    #[test]
    fn roundtrip_unix_modebits_false() {
        assert_eq!(wrap().can_roundtrip_unix_modebits(), false);
    }

    #[test]
    fn mkdir_squashes_name() {
        let t = wrap();
        t.mkdir("NewDir", None).unwrap();
        assert_eq!(t.has("newdir").unwrap(), true);
    }
}
