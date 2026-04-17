//! Shared forwarding helpers for Transport decorators, matching
//! dromedary/decorator.py.
//!
//! `forward_transport_all!($field)` emits a default forwarding impl for
//! every Transport method. Each individual forwarder is also exposed as
//! `fwd_<name>!` so decorators that want to override a few methods can
//! invoke only the forwarders they need instead of relying on skip
//! lists.

/// Build a decorator base URL by prefixing the inner transport's base.
/// `prefix` should include the trailing `+`, matching Python's
/// `_get_url_prefix()` convention (e.g. "fakenfs+").
pub fn prefixed_base(prefix: &str, inner: &dyn crate::Transport) -> ::url::Url {
    let inner_base = inner.base();
    let url = format!("{}{}", prefix, inner_base);
    ::url::Url::parse(&url).unwrap_or(inner_base)
}

#[macro_export]
macro_rules! fwd_external_url {
    ($field:ident) => {
        fn external_url(&self) -> $crate::Result<::url::Url> {
            self.$field.external_url()
        }
    };
}
#[macro_export]
macro_rules! fwd_can_roundtrip_unix_modebits {
    ($field:ident) => {
        fn can_roundtrip_unix_modebits(&self) -> bool {
            self.$field.can_roundtrip_unix_modebits()
        }
    };
}
#[macro_export]
macro_rules! fwd_is_readonly {
    ($field:ident) => {
        fn is_readonly(&self) -> bool {
            self.$field.is_readonly()
        }
    };
}
#[macro_export]
macro_rules! fwd_listable {
    ($field:ident) => {
        fn listable(&self) -> bool {
            self.$field.listable()
        }
    };
}
#[macro_export]
macro_rules! fwd_get {
    ($field:ident) => {
        fn get(
            &self,
            relpath: &$crate::UrlFragment,
        ) -> $crate::Result<Box<dyn $crate::ReadStream + Send + Sync>> {
            self.$field.get(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_has {
    ($field:ident) => {
        fn has(&self, relpath: &$crate::UrlFragment) -> $crate::Result<bool> {
            self.$field.has(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_stat {
    ($field:ident) => {
        fn stat(&self, relpath: &$crate::UrlFragment) -> $crate::Result<$crate::Stat> {
            self.$field.stat(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_clone {
    ($field:ident) => {
        fn clone(
            &self,
            offset: Option<&$crate::UrlFragment>,
        ) -> $crate::Result<Box<dyn $crate::Transport>> {
            self.$field.clone(offset)
        }
    };
}
#[macro_export]
macro_rules! fwd_abspath {
    ($field:ident) => {
        fn abspath(&self, relpath: &$crate::UrlFragment) -> $crate::Result<::url::Url> {
            self.$field.abspath(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_relpath {
    ($field:ident) => {
        fn relpath(&self, abspath: &::url::Url) -> $crate::Result<String> {
            self.$field.relpath(abspath)
        }
    };
}
#[macro_export]
macro_rules! fwd_put_file {
    ($field:ident) => {
        fn put_file(
            &self,
            relpath: &$crate::UrlFragment,
            f: &mut dyn ::std::io::Read,
            permissions: Option<::std::fs::Permissions>,
        ) -> $crate::Result<u64> {
            self.$field.put_file(relpath, f, permissions)
        }
    };
}
#[macro_export]
macro_rules! fwd_mkdir {
    ($field:ident) => {
        fn mkdir(
            &self,
            relpath: &$crate::UrlFragment,
            permissions: Option<::std::fs::Permissions>,
        ) -> $crate::Result<()> {
            self.$field.mkdir(relpath, permissions)
        }
    };
}
#[macro_export]
macro_rules! fwd_delete {
    ($field:ident) => {
        fn delete(&self, relpath: &$crate::UrlFragment) -> $crate::Result<()> {
            self.$field.delete(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_rmdir {
    ($field:ident) => {
        fn rmdir(&self, relpath: &$crate::UrlFragment) -> $crate::Result<()> {
            self.$field.rmdir(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_rename {
    ($field:ident) => {
        fn rename(
            &self,
            rel_from: &$crate::UrlFragment,
            rel_to: &$crate::UrlFragment,
        ) -> $crate::Result<()> {
            self.$field.rename(rel_from, rel_to)
        }
    };
}
#[macro_export]
macro_rules! fwd_set_segment_parameter {
    ($field:ident) => {
        fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> $crate::Result<()> {
            self.$field.set_segment_parameter(key, value)
        }
    };
}
#[macro_export]
macro_rules! fwd_get_segment_parameters {
    ($field:ident) => {
        fn get_segment_parameters(
            &self,
        ) -> $crate::Result<::std::collections::HashMap<String, String>> {
            self.$field.get_segment_parameters()
        }
    };
}
#[macro_export]
macro_rules! fwd_append_file {
    ($field:ident) => {
        fn append_file(
            &self,
            relpath: &$crate::UrlFragment,
            f: &mut dyn ::std::io::Read,
            permissions: Option<::std::fs::Permissions>,
        ) -> $crate::Result<u64> {
            self.$field.append_file(relpath, f, permissions)
        }
    };
}
#[macro_export]
macro_rules! fwd_readlink {
    ($field:ident) => {
        fn readlink(&self, relpath: &$crate::UrlFragment) -> $crate::Result<String> {
            self.$field.readlink(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_hardlink {
    ($field:ident) => {
        fn hardlink(
            &self,
            rel_from: &$crate::UrlFragment,
            rel_to: &$crate::UrlFragment,
        ) -> $crate::Result<()> {
            self.$field.hardlink(rel_from, rel_to)
        }
    };
}
#[macro_export]
macro_rules! fwd_symlink {
    ($field:ident) => {
        fn symlink(
            &self,
            rel_from: &$crate::UrlFragment,
            rel_to: &$crate::UrlFragment,
        ) -> $crate::Result<()> {
            self.$field.symlink(rel_from, rel_to)
        }
    };
}
#[macro_export]
macro_rules! fwd_iter_files_recursive {
    ($field:ident) => {
        fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = $crate::Result<String>>> {
            self.$field.iter_files_recursive()
        }
    };
}
#[macro_export]
macro_rules! fwd_open_write_stream {
    ($field:ident) => {
        fn open_write_stream(
            &self,
            relpath: &$crate::UrlFragment,
            permissions: Option<::std::fs::Permissions>,
        ) -> $crate::Result<Box<dyn $crate::WriteStream + Send + Sync>> {
            self.$field.open_write_stream(relpath, permissions)
        }
    };
}
#[macro_export]
macro_rules! fwd_delete_tree {
    ($field:ident) => {
        fn delete_tree(&self, relpath: &$crate::UrlFragment) -> $crate::Result<()> {
            self.$field.delete_tree(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_move {
    ($field:ident) => {
        fn r#move(
            &self,
            rel_from: &$crate::UrlFragment,
            rel_to: &$crate::UrlFragment,
        ) -> $crate::Result<()> {
            self.$field.r#move(rel_from, rel_to)
        }
    };
}
#[macro_export]
macro_rules! fwd_list_dir {
    ($field:ident) => {
        fn list_dir(
            &self,
            relpath: &$crate::UrlFragment,
        ) -> Box<dyn Iterator<Item = $crate::Result<String>>> {
            self.$field.list_dir(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_lock_read {
    ($field:ident) => {
        fn lock_read(
            &self,
            relpath: &$crate::UrlFragment,
        ) -> $crate::Result<Box<dyn $crate::lock::Lock + Send + Sync>> {
            self.$field.lock_read(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_lock_write {
    ($field:ident) => {
        fn lock_write(
            &self,
            relpath: &$crate::UrlFragment,
        ) -> $crate::Result<Box<dyn $crate::lock::Lock + Send + Sync>> {
            self.$field.lock_write(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_local_abspath {
    ($field:ident) => {
        fn local_abspath(
            &self,
            relpath: &$crate::UrlFragment,
        ) -> $crate::Result<::std::path::PathBuf> {
            self.$field.local_abspath(relpath)
        }
    };
}
#[macro_export]
macro_rules! fwd_get_smart_medium {
    ($field:ident) => {
        fn get_smart_medium(&self) -> $crate::Result<Box<dyn $crate::SmartMedium>> {
            self.$field.get_smart_medium()
        }
    };
}
#[macro_export]
macro_rules! fwd_copy {
    ($field:ident) => {
        fn copy(
            &self,
            rel_from: &$crate::UrlFragment,
            rel_to: &$crate::UrlFragment,
        ) -> $crate::Result<()> {
            self.$field.copy(rel_from, rel_to)
        }
    };
}

/// Forward every Transport method to `self.$field`. The caller must still
/// define `fn base(&self) -> Url`. Use this when no methods need to be
/// overridden; decorators that override a few methods should invoke the
/// individual `fwd_*!` macros instead.
#[macro_export]
macro_rules! fwd_all {
    ($field:ident) => {
        $crate::fwd_external_url!($field);
        $crate::fwd_can_roundtrip_unix_modebits!($field);
        $crate::fwd_is_readonly!($field);
        $crate::fwd_listable!($field);
        $crate::fwd_get!($field);
        $crate::fwd_has!($field);
        $crate::fwd_stat!($field);
        $crate::fwd_clone!($field);
        $crate::fwd_abspath!($field);
        $crate::fwd_relpath!($field);
        $crate::fwd_put_file!($field);
        $crate::fwd_mkdir!($field);
        $crate::fwd_delete!($field);
        $crate::fwd_rmdir!($field);
        $crate::fwd_rename!($field);
        $crate::fwd_set_segment_parameter!($field);
        $crate::fwd_get_segment_parameters!($field);
        $crate::fwd_append_file!($field);
        $crate::fwd_readlink!($field);
        $crate::fwd_hardlink!($field);
        $crate::fwd_symlink!($field);
        $crate::fwd_iter_files_recursive!($field);
        $crate::fwd_open_write_stream!($field);
        $crate::fwd_delete_tree!($field);
        $crate::fwd_move!($field);
        $crate::fwd_list_dir!($field);
        $crate::fwd_lock_read!($field);
        $crate::fwd_lock_write!($field);
        $crate::fwd_local_abspath!($field);
        $crate::fwd_get_smart_medium!($field);
        $crate::fwd_copy!($field);
    };
}
