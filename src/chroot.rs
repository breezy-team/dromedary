//! Chroot Transport, ported from dromedary/chroot.py.
//!
//! A chroot is a [`PathFilteringTransport`](crate::pathfilter::PathFilteringTransport)
//! with no user filter function: the server-root rebase that `pathfilter`
//! performs is enough to prevent `..` sequences from escaping the backing
//! transport's root.

use crate::pathfilter::PathFilteringTransport;
use crate::{Result, Transport};

/// Construct a chroot transport wrapping `backing`, exposed under `scheme`
/// (e.g. "chroot-42:///") with `base_path` (must start with `/`) as the
/// chroot root within the backing transport.
pub fn new_chroot(
    backing: Box<dyn Transport + Send + Sync>,
    scheme: impl Into<String>,
    base_path: impl Into<String>,
) -> Result<PathFilteringTransport> {
    PathFilteringTransport::new(backing, scheme, base_path, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryTransport;
    use crate::Error;

    fn chroot_at() -> PathFilteringTransport {
        // Mirror the Python setup: backing is already rooted inside the jail,
        // so escapes via `..` resolve to paths that don't exist on the
        // backing transport.
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.mkdir("jail", None).unwrap();
        mem.put_bytes("jail/inside", b"ok", None).unwrap();
        mem.put_bytes("outside", b"secret", None).unwrap();
        let jail = mem.clone(Some("jail")).unwrap();
        new_chroot(jail, "chroot-1:///", "/").unwrap()
    }

    #[test]
    fn reads_inside_jail() {
        let t = chroot_at();
        assert_eq!(t.get_bytes("inside").unwrap(), b"ok");
    }

    #[test]
    fn dotdot_cannot_escape_chroot() {
        let t = chroot_at();
        match t.get_bytes("../outside") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn deeper_dotdot_cannot_escape_chroot() {
        let t = chroot_at();
        match t.get_bytes("../../outside") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn absolute_path_cannot_escape_chroot() {
        let t = chroot_at();
        match t.get_bytes("/outside") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn mkdir_and_delete_round_trip() {
        let t = chroot_at();
        t.mkdir("new", None).unwrap();
        t.put_bytes("new/f", b"x", None).unwrap();
        assert_eq!(t.get_bytes("new/f").unwrap(), b"x");
    }
}
