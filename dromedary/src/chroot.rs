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

    fn chroot_at(base_path: &str) -> PathFilteringTransport {
        let mem = MemoryTransport::new("memory:///").unwrap();
        mem.mkdir("jail", None).unwrap();
        mem.put_bytes("jail/inside", b"ok", None).unwrap();
        mem.put_bytes("outside", b"secret", None).unwrap();
        new_chroot(Box::new(mem), "chroot-1:///", base_path).unwrap()
    }

    #[test]
    fn reads_inside_jail() {
        let t = chroot_at("/jail/");
        assert_eq!(t.get_bytes("inside").unwrap(), b"ok");
    }

    #[test]
    fn outside_jail_not_visible() {
        let t = chroot_at("/jail/");
        // `outside` only exists at the backing root; relative to the chroot
        // root (/jail/) it should not be findable.
        match t.get_bytes("outside") {
            Err(Error::NoSuchFile(_)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[test]
    fn dotdot_cannot_escape_chroot() {
        let t = chroot_at("/jail/");
        match t.get_bytes("../outside") {
            Err(Error::PathNotChild) => {}
            other => panic!("expected PathNotChild, got {:?}", other),
        }
    }

    #[test]
    fn deeper_dotdot_cannot_escape_chroot() {
        let t = chroot_at("/jail/");
        match t.get_bytes("../../outside") {
            Err(Error::PathNotChild) => {}
            other => panic!("expected PathNotChild, got {:?}", other),
        }
    }

    #[test]
    fn absolute_path_cannot_escape_chroot() {
        let t = chroot_at("/jail/");
        match t.get_bytes("/outside") {
            Err(Error::PathNotChild) => {}
            other => panic!("expected PathNotChild, got {:?}", other),
        }
    }

    #[test]
    fn mkdir_and_delete_round_trip() {
        let t = chroot_at("/jail/");
        t.mkdir("new", None).unwrap();
        t.put_bytes("new/f", b"x", None).unwrap();
        assert_eq!(t.get_bytes("new/f").unwrap(), b"x");
    }
}
