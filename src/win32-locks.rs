//! Windows file locking.
//!
//! This uses `std::fs::File::try_lock` / `File::lock` (stable in Rust 1.89)
//! to take advisory OS-level locks via `LockFileEx`, combined with the same
//! process-local tracking tables that `fcntl-locks.rs` uses so that a single
//! process can still distinguish read vs. write contention.
//!
//! TODO(windows): `File::try_lock` is exclusive-only. Implementing shared
//! read locks that interoperate with other processes requires dropping to
//! `LockFileEx` directly via `windows-sys`. For pass 1 we rely on the
//! process-local tracking alone for read-vs-write arbitration, which is
//! sufficient for single-process tests but will not coordinate across
//! processes for shared reads.

use crate::lock::{FileLock, Lock, LockError};
use lazy_static::lazy_static;
use log::debug;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

fn open(filename: &Path, options: &OpenOptions) -> std::result::Result<(PathBuf, File), LockError> {
    let filename = crate::osutils::path::realpath(filename)?;
    match options.open(&filename) {
        Ok(f) => Ok((filename, f)),
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Err(LockError::Failed(filename, e.to_string())),
            std::io::ErrorKind::NotFound => {
                debug!(
                    "trying to create missing lock {}",
                    filename.to_string_lossy()
                );
                let f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .open(&filename)?;
                Ok((filename, f))
            }
            _ => Err(e.into()),
        },
    }
}

lazy_static! {
    static ref OPEN_WRITE_LOCKS: std::sync::Mutex<HashSet<PathBuf>> =
        std::sync::Mutex::new(HashSet::new());
    static ref OPEN_READ_LOCKS: std::sync::Mutex<HashMap<PathBuf, usize>> =
        std::sync::Mutex::new(HashMap::new());
}

pub struct WriteLock {
    filename: PathBuf,
    f: File,
}

impl WriteLock {
    pub fn new(filename: &Path, strict_locks: bool) -> Result<WriteLock, LockError> {
        let filename = crate::osutils::path::realpath(filename)?;
        if OPEN_WRITE_LOCKS.lock().unwrap().contains(&filename) {
            return Err(LockError::Contention(filename));
        }
        if OPEN_READ_LOCKS.lock().unwrap().contains_key(&filename) {
            if strict_locks {
                return Err(LockError::Contention(filename));
            } else {
                debug!(
                    "Write lock taken w/ an open read lock on: {}",
                    filename.to_string_lossy()
                );
            }
        }

        let (filename, f) = open(
            filename.as_path(),
            OpenOptions::new().read(true).write(true),
        )?;
        match f.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(LockError::Contention(filename));
            }
            Err(std::fs::TryLockError::Error(_)) => {
                // Fall through — we still have process-local tracking.
            }
        }
        OPEN_WRITE_LOCKS.lock().unwrap().insert(filename.clone());
        Ok(WriteLock { filename, f })
    }
}

impl Lock for WriteLock {
    fn unlock(&mut self) -> Result<(), LockError> {
        OPEN_WRITE_LOCKS.lock().unwrap().remove(&self.filename);
        let _ = self.f.unlock();
        Ok(())
    }
}

impl FileLock for WriteLock {
    fn file(&self) -> std::io::Result<Box<File>> {
        Ok(Box::new(self.f.try_clone()?))
    }

    fn path(&self) -> &Path {
        &self.filename
    }
}

pub struct ReadLock {
    filename: PathBuf,
    f: File,
}

impl ReadLock {
    pub fn new(filename: &Path, strict_locks: bool) -> std::result::Result<Self, LockError> {
        let filename = crate::osutils::path::realpath(filename)?;
        if OPEN_WRITE_LOCKS.lock().unwrap().contains(&filename) {
            if strict_locks {
                return Err(LockError::Contention(filename));
            } else {
                debug!(
                    "Read lock taken w/ an open write lock on: {}",
                    filename.to_string_lossy()
                );
            }
        }

        OPEN_READ_LOCKS
            .lock()
            .unwrap()
            .entry(filename.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);

        let (filename, f) = open(&filename, OpenOptions::new().read(true))?;
        // `File::try_lock_shared` would be the right call here, but it is
        // currently unstable. See the module-level TODO.
        Ok(ReadLock { filename, f })
    }

    /// Try to grab a write lock on the file.
    pub fn temporary_write_lock(
        self,
    ) -> std::result::Result<TemporaryWriteLock, (Self, LockError)> {
        if OPEN_WRITE_LOCKS.lock().unwrap().contains(&self.filename) {
            panic!("file already locked: {}", self.filename.to_string_lossy());
        }
        TemporaryWriteLock::new(self)
    }
}

impl Lock for ReadLock {
    fn unlock(&mut self) -> std::result::Result<(), LockError> {
        match OPEN_READ_LOCKS.lock().unwrap().entry(self.filename.clone()) {
            Entry::Occupied(mut entry) => {
                let count = entry.get_mut();
                if *count == 1 {
                    entry.remove();
                } else {
                    *count -= 1;
                }
            }
            Entry::Vacant(_) => panic!("no read lock on {}", self.filename.to_string_lossy()),
        }
        Ok(())
    }
}

impl FileLock for ReadLock {
    fn file(&self) -> std::io::Result<Box<File>> {
        Ok(Box::new(self.f.try_clone()?))
    }

    fn path(&self) -> &Path {
        &self.filename
    }
}

/// A token used when grabbing a temporary_write_lock.
pub struct TemporaryWriteLock {
    read_lock: ReadLock,
    filename: PathBuf,
    f: File,
}

impl TemporaryWriteLock {
    pub fn new(read_lock: ReadLock) -> std::result::Result<Self, (ReadLock, LockError)> {
        let filename = read_lock.filename.clone();
        if let Some(count) = OPEN_READ_LOCKS.lock().unwrap().get(&filename) {
            if *count > 1 {
                return Err((read_lock, LockError::Contention(filename)));
            }
        }

        if OPEN_WRITE_LOCKS.lock().unwrap().contains(&filename) {
            panic!("file already locked: {}", filename.to_string_lossy());
        }

        let f = match OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(&filename)
        {
            Ok(f) => Ok(f),
            Err(e) => return Err((read_lock, e.into())),
        }?;

        match f.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err((read_lock, LockError::Contention(filename)));
            }
            Err(std::fs::TryLockError::Error(_)) => {
                // Fall through — process-local tracking is what we rely on.
            }
        }

        OPEN_WRITE_LOCKS.lock().unwrap().insert(filename.clone());

        Ok(Self {
            read_lock,
            filename,
            f,
        })
    }

    pub fn restore_read_lock(self) -> ReadLock {
        let _ = self.f.unlock();
        OPEN_WRITE_LOCKS.lock().unwrap().remove(&self.filename);
        self.read_lock
    }
}

impl FileLock for TemporaryWriteLock {
    fn file(&self) -> std::io::Result<Box<File>> {
        Ok(Box::new(self.f.try_clone()?))
    }

    fn path(&self) -> &Path {
        &self.filename
    }
}
