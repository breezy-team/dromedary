pub mod path;

/// Transport-style path helpers ported from dromedary/osutils.py.
///
/// These operate on forward-slash URL-style paths (strings), not on
/// native OS paths. See `path` for OS-path helpers.
/// Split a forward-slash path into its components.
///
/// Leading and trailing slashes are stripped. `""` and `"/"` both return
/// an empty vector.
pub fn splitpath(path: &str) -> Vec<String> {
    if path.is_empty() || path == "/" {
        return Vec::new();
    }
    let trimmed = path.trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed.split('/').map(|s| s.to_string()).collect()
}

/// Join forward-slash path components.
///
/// Empty and `"."` components are dropped. If the first component starts
/// with `/`, the result is absolute.
pub fn pathjoin(parts: &[&str]) -> String {
    if parts.is_empty() {
        return String::new();
    }
    let absolute = parts[0].starts_with('/');
    let components: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if components.is_empty() {
        return String::new();
    }
    let joined = components
        .iter()
        .map(|c| c.trim_start_matches('/'))
        .collect::<Vec<_>>()
        .join("/");
    if absolute {
        format!("/{}", joined)
    } else {
        joined
    }
}

/// File kinds reported by `file_kind_from_stat_mode`. String values match
/// the Python implementation for byte-for-byte parity.
pub const KIND_FILE: &str = "file";
pub const KIND_DIRECTORY: &str = "directory";
pub const KIND_SYMLINK: &str = "symlink";
pub const KIND_CHARDEV: &str = "chardev";
pub const KIND_BLOCK: &str = "block";
pub const KIND_FIFO: &str = "fifo";
pub const KIND_SOCKET: &str = "socket";
pub const KIND_UNKNOWN: &str = "unknown";

/// Translate a Unix stat mode into a kind string matching Python's
/// `stat.S_IS*` classification.
pub fn file_kind_from_stat_mode(stat_mode: u32) -> &'static str {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    match stat_mode & S_IFMT {
        S_IFREG => KIND_FILE,
        S_IFDIR => KIND_DIRECTORY,
        S_IFLNK => KIND_SYMLINK,
        S_IFCHR => KIND_CHARDEV,
        S_IFBLK => KIND_BLOCK,
        S_IFIFO => KIND_FIFO,
        S_IFSOCK => KIND_SOCKET,
        _ => KIND_UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitpath_basics() {
        assert_eq!(splitpath(""), Vec::<String>::new());
        assert_eq!(splitpath("/"), Vec::<String>::new());
        assert_eq!(splitpath("a"), vec!["a".to_string()]);
        assert_eq!(splitpath("/a"), vec!["a".to_string()]);
        assert_eq!(splitpath("a/"), vec!["a".to_string()]);
        assert_eq!(
            splitpath("/a/b/c"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn pathjoin_basics() {
        assert_eq!(pathjoin(&[]), "");
        assert_eq!(pathjoin(&["a", "b"]), "a/b");
        assert_eq!(pathjoin(&["a", "", "b"]), "a/b");
        assert_eq!(pathjoin(&["a", ".", "b"]), "a/b");
        assert_eq!(pathjoin(&["/a", "b"]), "/a/b");
        assert_eq!(pathjoin(&["", ""]), "");
    }

    #[test]
    fn file_kind_from_stat_mode_regular() {
        assert_eq!(file_kind_from_stat_mode(0o100644), KIND_FILE);
        assert_eq!(file_kind_from_stat_mode(0o040755), KIND_DIRECTORY);
        assert_eq!(file_kind_from_stat_mode(0o120777), KIND_SYMLINK);
    }

    #[test]
    fn file_kind_from_stat_mode_special() {
        assert_eq!(file_kind_from_stat_mode(0o020000), KIND_CHARDEV);
        assert_eq!(file_kind_from_stat_mode(0o060000), KIND_BLOCK);
        assert_eq!(file_kind_from_stat_mode(0o010000), KIND_FIFO);
        assert_eq!(file_kind_from_stat_mode(0o140000), KIND_SOCKET);
    }
}
