//! `HttpDavTransport` — a `dromedary::Transport` over WebDAV.
//!
//! Composition on top of [`HttpTransport`]: all reads / HEAD / GET
//! delegate to the underlying HTTP transport, and the WebDAV-
//! specific verbs (PUT, MKCOL, MOVE, DELETE, COPY, PROPFIND) are
//! implemented here by issuing raw HTTP requests through the
//! shared client and interpreting the status codes.
//!
//! Ported from `dromedary/webdav/webdav.py`. Like the Python
//! version, this implements the subset bzr needs — no LOCK/UNLOCK,
//! no PROPPATCH beyond allprop PROPFIND, no chunked upload. Bzr's
//! locking is faked with a bogus lock held on the read side.

use std::io::Read;
use std::sync::Arc;

use url::Url;

use crate::http::client::HttpClient;
use crate::http::HttpTransport;
use crate::{
    ConnectedTransport, Error, FileKind, Permissions, ReadStream, Result, Stat, Transport,
    UrlFragment,
};

use super::xml::{parse_propfind_dir, parse_propfind_stat};

/// WebDAV transport over HTTP(S).
///
/// `inner` is the plain-HTTP transport that owns the `HttpClient`
/// (connection pool, auth cache, range-hint state). WebDAV write
/// verbs are issued through `inner.request(...)` so they inherit
/// the same auth / redirect / proxy machinery.
#[derive(Clone)]
pub struct HttpDavTransport {
    inner: HttpTransport,
}

impl HttpDavTransport {
    /// Build a new transport over `base`. Accepts URLs with schemes
    /// `http`, `https`, or `http[s]+urllib` / `http[s]+webdav`; the
    /// implementation suffix is stripped and ignored.
    pub fn new(base: &str, client: Arc<HttpClient>) -> Result<Self> {
        // Drop any `+webdav` qualifier before handing the URL to
        // HttpTransport, which would otherwise reject the scheme.
        let trimmed = strip_dav_scheme_suffix(base);
        Ok(Self {
            inner: HttpTransport::new(&trimmed, client)?,
        })
    }

    /// Concrete version of [`Transport::clone`]. Mirrors
    /// `HttpTransport::clone_concrete` — always directory-shaped,
    /// shares the underlying `HttpClient`.
    pub fn clone_concrete(&self, offset: Option<&UrlFragment>) -> Result<Self> {
        Ok(Self {
            inner: self.inner.clone_concrete(offset)?,
        })
    }

    /// Access the underlying HTTP transport. Useful for the PyO3
    /// wrapper which exposes HttpTransport-inherited methods.
    pub fn http(&self) -> &HttpTransport {
        &self.inner
    }

    /// Issue a PROPFIND with the given depth and return the raw
    /// response body as bytes. Common to `stat`, `list_dir`, and
    /// `iter_files_recursive`.
    fn propfind(&self, relpath: &UrlFragment, depth: &str) -> Result<Vec<u8>> {
        let abspath = self.inner.remote_url(relpath)?.to_string();
        let body = br#"<?xml version="1.0" encoding="utf-8" ?>
   <D:propfind xmlns:D="DAV:">
     <D:allprop/>
   </D:propfind>
"#;
        let headers = [
            ("Depth".to_string(), depth.to_string()),
            (
                "Content-Type".to_string(),
                "application/xml; charset=\"utf-8\"".to_string(),
            ),
        ];
        let mut resp = self
            .inner
            .request("PROPFIND", &abspath, &headers, body, false)?;
        match resp.status {
            207 => resp.body().map(|b| b.to_vec()).map_err(Error::Io),
            404 | 409 => Err(Error::NoSuchFile(Some(abspath))),
            other => Err(Error::InvalidHttpResponse {
                path: abspath,
                msg: format!(
                    "unable to list directory (status {}: {})",
                    other, resp.reason
                ),
            }),
        }
    }

    /// PUT `bytes` at `abspath` without any atomicity guard. Used
    /// by `put_bytes_non_atomic` and as the final step of the
    /// atomic put algorithm.
    fn bare_put(&self, abspath: &str, bytes: &[u8], range_header: Option<String>) -> Result<()> {
        let mut headers: Vec<(String, String)> = vec![
            ("Accept".to_string(), "*/*".to_string()),
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
        ];
        if let Some(range) = range_header {
            headers.push(("Content-Range".to_string(), range));
        }
        let resp = self.inner.request("PUT", abspath, &headers, bytes, false)?;
        match resp.status {
            200 | 201 | 204 => Ok(()),
            // Intermediate directories missing.
            403 | 404 | 409 => Err(Error::NoSuchFile(Some(abspath.to_string()))),
            other => Err(Error::InvalidHttpResponse {
                path: abspath.to_string(),
                msg: format!("put file failed (status {}: {})", other, resp.reason),
            }),
        }
    }

    /// MOVE `from` to `to`. `overwrite=false` causes the server to
    /// refuse if `to` exists (412); `overwrite=true` replaces.
    fn webdav_move(&self, abs_from: &str, abs_to: &str, overwrite: bool) -> Result<()> {
        let headers = [
            ("Destination".to_string(), abs_to.to_string()),
            (
                "Overwrite".to_string(),
                if overwrite { "T" } else { "F" }.to_string(),
            ),
        ];
        let resp = self.inner.request("MOVE", abs_from, &headers, &[], false)?;
        match resp.status {
            201 => Ok(()),
            // 204 means `to` already existed — allowed only when
            // we asked for overwrite. With overwrite=false a 204
            // is a server bug (it should have been 412).
            204 if overwrite => Ok(()),
            404 => Err(Error::NoSuchFile(Some(abs_from.to_string()))),
            412 => Err(Error::FileExists(Some(abs_to.to_string()))),
            409 if overwrite => Err(Error::DirectoryNotEmptyError(Some(abs_to.to_string()))),
            409 => Err(Error::NoSuchFile(Some(abs_to.to_string()))),
            other => Err(Error::InvalidHttpResponse {
                path: abs_from.to_string(),
                msg: format!(
                    "unable to move to {} (status {}: {})",
                    abs_to, other, resp.reason
                ),
            }),
        }
    }

    /// Generate a random temp-file suffix. Used to stamp a
    /// not-yet-committed PUT so we can MOVE it into place
    /// atomically (and delete it on failure). Matches the Python
    /// `".tmp.%.9f.%d.%d" % (time.time(), os.getpid(), rand)` shape
    /// closely enough that clients debugging a hung upload can
    /// still recognise the leftover.
    fn temp_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let pid = std::process::id();
        let r: u32 = rand::random();
        format!(".tmp.{:.9}.{}.{}", now, pid, r)
    }

    /// Append via HEAD-then-ranged-PUT. Efficient when the server
    /// supports Content-Range (Apache does).
    fn append_by_head_put(&self, relpath: &UrlFragment, bytes: &[u8]) -> Result<u64> {
        let resp = match self.inner.head(relpath) {
            Ok(r) => r,
            // 404 means the file doesn't exist yet; fall back to a
            // plain put_bytes that creates it.
            Err(Error::NoSuchFile(_)) => {
                self.put_bytes(relpath, bytes, None)?;
                return Ok(0);
            }
            Err(e) => return Err(e),
        };
        let current_size = resp
            .header("content-length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if current_size == 0 {
            // Apache omits Content-Length on empty files (module
            // source calls it a "hack"). Treat as new-file create.
            self.put_bytes(relpath, bytes, None)?;
            return Ok(0);
        }
        let abspath = self.inner.remote_url(relpath)?.to_string();
        let range = format!(
            "bytes {}-{}/*",
            current_size,
            current_size + bytes.len() as u64 - 1
        );
        self.bare_put(&abspath, bytes, Some(range))?;
        Ok(current_size)
    }

    /// Append via GET+modify+PUT. Universal fallback for servers
    /// that don't honour Content-Range on PUT.
    fn append_by_get_put(&self, relpath: &UrlFragment, bytes: &[u8]) -> Result<u64> {
        let mut existing = Vec::new();
        match self.inner.get(relpath) {
            Ok(mut rf) => {
                std::io::Read::read_to_end(&mut rf, &mut existing).map_err(Error::Io)?;
            }
            Err(Error::NoSuchFile(_)) => {
                // File doesn't exist; `existing` stays empty and we
                // put exactly the new bytes.
            }
            Err(e) => return Err(e),
        }
        let before = existing.len() as u64;
        existing.extend_from_slice(bytes);
        self.put_bytes(relpath, &existing, None)?;
        Ok(before)
    }
}

/// Construct a `TransportNotPossible` error for the verbs WebDAV
/// doesn't implement (symlinks, hardlinks, write streams, mode bits).
fn unsupported(what: &str) -> Error {
    Error::TransportNotPossible(Some(format!("webdav does not support {}", what)))
}

/// Strip `+webdav` / `+urllib` / `+impl` suffixes from the scheme
/// before handing the URL to `HttpTransport::new`, which only
/// accepts `http` / `https`.
fn strip_dav_scheme_suffix(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let scheme = &url[..scheme_end];
    let unqualified = scheme.split_once('+').map(|(s, _)| s).unwrap_or(scheme);
    format!("{}{}", unqualified, &url[scheme_end..])
}

impl std::fmt::Debug for HttpDavTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "HttpDavTransport({})", self.inner.base())
    }
}

impl Transport for HttpDavTransport {
    fn external_url(&self) -> Result<Url> {
        self.inner.external_url()
    }

    fn base(&self) -> Url {
        self.inner.base()
    }

    fn can_roundtrip_unix_modebits(&self) -> bool {
        false
    }

    fn is_readonly(&self) -> bool {
        false
    }

    fn listable(&self) -> bool {
        true
    }

    fn recommended_page_size(&self) -> usize {
        64 * 1024
    }

    fn get(&self, relpath: &UrlFragment) -> Result<Box<dyn ReadStream + Send + Sync>> {
        self.inner.get(relpath)
    }

    fn has(&self, relpath: &UrlFragment) -> Result<bool> {
        self.inner.has(relpath)
    }

    fn stat(&self, relpath: &UrlFragment) -> Result<Stat> {
        let abspath = self.inner.remote_url(relpath)?.to_string();
        let body = self.propfind(relpath, "0")?;
        let dav = parse_propfind_stat(&body, &abspath)?;
        // bzr expects a conventional unix mode. Directories go to
        // 040644, regular files to 100644, with the exec bit
        // flipped on if DAV reported the `executable` property.
        let kind = if dav.is_dir {
            FileKind::Dir
        } else {
            FileKind::File
        };
        #[cfg(unix)]
        let mode = if dav.is_dir {
            0o040644
        } else if dav.is_exec {
            0o100644 | 0o755
        } else {
            0o100644
        };
        let size = if dav.is_dir {
            0
        } else {
            dav.size.max(0) as usize
        };
        Ok(Stat {
            size,
            #[cfg(unix)]
            mode,
            kind,
            // WebDAV PROPFIND does surface `getlastmodified`, but
            // bzr doesn't consult mtimes over remote transports —
            // so skip the parse rather than pay for a chrono dep.
            mtime: None,
        })
    }

    fn clone(&self, offset: Option<&UrlFragment>) -> Result<Box<dyn Transport>> {
        Ok(Box::new(self.clone_concrete(offset)?))
    }

    fn abspath(&self, relpath: &UrlFragment) -> Result<Url> {
        self.inner.abspath(relpath)
    }

    fn relpath(&self, abspath: &Url) -> Result<String> {
        self.inner.relpath(abspath)
    }

    fn set_segment_parameter(&mut self, key: &str, value: Option<&str>) -> Result<()> {
        self.inner.set_segment_parameter(key, value)
    }

    fn get_segment_parameters(&self) -> Result<std::collections::HashMap<String, String>> {
        self.inner.get_segment_parameters()
    }

    fn mkdir(&self, relpath: &UrlFragment, _permissions: Option<Permissions>) -> Result<()> {
        let abspath = self.inner.remote_url(relpath)?.to_string();
        let resp = self.inner.request("MKCOL", &abspath, &[], &[], false)?;
        match resp.status {
            201 => Ok(()),
            // 405 Method Not Allowed is returned when the resource
            // already exists; map to FileExists for bzr.
            405 => Err(Error::FileExists(Some(abspath))),
            // Missing intermediate directories.
            404 | 409 => Err(Error::NoSuchFile(Some(abspath))),
            other => Err(Error::InvalidHttpResponse {
                path: abspath,
                msg: format!("mkdir failed (status {}: {})", other, resp.reason),
            }),
        }
    }

    fn put_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        // Match Python put_file: eager-read the source so we can
        // honour the atomic-put dance. Streaming uploads would need
        // Transfer-Encoding: chunked which the Python version also
        // skips.
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(Error::Io)?;
        let n = buf.len() as u64;
        self.put_bytes(relpath, &buf, None)?;
        Ok(n)
    }

    fn put_bytes(
        &self,
        relpath: &UrlFragment,
        bytes: &[u8],
        _permissions: Option<Permissions>,
    ) -> Result<()> {
        // RFC 2068 said PUT was atomic; practice disagreed. Apache
        // in particular leaves a half-written file behind if the
        // client disconnects mid-PUT. We therefore put to a temp
        // relpath first, then MOVE it into place.
        let stamp = Self::temp_suffix();
        let tmp_relpath = format!("{}{}", relpath, stamp);
        self.put_bytes_non_atomic(&tmp_relpath, bytes, None, None, None)?;
        // Move the temp file into place. On failure, try to clean
        // up the temp file before surfacing the original error.
        let abs_tmp = self.inner.remote_url(&tmp_relpath)?.to_string();
        let abs_dst = self.inner.remote_url(relpath)?.to_string();
        if let Err(primary) = self.webdav_move(&abs_tmp, &abs_dst, true) {
            // Best-effort cleanup; ignore secondary errors so the
            // caller sees the real failure.
            let _ = self.delete(&tmp_relpath);
            return Err(primary);
        }
        Ok(())
    }

    fn put_bytes_non_atomic(
        &self,
        relpath: &UrlFragment,
        bytes: &[u8],
        _permissions: Option<Permissions>,
        create_parent_dir: Option<bool>,
        dir_permissions: Option<Permissions>,
    ) -> Result<()> {
        let abspath = self.inner.remote_url(relpath)?.to_string();
        match self.bare_put(&abspath, bytes, None) {
            Ok(()) => Ok(()),
            Err(Error::NoSuchFile(_)) if create_parent_dir.unwrap_or(false) => {
                if let Some(parent) = relpath.rsplit_once('/').map(|x| x.0) {
                    self.mkdir(parent, dir_permissions)?;
                    self.bare_put(&abspath, bytes, None)
                } else {
                    Err(Error::NoSuchFile(Some(abspath)))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn append_bytes(
        &self,
        relpath: &UrlFragment,
        bytes: &[u8],
        _permissions: Option<Permissions>,
    ) -> Result<u64> {
        // Python picks between HEAD+PUT-with-Content-Range (cheap,
        // but needs a server that honours ranges) and GET+PUT
        // (expensive but universal). The selection key is the
        // current range_hint — if it's degraded all the way, we
        // fall back to GET+PUT.
        if self.inner.range_hint_str().is_some() {
            self.append_by_head_put(relpath, bytes)
        } else {
            self.append_by_get_put(relpath, bytes)
        }
    }

    fn append_file(
        &self,
        relpath: &UrlFragment,
        f: &mut dyn Read,
        permissions: Option<Permissions>,
    ) -> Result<u64> {
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(Error::Io)?;
        self.append_bytes(relpath, &buf, permissions)
    }

    fn rename(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let abs_from = self.inner.remote_url(rel_from)?.to_string();
        let abs_to = self.inner.remote_url(rel_to)?.to_string();
        // Rename in bzr-speak means "don't overwrite" — the
        // destination must not exist.
        self.webdav_move(&abs_from, &abs_to, false)
    }

    fn delete(&self, relpath: &UrlFragment) -> Result<()> {
        let abspath = self.inner.remote_url(relpath)?.to_string();
        let resp = self.inner.request("DELETE", &abspath, &[], &[], false)?;
        match resp.status {
            200 | 204 => Ok(()),
            404 => Err(Error::NoSuchFile(Some(abspath))),
            other => Err(Error::InvalidHttpResponse {
                path: abspath,
                msg: format!("unable to delete (status {}: {})", other, resp.reason),
            }),
        }
    }

    fn rmdir(&self, relpath: &UrlFragment) -> Result<()> {
        // Transport::rmdir contract: fail if the directory isn't
        // empty. RFC 4918 DELETE on a collection removes it *with*
        // contents, so we list first and raise DirectoryNotEmpty
        // ourselves when needed.
        let mut iter = self.list_dir(relpath);
        if let Some(first) = iter.next() {
            // Surface a listing error rather than misreporting it
            // as "directory not empty".
            first?;
            let abspath = self.inner.remote_url(relpath)?.to_string();
            return Err(Error::DirectoryNotEmptyError(Some(abspath)));
        }
        self.delete(relpath)
    }

    fn delete_tree(&self, relpath: &UrlFragment) -> Result<()> {
        // DELETE on a collection in WebDAV removes it plus all
        // children. The Python transport doesn't expose delete_tree
        // but a recursive delete maps naturally onto the protocol.
        self.delete(relpath)
    }

    fn copy(&self, rel_from: &UrlFragment, rel_to: &UrlFragment) -> Result<()> {
        let abs_from = self.inner.remote_url(rel_from)?.to_string();
        let abs_to = self.inner.remote_url(rel_to)?.to_string();
        let headers = [("Destination".to_string(), abs_to.clone())];
        let resp = self
            .inner
            .request("COPY", &abs_from, &headers, &[], false)?;
        match resp.status {
            // Apache returns 204 on overwrite; the dromedary test
            // server returns 201. Both are acceptable per RFC 4918.
            201 | 204 => Ok(()),
            404 | 409 => Err(Error::NoSuchFile(Some(abs_from))),
            other => Err(Error::InvalidHttpResponse {
                path: abs_from.clone(),
                msg: format!(
                    "unable to copy from {} to {} (status {}: {})",
                    abs_from, abs_to, other, resp.reason
                ),
            }),
        }
    }

    fn list_dir(&self, relpath: &UrlFragment) -> Box<dyn Iterator<Item = Result<String>>> {
        let abspath = match self.inner.remote_url(relpath) {
            Ok(u) => u.to_string(),
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        match self.propfind(relpath, "1") {
            Ok(body) => match parse_propfind_dir(&body, &abspath) {
                Ok(entries) => Box::new(entries.into_iter().map(|e| Ok(e.href))),
                Err(e) => Box::new(std::iter::once(Err(e))),
            },
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }

    fn iter_files_recursive(&self) -> Box<dyn Iterator<Item = Result<String>>> {
        // PROPFIND with depth=Infinity. Some real servers disable
        // this; bzr/dromedary has always relied on it so we match.
        let abspath = match self.inner.remote_url(".") {
            Ok(u) => u.to_string(),
            Err(e) => return Box::new(std::iter::once(Err(e))),
        };
        match self.propfind(".", "Infinity") {
            Ok(body) => match parse_propfind_dir(&body, &abspath) {
                Ok(entries) => Box::new(
                    entries
                        .into_iter()
                        .filter(|e| !e.is_dir)
                        .map(|e| Ok(e.href)),
                ),
                Err(e) => Box::new(std::iter::once(Err(e))),
            },
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }

    fn readv<'a>(
        &self,
        relpath: &'a UrlFragment,
        offsets: Vec<(u64, usize)>,
        adjust_for_latency: bool,
        upper_limit: Option<u64>,
    ) -> Box<dyn Iterator<Item = Result<(u64, Vec<u8>)>> + Send + 'a> {
        self.inner
            .readv(relpath, offsets, adjust_for_latency, upper_limit)
    }

    fn lock_read(&self, relpath: &UrlFragment) -> Result<Box<dyn crate::Lock + Send + Sync>> {
        self.inner.lock_read(relpath)
    }

    fn lock_write(&self, relpath: &UrlFragment) -> Result<Box<dyn crate::Lock + Send + Sync>> {
        // Python follows FTP: return a bogus read lock rather than
        // implement WebDAV LOCK/UNLOCK. Comment from the Python
        // version: "WebDAV supports some sort of locking [but] we
        // don't explicitly support locking a specific file."
        self.inner.lock_read(relpath)
    }

    fn readlink(&self, _relpath: &UrlFragment) -> Result<String> {
        Err(unsupported("readlink()"))
    }

    fn symlink(&self, _source: &UrlFragment, _link_name: &UrlFragment) -> Result<()> {
        Err(unsupported("symlink()"))
    }

    fn hardlink(&self, _source: &UrlFragment, _link_name: &UrlFragment) -> Result<()> {
        Err(unsupported("hardlink()"))
    }

    fn open_write_stream(
        &self,
        _relpath: &UrlFragment,
        _permissions: Option<Permissions>,
    ) -> Result<Box<dyn crate::WriteStream + Send + Sync>> {
        // Python emulates this with AppendBasedFileStream; bzr uses
        // it for the knit index. We'd need an analogous streaming
        // wrapper in Rust — out of scope for this stage.
        Err(unsupported("open_write_stream()"))
    }

    fn local_abspath(&self, _relpath: &UrlFragment) -> Result<std::path::PathBuf> {
        Err(Error::NotLocalUrl(self.inner.base().to_string()))
    }
}

impl ConnectedTransport for HttpDavTransport {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_client() -> Arc<HttpClient> {
        Arc::new(
            HttpClient::new(crate::http::client::HttpClientConfig::default())
                .expect("client builds"),
        )
    }

    #[test]
    fn strip_dav_scheme_suffix_drops_impl_qualifier() {
        assert_eq!(
            strip_dav_scheme_suffix("http+webdav://example.com/"),
            "http://example.com/"
        );
        assert_eq!(
            strip_dav_scheme_suffix("https+urllib://example.com/path/"),
            "https://example.com/path/"
        );
    }

    #[test]
    fn strip_dav_scheme_suffix_passes_through_plain_scheme() {
        assert_eq!(
            strip_dav_scheme_suffix("http://example.com/"),
            "http://example.com/"
        );
    }

    #[test]
    fn strip_dav_scheme_suffix_passes_through_non_url() {
        // No `://` — we don't know how to classify it, but we
        // shouldn't panic either. HttpTransport::new will reject it.
        assert_eq!(strip_dav_scheme_suffix("not a url"), "not a url");
    }

    #[test]
    fn new_accepts_webdav_scheme_suffix() {
        // `+webdav` is a breezy-era suffix used to pin the WebDAV
        // implementation; HttpTransport rejects it outright so we
        // must strip before delegating.
        let t = HttpDavTransport::new("http+webdav://example.com/", fresh_client()).unwrap();
        assert_eq!(t.base().scheme(), "http");
    }

    #[test]
    fn new_normalises_trailing_slash() {
        let t = HttpDavTransport::new("http://example.com/a", fresh_client()).unwrap();
        assert!(t.base().as_str().ends_with('/'));
    }

    #[test]
    fn transport_is_not_readonly() {
        // Unlike plain HTTP, WebDAV supports writes — so is_readonly
        // must return false so bzr tries write operations.
        let t = HttpDavTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(!t.is_readonly());
    }

    #[test]
    fn transport_is_listable() {
        let t = HttpDavTransport::new("http://example.com/", fresh_client()).unwrap();
        assert!(t.listable());
    }

    #[test]
    fn temp_suffix_starts_with_dot_tmp_and_varies() {
        let a = HttpDavTransport::temp_suffix();
        let b = HttpDavTransport::temp_suffix();
        assert!(a.starts_with(".tmp."));
        // Random component is 32 bits so collisions are unlikely
        // enough that this flaky-flake is cheap insurance against a
        // regression where the random bit gets dropped.
        assert_ne!(a, b);
    }
}
