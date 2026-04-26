//! PROPFIND multi-status response parser.
//!
//! Ports `DavStatHandler` / `DavListDirHandler` from
//! `dromedary/webdav/webdav.py`. The Python version is a SAX
//! ContentHandler maintaining an element stack; we use `quick-xml`'s
//! pull-parser and keep an equivalent stack of stripped element
//! names (namespace prefixes dropped — we don't care about them in
//! practice because the WebDAV vocabulary is flat enough that
//! `response/href`, `propstat/prop/resourcetype/collection` etc.
//! are unambiguous).

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::{Error, Result};

/// Stat-like data extracted from a depth-0 PROPFIND response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavStat {
    /// Size in bytes; `-1` for directories where the length is
    /// meaningless. Matches Python `_DAVStat.st_size`.
    pub size: i64,
    pub is_dir: bool,
    pub is_exec: bool,
}

/// One entry from a depth-1 or -Infinity PROPFIND response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavEntry {
    pub href: String,
    pub is_dir: bool,
    pub size: i64,
    pub is_exec: bool,
}

/// State accumulated while walking a single `response` element —
/// drained into a `DavEntry` or promoted into a `DavStat` depending
/// on which parser called us.
#[derive(Default)]
struct ResponseAccumulator {
    href: Option<String>,
    length: Option<i64>,
    executable: Option<String>,
    is_dir: bool,
}

impl ResponseAccumulator {
    fn into_entry(self) -> Option<DavEntry> {
        let href = self.href?;
        let size = if self.is_dir {
            -1
        } else {
            self.length.unwrap_or(-1)
        };
        let is_exec = if self.is_dir {
            // Directories are reported as executable to match
            // Python `_extract_stat_info` which does the same —
            // bzr expects to be able to descend into them.
            true
        } else {
            matches!(self.executable.as_deref(), Some("T"))
        };
        Some(DavEntry {
            href,
            is_dir: self.is_dir,
            size,
            is_exec,
        })
    }
}

/// Parse a depth-0 PROPFIND response and return the single entry's
/// stat metadata. `url` is only used in error messages.
pub fn parse_propfind_stat(body: &[u8], url: &str) -> Result<DavStat> {
    let entries = parse_responses(body, url)?;
    let first = entries
        .into_iter()
        .next()
        .ok_or_else(|| Error::InvalidHttpResponse {
            path: url.to_string(),
            msg: "PROPFIND returned no response elements".into(),
        })?;
    Ok(DavStat {
        size: first.size,
        is_dir: first.is_dir,
        is_exec: first.is_exec,
    })
}

/// Parse a depth-1 or -Infinity PROPFIND response. The first entry
/// is the directory itself (its href is used to compute relative
/// names); subsequent entries are the children. Returns the child
/// entries with their `href` trimmed to the name relative to the
/// directory, matching `_extract_dir_content`.
pub fn parse_propfind_dir(body: &[u8], url: &str) -> Result<Vec<DavEntry>> {
    let entries = parse_responses(body, url)?;
    let mut iter = entries.into_iter();
    let first = iter.next().ok_or_else(|| Error::InvalidHttpResponse {
        path: url.to_string(),
        msg: "PROPFIND returned no response elements".into(),
    })?;
    if !first.is_dir {
        return Err(Error::NotADirectoryError(Some(url.to_string())));
    }
    let dir_href = first.href;
    let dir_len = dir_href.len();
    let mut out = Vec::new();
    for mut entry in iter {
        if !entry.href.starts_with(&dir_href) {
            continue;
        }
        let mut name = entry.href[dir_len..].to_string();
        if name.ends_with('/') {
            name.pop();
        }
        entry.href = name;
        out.push(entry);
    }
    Ok(out)
}

/// Walk every `<response>` element in the body and return a
/// `DavEntry` per response. Shared backend for the two entry points.
fn parse_responses(body: &[u8], url: &str) -> Result<Vec<DavEntry>> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut acc: Option<ResponseAccumulator> = None;
    let mut chars = String::new();
    let mut entries: Vec<DavEntry> = Vec::new();

    let parse_err = |e: quick_xml::Error| Error::InvalidHttpResponse {
        path: url.to_string(),
        msg: format!("Malformed xml response: {}", e),
    };

    loop {
        match reader.read_event_into(&mut buf).map_err(parse_err)? {
            Event::Start(e) => {
                let name = strip_ns(e.name().as_ref());
                stack.push(name.clone());
                chars.clear();
                if name == "response" {
                    acc = Some(ResponseAccumulator::default());
                }
            }
            Event::End(_) => {
                let Some(name) = stack.pop() else { continue };
                if let Some(ref mut a) = acc {
                    commit_element(a, &stack, &name, &chars);
                }
                if name == "response" {
                    if let Some(a) = acc.take() {
                        if let Some(entry) = a.into_entry() {
                            entries.push(entry);
                        }
                    }
                }
                chars.clear();
            }
            Event::Empty(e) => {
                // quick-xml yields self-closing tags (`<D:collection/>`)
                // as Empty events rather than Start+End. Synthesise
                // the stack push/pop so commit_element sees the right
                // path.
                let name = strip_ns(e.name().as_ref());
                stack.push(name.clone());
                if let Some(ref mut a) = acc {
                    commit_element(a, &stack[..stack.len() - 1], &name, "");
                }
                stack.pop();
            }
            Event::Text(t) => {
                if acc.is_some() {
                    let s = t.unescape().map_err(parse_err)?;
                    chars.push_str(&s);
                }
            }
            Event::CData(t) => {
                if acc.is_some() {
                    chars.push_str(&String::from_utf8_lossy(&t));
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if entries.is_empty() {
        return Err(Error::InvalidHttpResponse {
            path: url.to_string(),
            msg: "Unknown xml response".into(),
        });
    }
    Ok(entries)
}

/// Apply a completed element's content to the accumulator.
///
/// `stack` is the element stack *not* including the element we're
/// committing — mirrors how the Python version checked the stack
/// before the pop.
fn commit_element(acc: &mut ResponseAccumulator, stack: &[String], name: &str, chars: &str) {
    // Expected stacks, matching the Python _href_end / _getcontentlength_end
    // / _executable_end / _collection_end helpers:
    //   /multistatus/response/href
    //   /multistatus/response/propstat/prop/getcontentlength
    //   /multistatus/response/propstat/prop/executable
    //   /multistatus/response/propstat/prop/resourcetype/collection
    let depth = stack.len();
    match name {
        "href" => {
            if depth == 2 && stack[0] == "multistatus" && stack[1] == "response" {
                acc.href = Some(chars.to_string());
            }
        }
        "getcontentlength" => {
            if depth == 4
                && stack[0] == "multistatus"
                && stack[1] == "response"
                && stack[2] == "propstat"
                && stack[3] == "prop"
            {
                if let Ok(n) = chars.trim().parse::<i64>() {
                    acc.length = Some(n);
                }
            }
        }
        "executable" => {
            if depth == 4
                && stack[0] == "multistatus"
                && stack[1] == "response"
                && stack[2] == "propstat"
                && stack[3] == "prop"
            {
                acc.executable = Some(chars.trim().to_string());
            }
        }
        "collection" => {
            if depth == 5
                && stack[0] == "multistatus"
                && stack[1] == "response"
                && stack[2] == "propstat"
                && stack[3] == "prop"
                && stack[4] == "resourcetype"
            {
                acc.is_dir = true;
            }
        }
        _ => {}
    }
}

/// Strip a `ns:name` qualifier from an element name. WebDAV uses
/// namespace prefixes (`D:response`, `liveprop:getcontentlength`)
/// but the vocabulary is flat enough that we don't need to track
/// which prefix binds which URI — treating `href` and `D:href` as
/// equivalent is what the Python version does.
fn strip_ns(raw: &[u8]) -> String {
    let s = std::str::from_utf8(raw).unwrap_or("");
    match s.split_once(':') {
        Some((_, rest)) => rest.to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT_FILE: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:liveprop="DAV:" xmlns:bzr="DAV:">
  <D:response>
    <D:href>/some/file.txt</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype/>
        <liveprop:getcontentlength>1234</liveprop:getcontentlength>
        <bzr:executable>F</bzr:executable>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    const STAT_DIR: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:liveprop="DAV:">
  <D:response>
    <D:href>/some/dir/</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype><D:collection/></liveprop:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    const STAT_EXEC: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:liveprop="DAV:" xmlns:bzr="DAV:">
  <D:response>
    <D:href>/some/script.sh</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype/>
        <liveprop:getcontentlength>99</liveprop:getcontentlength>
        <bzr:executable>T</bzr:executable>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    const DIR_LIST: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:liveprop="DAV:" xmlns:bzr="DAV:">
  <D:response>
    <D:href>/dir/</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype><D:collection/></liveprop:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dir/a.txt</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype/>
        <liveprop:getcontentlength>10</liveprop:getcontentlength>
        <bzr:executable>F</bzr:executable>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dir/sub/</D:href>
    <D:propstat>
      <D:prop>
        <liveprop:resourcetype><D:collection/></liveprop:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    #[test]
    fn stat_file_extracts_size_and_not_dir() {
        let stat = parse_propfind_stat(STAT_FILE, "/some/file.txt").unwrap();
        assert_eq!(
            stat,
            DavStat {
                size: 1234,
                is_dir: false,
                is_exec: false,
            }
        );
    }

    #[test]
    fn stat_directory_reports_is_dir_and_exec_sentinel() {
        let stat = parse_propfind_stat(STAT_DIR, "/some/dir/").unwrap();
        // Matches Python: directories carry size=-1 and is_exec=True
        // so bzr can descend into them.
        assert_eq!(
            stat,
            DavStat {
                size: -1,
                is_dir: true,
                is_exec: true,
            }
        );
    }

    #[test]
    fn stat_executable_flag_recognised() {
        let stat = parse_propfind_stat(STAT_EXEC, "/some/script.sh").unwrap();
        assert!(stat.is_exec);
    }

    #[test]
    fn listdir_strips_parent_prefix_and_trailing_slash() {
        let entries = parse_propfind_dir(DIR_LIST, "/dir/").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].href, "a.txt");
        assert_eq!(entries[0].is_dir, false);
        assert_eq!(entries[0].size, 10);
        assert_eq!(entries[1].href, "sub");
        assert_eq!(entries[1].is_dir, true);
    }

    #[test]
    fn listdir_on_file_yields_not_a_directory() {
        // A depth-1 PROPFIND issued against a file returns a single
        // response whose resourcetype is not `collection`. We surface
        // that as NotADirectory rather than silently returning empty.
        let result = parse_propfind_dir(STAT_FILE, "/some/file.txt");
        assert!(matches!(result, Err(Error::NotADirectoryError(_))));
    }

    #[test]
    fn malformed_xml_raises_invalid_http_response() {
        let result = parse_propfind_stat(b"<not<valid>>", "/url");
        assert!(matches!(result, Err(Error::InvalidHttpResponse { .. })));
    }

    #[test]
    fn empty_multistatus_reports_unknown_xml_response() {
        let body = br#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"/>"#;
        let result = parse_propfind_stat(body, "/url");
        assert!(matches!(result, Err(Error::InvalidHttpResponse { .. })));
    }

    #[test]
    fn namespace_prefix_variations_treated_equivalently() {
        // Apache mod_dav uses `lp1:` and `lp2:` for the bzr/liveprop
        // namespaces. The stripper drops the prefix, so both parse.
        let body = br#"<?xml version="1.0"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/f</href>
    <propstat>
      <prop>
        <resourcetype/>
        <getcontentlength>42</getcontentlength>
        <executable>F</executable>
      </prop>
    </propstat>
  </response>
</multistatus>"#;
        let stat = parse_propfind_stat(body, "/f").unwrap();
        assert_eq!(stat.size, 42);
    }

    #[test]
    fn unknown_format_xml_rejected() {
        // Valid XML but not a multistatus — Python raises
        // InvalidHttpResponse with msg="Unknown xml response".
        let result = parse_propfind_stat(b"<document/>", "/url");
        assert!(matches!(result, Err(Error::InvalidHttpResponse { .. })));
        // Same for listdir.
        let result = parse_propfind_dir(b"<document/>", "/url");
        assert!(matches!(result, Err(Error::InvalidHttpResponse { .. })));
    }

    #[test]
    fn listdir_first_entry_without_resourcetype_rejected() {
        // lighttpd returns no resourcetype elements at all. Without a
        // collection marker on the first entry, it's indistinguishable
        // from a file, so listdir must fail with NotADirectory.
        let body = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dir/</D:href></D:response>
  <D:response><D:href>/dir/a</D:href></D:response>
  <D:response><D:href>/dir/b</D:href></D:response>
</D:multistatus>"#;
        let result = parse_propfind_dir(body, "/dir/");
        assert!(matches!(result, Err(Error::NotADirectoryError(_))));
    }

    #[test]
    fn apache_lp1_lp2_prefixes_parsed() {
        // Apache mod_dav's allprop response uses `lp1:` and `lp2:`
        // prefixes for the live and dead properties respectively.
        let body = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
    <D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
        <D:href>/executable</D:href>
        <D:propstat>
            <D:prop>
                <lp1:resourcetype/>
                <lp1:getcontentlength>12</lp1:getcontentlength>
                <lp2:executable>T</lp2:executable>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>
</D:multistatus>"#;
        let stat = parse_propfind_stat(body, "/executable").unwrap();
        assert_eq!(stat.size, 12);
        assert!(!stat.is_dir);
        assert!(stat.is_exec);
    }

    #[test]
    fn href_outside_response_stack_ignored() {
        // An `href` at a different stack depth (e.g. inside a
        // propstat) must not be picked up as the response's href.
        let body = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:propstat><D:href>noise</D:href></D:propstat>
    <D:href>/real</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>0</D:getcontentlength>
      </D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        // The real href comes second and should win over the noise one.
        let entries = parse_responses(body, "/real").unwrap();
        assert_eq!(entries[0].href, "/real");
    }
}
