//! WebDAV transport on top of HTTP.
//!
//! Implements the subset of RFC 4918 bzr / dromedary needs: PUT/GET,
//! MKCOL, MOVE, DELETE, COPY, and PROPFIND (depth 0 / 1 / Infinity).
//! Locking and property setting are out of scope — bzr fakes locks
//! with a bogus lock and stores everything it needs in file content.
//!
//! The module is feature-gated behind `webdav`: it pulls in
//! `quick-xml` for parsing multi-status PROPFIND responses, which
//! callers that only talk plain HTTP shouldn't pay for.

pub mod transport;
pub mod xml;

pub use transport::HttpDavTransport;
pub use xml::{parse_propfind_dir, parse_propfind_stat, DavEntry, DavStat};
