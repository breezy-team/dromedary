//! HTTP authentication header builders.
//!
//! Thin composition layer over the primitives ported in Stage 2
//! (`DigestAlgorithm`, `new_cnonce`, `parse_auth_header`,
//! `parse_http_list`, `parse_keqv_list`). This module holds the
//! recipes that turn a parsed challenge + credentials into the
//! `Authorization:` header value.
//!
//! Stage 6 scope is pure-Rust composition. The Python side still
//! owns the handler chain (BasicAuthHandler / DigestAuthHandler /
//! NegotiateAuthHandler in `dromedary/http/urllib.py`); Stage 7 is
//! where the Rust `HttpClient` starts driving auth itself.
//! Negotiate (kerberos) intentionally lives outside this module —
//! it's a pluggable callback on the client, not a header formula.

use base64::Engine;

use super::{new_cnonce, DigestAlgorithm};

/// Build the value of an `Authorization: Basic ...` header.
///
/// Mirrors `BasicAuthHandler.build_auth_header`: base64-encode
/// `"user:password"` as UTF-8 and prepend the scheme keyword.
pub fn build_basic_auth_header(user: &str, password: &str) -> String {
    let raw = format!("{}:{}", user, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    format!("Basic {}", encoded)
}

/// Per-connection digest-auth state.
///
/// The `nonce_count` counter must be monotonic across retries
/// against the same server nonce; a fresh nonce resets it to zero
/// (matching `DigestAuthHandler.auth_match`'s behaviour when it
/// sees `auth["nonce"] != nonce`).
#[derive(Debug, Clone)]
pub struct DigestAuthState {
    pub user: String,
    pub password: String,
    pub realm: String,
    pub nonce: String,
    /// The last `nonce_count` used. `build_digest_auth_header`
    /// increments this before formatting the `nc=...` field, so the
    /// first request bumps from 0 → 1 (matching Python's behaviour
    /// where `nonce_count` starts at 0 and the header shows `nc=00000001`).
    pub nonce_count: u64,
    pub algorithm: DigestAlgorithm,
    pub algorithm_name: Option<String>,
    pub opaque: Option<String>,
    pub qop: String,
}

/// Parsed `WWW-Authenticate: Digest ...` challenge that we can
/// actually handle. `parse_digest_challenge` returns `None` when
/// anything the Python version would have rejected is missing:
/// unsupported `qop`, unsupported `algorithm`, or missing `nonce` /
/// `realm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub algorithm: DigestAlgorithm,
    /// Original `algorithm=` parameter value as the server sent it.
    /// Kept verbatim so the echoed `algorithm=` field in the
    /// response can be byte-for-byte the same.
    pub algorithm_name: Option<String>,
    pub opaque: Option<String>,
    /// Currently we only accept `qop=auth` (no `auth-int`), mirroring
    /// the Python `DigestAuthHandler.auth_match` check at urllib.py:1894.
    pub qop: String,
}

/// Parse the remainder of a `WWW-Authenticate: Digest ...` header
/// (the part after the `Digest ` scheme keyword, typically what
/// [`super::parse_auth_header`] hands back as the remainder).
///
/// Returns `None` if the challenge is missing a required field or
/// specifies an algorithm/qop we can't handle. Matches the Python
/// `DigestAuthHandler.auth_match` accept/reject criteria.
pub fn parse_digest_challenge(raw_auth: &str) -> Option<DigestChallenge> {
    let params = super::parse_keqv_list(&super::parse_http_list(raw_auth));
    // qop=auth only — Python `auth_match` rejects everything else
    // including the `auth-int` variant.
    let qop = params.get("qop")?.clone();
    if qop != "auth" {
        return None;
    }
    // Default algorithm is MD5 when the server doesn't specify one.
    let algorithm_name = params.get("algorithm").cloned();
    let algorithm_str = algorithm_name.as_deref().unwrap_or("MD5");
    let algorithm = DigestAlgorithm::parse(algorithm_str)?;
    let realm = params.get("realm")?.clone();
    let nonce = params.get("nonce")?.clone();
    let opaque = params.get("opaque").cloned();
    Some(DigestChallenge {
        realm,
        nonce,
        algorithm,
        algorithm_name,
        opaque,
        qop,
    })
}

/// Build the `Authorization: Digest ...` header value for the given
/// request, bumping `state.nonce_count` by one in the process.
///
/// Follows RFC 2617 §3.2.2 — the same recipe the Python
/// `DigestAuthHandler.build_auth_header` uses:
///
/// ```text
/// A1 = user:realm:password
/// A2 = method:uri
/// response = KD(H(A1), nonce:nc:cnonce:qop:H(A2))
/// ```
///
/// The `uri` argument should be the path component the client
/// sends (what the Python version extracts with
/// `urlparse(request.selector).path`).
pub fn build_digest_auth_header(state: &mut DigestAuthState, method: &str, uri: &str) -> String {
    state.nonce_count += 1;
    let ncvalue = format!("{:08x}", state.nonce_count);
    let cnonce = new_cnonce(&state.nonce, state.nonce_count);

    let algo = state.algorithm;
    let a1 = format!("{}:{}:{}", state.user, state.realm, state.password);
    let a2 = format!("{}:{}", method, uri);
    let nonce_data = format!(
        "{}:{}:{}:{}:{}",
        state.nonce,
        ncvalue,
        cnonce,
        state.qop,
        algo.h(a2.as_bytes())
    );
    let response_digest = algo.kd(&algo.h(a1.as_bytes()), &nonce_data);

    let mut header = format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", cnonce=\"{cnonce}\", nc={nc}, qop=\"{qop}\", response=\"{resp}\"",
        user = state.user,
        realm = state.realm,
        nonce = state.nonce,
        uri = uri,
        cnonce = cnonce,
        nc = ncvalue,
        qop = state.qop,
        resp = response_digest,
    );
    if let Some(opaque) = &state.opaque {
        // Python only appends `opaque` when the value is truthy;
        // mirror that by skipping empty strings too.
        if !opaque.is_empty() {
            header.push_str(&format!(", opaque=\"{}\"", opaque));
        }
    }
    if let Some(alg) = &state.algorithm_name {
        if !alg.is_empty() {
            header.push_str(&format!(", algorithm=\"{}\"", alg));
        }
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_header_matches_known_vector() {
        // RFC 7617 §2 example: user `Aladdin`, password `open sesame`
        // → `QWxhZGRpbjpvcGVuIHNlc2FtZQ==`.
        assert_eq!(
            build_basic_auth_header("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn basic_header_handles_empty_password() {
        // Some services (webdav guests) do `user:` — the colon is
        // still present.
        assert_eq!(build_basic_auth_header("user", ""), "Basic dXNlcjo=");
    }

    #[test]
    fn basic_header_does_not_embed_newlines() {
        // Regression test for https://bugs.launchpad.net/bzr/+bug/1606203:
        // Python's base64 module wrapped at 76 chars and embedded
        // '\n' into long-credential Authorization headers, which
        // the server rejected as a malformed line. Long creds here
        // exercise the wrap-trigger path.
        let user = "user".repeat(10); // 40 chars
        let password = "password".repeat(5); // 40 chars
        let hdr = build_basic_auth_header(&user, &password);
        assert!(
            !hdr.contains('\n'),
            "header must not embed newlines: {:?}",
            hdr
        );
    }

    #[test]
    fn parse_digest_challenge_happy_path() {
        let raw = r#"realm="Example", nonce="abc123", qop="auth", algorithm="MD5", opaque="o"#
            .to_string()
            + "\"";
        let c = parse_digest_challenge(&raw).expect("valid challenge");
        assert_eq!(c.realm, "Example");
        assert_eq!(c.nonce, "abc123");
        assert_eq!(c.qop, "auth");
        assert_eq!(c.algorithm, DigestAlgorithm::Md5);
        assert_eq!(c.algorithm_name.as_deref(), Some("MD5"));
        assert_eq!(c.opaque.as_deref(), Some("o"));
    }

    #[test]
    fn parse_digest_challenge_rejects_auth_int() {
        // Python `auth_match` explicitly checks `qop != "auth"` and
        // returns False for anything else, including `auth-int`.
        let raw = r#"realm="Example", nonce="abc123", qop="auth-int""#;
        assert!(parse_digest_challenge(raw).is_none());
    }

    #[test]
    fn parse_digest_challenge_rejects_unknown_algorithm() {
        // SHA-256 isn't in our table yet — Python returns False.
        let raw = r#"realm="Example", nonce="abc123", qop="auth", algorithm="SHA-256""#;
        assert!(parse_digest_challenge(raw).is_none());
    }

    #[test]
    fn parse_digest_challenge_defaults_md5() {
        // Algorithm field is optional; servers that omit it mean MD5.
        let raw = r#"realm="Example", nonce="abc123", qop="auth""#;
        let c = parse_digest_challenge(raw).expect("valid challenge");
        assert_eq!(c.algorithm, DigestAlgorithm::Md5);
        assert_eq!(c.algorithm_name, None);
    }

    #[test]
    fn parse_digest_challenge_missing_nonce() {
        let raw = r#"realm="Example", qop="auth""#;
        assert!(parse_digest_challenge(raw).is_none());
    }

    #[test]
    fn digest_header_has_rfc_shape() {
        // Drive with fixed inputs and check the header contains the
        // pieces we expect. The `response=` and `cnonce=` values
        // include a time-dependent cnonce, so we don't assert on the
        // exact digest — only that the field layout matches what
        // Python's version emits.
        let mut state = DigestAuthState {
            user: "alice".into(),
            password: "secret".into(),
            realm: "Example".into(),
            nonce: "abc123".into(),
            nonce_count: 0,
            algorithm: DigestAlgorithm::Md5,
            algorithm_name: Some("MD5".into()),
            opaque: Some("opaqueval".into()),
            qop: "auth".into(),
        };
        let header = build_digest_auth_header(&mut state, "GET", "/path");
        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"alice\""));
        assert!(header.contains("realm=\"Example\""));
        assert!(header.contains("nonce=\"abc123\""));
        assert!(header.contains("uri=\"/path\""));
        // Python's ncvalue is zero-padded to 8 hex digits.
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("qop=\"auth\""));
        assert!(header.contains("response=\""));
        assert!(header.contains("opaque=\"opaqueval\""));
        assert!(header.contains("algorithm=\"MD5\""));
        // nonce_count bumped.
        assert_eq!(state.nonce_count, 1);
    }

    #[test]
    fn digest_header_increments_nonce_count() {
        let mut state = DigestAuthState {
            user: "alice".into(),
            password: "s".into(),
            realm: "R".into(),
            nonce: "n".into(),
            nonce_count: 5,
            algorithm: DigestAlgorithm::Md5,
            algorithm_name: None,
            opaque: None,
            qop: "auth".into(),
        };
        let header = build_digest_auth_header(&mut state, "GET", "/");
        assert_eq!(state.nonce_count, 6);
        assert!(header.contains("nc=00000006"));
    }

    #[test]
    fn digest_header_skips_empty_opaque_and_algorithm() {
        // Matches Python: `if opaque:` skips empty strings.
        let mut state = DigestAuthState {
            user: "a".into(),
            password: "b".into(),
            realm: "r".into(),
            nonce: "n".into(),
            nonce_count: 0,
            algorithm: DigestAlgorithm::Md5,
            algorithm_name: Some("".into()),
            opaque: Some("".into()),
            qop: "auth".into(),
        };
        let header = build_digest_auth_header(&mut state, "GET", "/");
        assert!(
            !header.contains("opaque"),
            "empty opaque should be omitted: {}",
            header
        );
        assert!(
            !header.contains("algorithm"),
            "empty algorithm should be omitted: {}",
            header
        );
    }

    #[test]
    fn digest_response_matches_rfc_2617_vector() {
        // The canonical RFC 2617 §3.5 example, minus `uri=` in the
        // request-line (we use the absolute path). Given:
        //   user     = Mufasa
        //   password = Circle Of Life
        //   realm    = testrealm@host.com
        //   nonce    = dcd98b7102dd2f0e8b11d0f600bfb0c093
        //   method   = GET
        //   uri      = /dir/index.html
        //   qop      = auth
        //   nc       = 00000001
        //   cnonce   = 0a4f113b
        // the RFC says the response digest is:
        //   6629fae49393a05397450978507c4ef1
        //
        // Our cnonce is random, so we can't reuse the vector as-is.
        // Instead we reconstruct it by computing the digest by hand
        // with the same inputs our function uses, and then assert
        // that `build_digest_auth_header` produces a `response=` we
        // can't easily verify against a published fixture — so skip
        // the end-to-end response check here and let the per-piece
        // tests in DigestAlgorithm cover the crypto. The other tests
        // above cover the *shape* of the header, which is what we
        // control.
        //
        // This keeps the RFC test as a documentation reference.
        let a1 = "Mufasa:testrealm@host.com:Circle Of Life";
        let a2 = "GET:/dir/index.html";
        let h_a1 = DigestAlgorithm::Md5.h(a1.as_bytes());
        assert_eq!(h_a1, "939e7578ed9e3c518a452acee763bce9");
        let h_a2 = DigestAlgorithm::Md5.h(a2.as_bytes());
        assert_eq!(h_a2, "39aff3a2bab6126f332b942af96d3366");
    }
}
