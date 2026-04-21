//! Pure-logic pieces of the SSH module — argv construction for subprocess
//! vendors, shared by the PyO3 layer in `_transport_rs` and unit-testable
//! without Python link symbols.
//!
//! Spawning, connection wrappers, and library-backed vendors live in
//! `_transport_rs/src/ssh/` because they're PyO3-facing.

use std::error::Error;
use std::fmt;

/// Which subprocess vendor we're building argv for. Collapses the per-vendor
/// Python classes into an enum because they differ only in flag syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    OpenSSH,
    Lsh,
    PLink,
}

impl Flavor {
    pub fn executable(self) -> &'static str {
        match self {
            Flavor::OpenSSH => "ssh",
            Flavor::Lsh => "lsh",
            Flavor::PLink => "plink",
        }
    }
}

/// Reasons `build_argv` may reject its input. Callers map these to the
/// appropriate Python exceptions (`StrangeHostname`, etc.).
#[derive(Debug)]
pub enum ArgvError {
    /// Hostname starts with `-`; would be interpreted as a flag by the ssh
    /// binary. Matches Python `StrangeHostname`.
    StrangeHostname(String),
    /// Neither (or both of) `subsystem` and `command` were provided.
    InvalidArguments,
}

impl fmt::Display for ArgvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgvError::StrangeHostname(h) => {
                write!(f, "Refusing to connect to strange SSH hostname {h}")
            }
            ArgvError::InvalidArguments => {
                write!(f, "exactly one of subsystem or command must be provided")
            }
        }
    }
}

impl Error for ArgvError {}

/// Build the full argv for a subprocess vendor.
///
/// Exactly one of `subsystem` and `command` must be `Some`. The produced
/// argv matches the Python vendor classes in `dromedary/ssh/__init__.py`
/// byte-for-byte so behavioral tests that compare argv stay stable across
/// the port.
pub fn build_argv(
    flavor: Flavor,
    username: Option<&str>,
    host: &str,
    port: Option<u16>,
    subsystem: Option<&str>,
    command: Option<&[String]>,
) -> Result<Vec<String>, ArgvError> {
    // Match Python exactly: OpenSSH doesn't call _check_hostname, the others
    // do. The `--` separator before host in the OpenSSH argv makes this safe
    // for OpenSSH specifically.
    // TODO: Python OpenSSH vendor likely should also reject leading-dash
    // hostnames defensively — raise upstream before changing behavior.
    if !matches!(flavor, Flavor::OpenSSH) && host.starts_with('-') {
        return Err(ArgvError::StrangeHostname(host.to_string()));
    }

    let mut args: Vec<String> = Vec::new();
    args.push(flavor.executable().to_string());

    match flavor {
        Flavor::OpenSSH => {
            args.extend(
                [
                    "-oForwardX11=no",
                    "-oForwardAgent=no",
                    "-oClearAllForwardings=yes",
                    "-oNoHostAuthenticationForLocalhost=yes",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
        Flavor::Lsh => {}
        Flavor::PLink => {
            args.extend(
                ["-x", "-a", "-ssh", "-2", "-batch"]
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
    }

    let port_flag = match flavor {
        Flavor::PLink => "-P",
        _ => "-p",
    };
    if let Some(p) = port {
        args.push(port_flag.to_string());
        args.push(p.to_string());
    }
    if let Some(u) = username {
        args.push("-l".to_string());
        args.push(u.to_string());
    }

    match (subsystem, command) {
        (Some(sub), None) => match flavor {
            Flavor::OpenSSH => {
                args.extend(["-s", "--", host, sub].iter().map(|s| s.to_string()));
            }
            Flavor::Lsh => {
                args.extend(["--subsystem", sub, host].iter().map(|s| s.to_string()));
            }
            Flavor::PLink => {
                args.extend(["-s", host, sub].iter().map(|s| s.to_string()));
            }
        },
        (None, Some(cmd)) => {
            if matches!(flavor, Flavor::OpenSSH) {
                args.push("--".to_string());
            }
            args.push(host.to_string());
            args.extend(cmd.iter().cloned());
        }
        _ => return Err(ArgvError::InvalidArguments),
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn openssh_sftp_argv() {
        let argv = build_argv(
            Flavor::OpenSSH,
            Some("alice"),
            "example.com",
            Some(2222),
            Some("sftp"),
            None,
        )
        .unwrap();
        assert_eq!(
            argv,
            s(&[
                "ssh",
                "-oForwardX11=no",
                "-oForwardAgent=no",
                "-oClearAllForwardings=yes",
                "-oNoHostAuthenticationForLocalhost=yes",
                "-p",
                "2222",
                "-l",
                "alice",
                "-s",
                "--",
                "example.com",
                "sftp",
            ])
        );
    }

    #[test]
    fn openssh_command_argv() {
        let cmd = s(&["bzr", "serve", "--inet"]);
        let argv =
            build_argv(Flavor::OpenSSH, None, "example.com", None, None, Some(&cmd)).unwrap();
        assert_eq!(
            argv,
            s(&[
                "ssh",
                "-oForwardX11=no",
                "-oForwardAgent=no",
                "-oClearAllForwardings=yes",
                "-oNoHostAuthenticationForLocalhost=yes",
                "--",
                "example.com",
                "bzr",
                "serve",
                "--inet",
            ])
        );
    }

    #[test]
    fn lsh_sftp_argv() {
        let argv = build_argv(
            Flavor::Lsh,
            Some("bob"),
            "example.com",
            Some(22),
            Some("sftp"),
            None,
        )
        .unwrap();
        assert_eq!(
            argv,
            s(&[
                "lsh",
                "-p",
                "22",
                "-l",
                "bob",
                "--subsystem",
                "sftp",
                "example.com",
            ])
        );
    }

    #[test]
    fn plink_sftp_argv() {
        let argv = build_argv(
            Flavor::PLink,
            Some("carol"),
            "example.com",
            Some(22),
            Some("sftp"),
            None,
        )
        .unwrap();
        assert_eq!(
            argv,
            s(&[
                "plink",
                "-x",
                "-a",
                "-ssh",
                "-2",
                "-batch",
                "-P",
                "22",
                "-l",
                "carol",
                "-s",
                "example.com",
                "sftp",
            ])
        );
    }

    #[test]
    fn strange_hostname_rejected_for_non_openssh() {
        let err = build_argv(Flavor::Lsh, None, "-evil", None, Some("sftp"), None);
        assert!(matches!(err, Err(ArgvError::StrangeHostname(_))));
    }

    #[test]
    fn openssh_does_not_check_hostname() {
        // Matches Python: OpenSSH vendor never called _check_hostname. The
        // -- separator before host makes this safe for OpenSSH.
        let argv = build_argv(Flavor::OpenSSH, None, "-evil", None, Some("sftp"), None).unwrap();
        assert!(argv.contains(&"-evil".to_string()));
        assert!(argv.contains(&"--".to_string()));
    }

    #[test]
    fn missing_both_subsystem_and_command_errors() {
        let err = build_argv(Flavor::OpenSSH, None, "h", None, None, None);
        assert!(matches!(err, Err(ArgvError::InvalidArguments)));
    }
}
