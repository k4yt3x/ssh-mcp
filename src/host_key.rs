//! Host key verification: what the agent supplied to check a server's key against, the verdict on
//! the key the server presented, and the report every connect returns.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use hmac::{Hmac, KeyInit, Mac};
use russh::keys::ssh_key::{
    Algorithm, Fingerprint, HashAlg, PublicKey,
    known_hosts::{Entry, HostPatterns, KnownHosts, Marker},
};
use sha1::Sha1;

use crate::{output::ToolError, paths::read_small_file};

/// The largest known_hosts file read.
const MAX_KNOWN_HOSTS_BYTES: u64 = 16 * 1024 * 1024;

/// One key the agent expects the server to present.
#[derive(Debug)]
enum ExpectedKey {
    Fingerprint(Fingerprint),
    PublicKey(PublicKey),
}

impl ExpectedKey {
    fn parse(text: &str) -> Result<Self, ToolError> {
        let text = text.trim();
        if text.contains(char::is_whitespace) {
            return PublicKey::from_openssh(text)
                .map(Self::PublicKey)
                .map_err(|_| {
                    ToolError::new(format!(
                        "host_key_fingerprint \"{text}\" is neither a SHA256: fingerprint nor a public key line"
                    ))
                });
        }
        Fingerprint::from_str(text)
            .map(Self::Fingerprint)
            .map_err(|_| {
                ToolError::new(format!(
                    "host_key_fingerprint \"{text}\" is not a fingerprint in the SHA256:... form ssh-keygen -l prints"
                ))
            })
    }

    fn matches(&self, key: &PublicKey) -> bool {
        match self {
            Self::Fingerprint(fingerprint) => {
                key.fingerprint(fingerprint.algorithm()) == *fingerprint
            }
            Self::PublicKey(expected) => expected.key_data() == key.key_data(),
        }
    }
}

/// Where the expected host keys come from.
#[derive(Debug)]
enum Source {
    Nothing,
    Fingerprints(Vec<ExpectedKey>),
    KnownHosts {
        path: PathBuf,
        entries: Vec<Entry>,
        unreadable_lines: usize,
    },
}

/// How the server's host key is checked for one connect.
#[derive(Debug)]
pub(crate) struct HostKeyPolicy {
    source: Source,
    accept_new: bool,
}

/// How an accepted host key was verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verification {
    /// It matched `host_key_fingerprint`.
    Fingerprint,
    /// It matched an entry in `known_hosts_file`.
    KnownHosts(PathBuf),
    /// The host was not known and `accept_new_host_key` accepted it.
    AcceptedNew { known_hosts_file: Option<PathBuf> },
}

impl Verification {
    /// One sentence describing the verification, for the connect result and connection status.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Fingerprint => "verified against host_key_fingerprint".to_owned(),
            Self::KnownHosts(path) => format!("verified against {}", path.display()),
            Self::AcceptedNew {
                known_hosts_file: Some(path),
            } => format!(
                "not verified: the host is not in {}, accepted as new",
                path.display()
            ),
            Self::AcceptedNew {
                known_hosts_file: None,
            } => "not verified: accepted as new".to_owned(),
        }
    }
}

/// The verdict on a presented host key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accepted(Verification),
    Refused(String),
}

impl HostKeyPolicy {
    /// Build the policy from the connect arguments, reading `known_hosts_file` now so a missing or
    /// unreadable file fails before any network traffic.
    pub(crate) fn from_arguments(
        fingerprints: Vec<String>,
        known_hosts_file: Option<PathBuf>,
        accept_new: bool,
    ) -> Result<Self, ToolError> {
        let source = match (fingerprints.is_empty(), known_hosts_file) {
            (false, Some(_)) => {
                return Err(ToolError::new(
                    "host_key_fingerprint and known_hosts_file cannot be combined; pass one",
                ));
            }
            (false, None) => {
                if accept_new {
                    return Err(ToolError::new(
                        "accept_new_host_key cannot be combined with host_key_fingerprint: a fingerprint already says which key to accept",
                    ));
                }
                Source::Fingerprints(
                    fingerprints
                        .iter()
                        .map(|text| ExpectedKey::parse(text))
                        .collect::<Result<_, _>>()?,
                )
            }
            (true, Some(path)) => {
                let text = read_small_file("known_hosts_file", &path, MAX_KNOWN_HOSTS_BYTES)?;
                let (entries, unreadable_lines) = parse_known_hosts(&text);
                Source::KnownHosts {
                    path,
                    entries,
                    unreadable_lines,
                }
            }
            (true, None) => Source::Nothing,
        };
        Ok(Self { source, accept_new })
    }

    /// Host key algorithms the server should be asked for first: those of keys already expected
    /// for this host, so a server with several host keys presents the one that can be checked.
    pub(crate) fn preferred_algorithms(&self, host: &str, port: u16) -> Vec<Algorithm> {
        match &self.source {
            Source::Nothing => Vec::new(),
            Source::Fingerprints(expected) => expected
                .iter()
                .filter_map(|key| match key {
                    ExpectedKey::PublicKey(key) => Some(key.algorithm()),
                    ExpectedKey::Fingerprint(_) => None,
                })
                .collect(),
            Source::KnownHosts { entries, .. } => {
                let name = lookup_name(host, port);
                entries
                    .iter()
                    .filter(|entry| {
                        entry.marker().is_none() && patterns_match(entry.host_patterns(), &name)
                    })
                    .map(|entry| entry.public_key().algorithm())
                    .collect()
            }
        }
    }

    /// Decide whether the key `host:port` presented is accepted.
    pub(crate) fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Verdict {
        match &self.source {
            Source::Nothing => {
                if self.accept_new {
                    Verdict::Accepted(Verification::AcceptedNew {
                        known_hosts_file: None,
                    })
                } else {
                    Verdict::Refused(
                        "No host key check was given. Check the fingerprint below, then pass it as host_key_fingerprint, pass a known_hosts_file, or pass accept_new_host_key to accept the key unverified."
                            .to_owned(),
                    )
                }
            }
            Source::Fingerprints(expected) => {
                if expected.iter().any(|expected| expected.matches(key)) {
                    Verdict::Accepted(Verification::Fingerprint)
                } else {
                    Verdict::Refused(
                        "The server's host key does not match host_key_fingerprint. The server may have been reinstalled, or the connection may be intercepted."
                            .to_owned(),
                    )
                }
            }
            Source::KnownHosts {
                path,
                entries,
                unreadable_lines,
            } => self.verify_against_known_hosts(host, port, key, path, entries, *unreadable_lines),
        }
    }

    fn verify_against_known_hosts(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
        path: &Path,
        entries: &[Entry],
        unreadable_lines: usize,
    ) -> Verdict {
        let name = lookup_name(host, port);
        let applicable: Vec<&Entry> = entries
            .iter()
            .filter(|entry| patterns_match(entry.host_patterns(), &name))
            .collect();
        let revoked = applicable.iter().any(|entry| {
            matches!(entry.marker(), Some(Marker::Revoked))
                && entry.public_key().key_data() == key.key_data()
        });
        if revoked {
            return Verdict::Refused(format!(
                "The server's host key is marked @revoked in {}.",
                path.display()
            ));
        }
        let mut known_algorithms = Vec::new();
        for entry in applicable.iter().filter(|entry| entry.marker().is_none()) {
            if entry.public_key().key_data() == key.key_data() {
                return Verdict::Accepted(Verification::KnownHosts(path.to_path_buf()));
            }
            let algorithm = entry.public_key().algorithm().to_string();
            if !known_algorithms.contains(&algorithm) {
                known_algorithms.push(algorithm);
            }
        }
        if !known_algorithms.is_empty() {
            return Verdict::Refused(format!(
                "The server's host key does not match the key {} lists for {name} ({}). The server may have been reinstalled, or the connection may be intercepted.",
                path.display(),
                known_algorithms.join(", ")
            ));
        }
        // A host a certificate authority vouches for is listed, so accept_new_host_key does not
        // apply to it; host certificates are not checked here, so its key cannot be verified.
        if applicable
            .iter()
            .any(|entry| matches!(entry.marker(), Some(Marker::CertAuthority)))
        {
            return Verdict::Refused(format!(
                "{} trusts a certificate authority for {name}, and host certificates are not checked here, so the key cannot be verified. Check the fingerprint below another way and pass it as host_key_fingerprint.",
                path.display()
            ));
        }
        if self.accept_new {
            return Verdict::Accepted(Verification::AcceptedNew {
                known_hosts_file: Some(path.to_path_buf()),
            });
        }
        let unreadable = if unreadable_lines > 0 {
            format!(" ({unreadable_lines} lines of it could not be read)")
        } else {
            String::new()
        };
        Verdict::Refused(format!(
            "{name} is not in {}{unreadable}. Pass accept_new_host_key to accept a host that is not listed.",
            path.display()
        ))
    }
}

/// Parse known_hosts text, skipping lines that are not valid entries the way OpenSSH does, and
/// counting them so a refusal can say the file was only partly read.
fn parse_known_hosts(text: &str) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut unreadable_lines = 0;
    for entry in KnownHosts::new(text) {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(_) => unreadable_lines += 1,
        }
    }
    (entries, unreadable_lines)
}

/// The name a host is recorded under in known_hosts: the hostname for port 22, `[host]:port`
/// otherwise, lowercased as OpenSSH records it.
fn lookup_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

/// Whether an entry's host patterns cover `name`: a hashed name must hash to the same value, and
/// a pattern list must have a pattern matching it and no negated (`!`) pattern matching it.
fn patterns_match(patterns: &HostPatterns, name: &str) -> bool {
    match patterns {
        HostPatterns::HashedName { salt, hash } => {
            let Ok(hmac) = Hmac::<Sha1>::new_from_slice(salt) else {
                return false;
            };
            hmac.chain_update(name.as_bytes())
                .verify_slice(hash)
                .is_ok()
        }
        HostPatterns::Patterns(patterns) => {
            let mut matched = false;
            for pattern in patterns {
                let pattern = pattern.to_ascii_lowercase();
                if let Some(negated) = pattern.strip_prefix('!') {
                    if wildcard_match(negated, name) {
                        return false;
                    }
                } else if wildcard_match(&pattern, name) {
                    matched = true;
                }
            }
            matched
        }
    }
}

/// Match `text` against a pattern where `*` matches any run of characters and `?` any one.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pattern_index, mut text_index) = (0usize, 0usize);
    let mut backtrack: Option<(usize, usize)> = None;
    while text_index < text.len() {
        match pattern.get(pattern_index) {
            Some('*') => {
                backtrack = Some((pattern_index, text_index));
                pattern_index += 1;
            }
            Some(&character) if character == '?' || Some(&character) == text.get(text_index) => {
                pattern_index += 1;
                text_index += 1;
            }
            _ => match backtrack {
                Some((star, matched_until)) => {
                    pattern_index = star + 1;
                    text_index = matched_until + 1;
                    backtrack = Some((star, matched_until + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(pattern_index..)
        .is_some_and(|rest| rest.iter().all(|character| *character == '*'))
}

/// What a connect reports about the key the server presented.
#[derive(Clone, Debug)]
pub(crate) struct HostKeyReport {
    algorithm: String,
    fingerprint: String,
    known_hosts_line: String,
}

impl HostKeyReport {
    /// Describe `key` as presented by `host:port`.
    pub(crate) fn new(host: &str, port: u16, key: &PublicKey) -> Self {
        let mut bare = key.clone();
        bare.set_comment("");
        let key_text = bare
            .to_openssh()
            .unwrap_or_else(|_| key.algorithm().to_string());
        Self {
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            known_hosts_line: format!("{} {key_text}", lookup_name(host, port)),
        }
    }

    /// The lines a result shows for the host key.
    pub(crate) fn describe(&self) -> String {
        format!(
            "Host key: {} {}\nknown_hosts line: {}",
            self.algorithm, self.fingerprint, self.known_hosts_line
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_private_key;

    fn random_key() -> PublicKey {
        random_private_key().public_key().clone()
    }

    fn openssh(key: &PublicKey) -> String {
        key.to_openssh().unwrap()
    }

    fn policy_with_file(text: &str, accept_new: bool) -> HostKeyPolicy {
        let (entries, unreadable_lines) = parse_known_hosts(text);
        HostKeyPolicy {
            source: Source::KnownHosts {
                path: PathBuf::from("/known_hosts"),
                entries,
                unreadable_lines,
            },
            accept_new,
        }
    }

    #[test]
    fn a_listed_key_is_verified() {
        let key = random_key();
        let policy = policy_with_file(&format!("example.com {}\n", openssh(&key)), false);
        assert_eq!(
            policy.verify("example.com", 22, &key),
            Verdict::Accepted(Verification::KnownHosts(PathBuf::from("/known_hosts")))
        );
    }

    #[test]
    fn a_changed_key_is_refused_even_with_accept_new() {
        let listed = random_key();
        let presented = random_key();
        let policy = policy_with_file(&format!("example.com {}\n", openssh(&listed)), true);
        assert!(matches!(
            policy.verify("example.com", 22, &presented),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn an_unlisted_host_is_refused_without_accept_new_and_accepted_with_it() {
        let key = random_key();
        let file = format!("other.example {}\n", openssh(&random_key()));
        assert!(matches!(
            policy_with_file(&file, false).verify("example.com", 22, &key),
            Verdict::Refused(_)
        ));
        assert!(matches!(
            policy_with_file(&file, true).verify("example.com", 22, &key),
            Verdict::Accepted(Verification::AcceptedNew { .. })
        ));
    }

    #[test]
    fn a_non_default_port_is_looked_up_in_brackets() {
        let key = random_key();
        let policy = policy_with_file(&format!("[example.com]:2222 {}\n", openssh(&key)), false);
        assert!(matches!(
            policy.verify("example.com", 2222, &key),
            Verdict::Accepted(_)
        ));
        assert!(matches!(
            policy.verify("example.com", 22, &key),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn wildcards_and_negations_follow_openssh() {
        let key = random_key();
        let policy = policy_with_file(
            &format!("*.example.com,!secret.example.com {}\n", openssh(&key)),
            false,
        );
        assert!(matches!(
            policy.verify("web.example.com", 22, &key),
            Verdict::Accepted(_)
        ));
        assert!(matches!(
            policy.verify("secret.example.com", 22, &key),
            Verdict::Refused(_)
        ));
        assert!(matches!(
            policy.verify("example.com", 22, &key),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn a_hashed_host_name_matches() {
        let key = random_key();
        // `ssh-keygen -H` hashes the name with HMAC-SHA1 under a random salt.
        let salt = [7u8; 20];
        let hash = Hmac::<Sha1>::new_from_slice(&salt)
            .unwrap()
            .chain_update(b"example.com")
            .finalize()
            .into_bytes();
        let line = format!("|1|{}|{} {}\n", base64(&salt), base64(&hash), openssh(&key));
        let policy = policy_with_file(&line, false);
        assert!(matches!(
            policy.verify("example.com", 22, &key),
            Verdict::Accepted(_)
        ));
        assert!(matches!(
            policy.verify("other.com", 22, &key),
            Verdict::Refused(_)
        ));
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let block = [
                chunk.first().copied().unwrap_or(0),
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let value =
                (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(char::from(
                        ALPHABET[((value >> (18 - 6 * index)) & 63) as usize],
                    ));
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    #[test]
    fn a_revoked_key_is_refused_even_when_also_listed() {
        let key = random_key();
        let listed = format!("example.com {}\n", openssh(&key));
        let revoked = format!("@revoked * {}\n", openssh(&key));
        for file in [format!("{revoked}{listed}"), format!("{listed}{revoked}")] {
            assert!(
                matches!(
                    policy_with_file(&file, true).verify("example.com", 22, &key),
                    Verdict::Refused(reason) if reason.contains("@revoked")
                ),
                "{file}"
            );
        }
    }

    #[test]
    fn a_missing_known_hosts_file_is_an_error_not_an_empty_file() {
        let result = HostKeyPolicy::from_arguments(
            Vec::new(),
            Some(PathBuf::from("/nonexistent/ssh-mcp/known_hosts")),
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn fingerprints_and_public_key_lines_both_verify() {
        let key = random_key();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let by_fingerprint = HostKeyPolicy::from_arguments(vec![fingerprint], None, false).unwrap();
        assert_eq!(
            by_fingerprint.verify("h", 22, &key),
            Verdict::Accepted(Verification::Fingerprint)
        );
        let by_line =
            HostKeyPolicy::from_arguments(vec![format!("{} comment", openssh(&key))], None, false)
                .unwrap();
        assert_eq!(
            by_line.verify("h", 22, &key),
            Verdict::Accepted(Verification::Fingerprint)
        );
        assert!(matches!(
            by_fingerprint.verify("h", 22, &random_key()),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn contradictory_arguments_are_refused_before_connecting() {
        let fingerprint = random_key().fingerprint(HashAlg::Sha256).to_string();
        assert!(HostKeyPolicy::from_arguments(vec![fingerprint.clone()], None, true).is_err());
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("known_hosts");
        std::fs::write(&file, "").unwrap();
        let combined =
            HostKeyPolicy::from_arguments(vec![fingerprint], Some(file), false).unwrap_err();
        assert!(
            combined.message().contains("cannot be combined"),
            "{combined}"
        );
        assert!(HostKeyPolicy::from_arguments(vec!["MD5:aa:bb".to_owned()], None, false).is_err());
    }

    #[test]
    fn a_host_under_a_certificate_authority_is_refused_even_with_accept_new() {
        let key = random_key();
        let file = format!("@cert-authority *.example.com {}\n", openssh(&random_key()));
        assert!(matches!(
            policy_with_file(&file, true).verify("web.example.com", 22, &key),
            Verdict::Refused(reason) if reason.contains("certificate authority")
        ));
        assert!(matches!(
            policy_with_file(&file, true).verify("other.org", 22, &key),
            Verdict::Accepted(Verification::AcceptedNew { .. })
        ));
    }

    #[test]
    fn no_check_refuses_unless_accept_new() {
        let key = random_key();
        let strict = HostKeyPolicy::from_arguments(Vec::new(), None, false).unwrap();
        assert!(matches!(strict.verify("h", 22, &key), Verdict::Refused(_)));
        let accepting = HostKeyPolicy::from_arguments(Vec::new(), None, true).unwrap();
        assert!(matches!(
            accepting.verify("h", 22, &key),
            Verdict::Accepted(Verification::AcceptedNew {
                known_hosts_file: None
            })
        ));
    }

    #[test]
    fn wildcard_matching_backtracks() {
        assert!(wildcard_match("*.example.com", "a.b.example.com"));
        assert!(wildcard_match("host?", "host1"));
        assert!(!wildcard_match("host?", "host12"));
        assert!(wildcard_match("*a*b", "xxaxxb"));
        assert!(!wildcard_match("*a*b", "xxaxxbc"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn the_report_carries_a_ready_known_hosts_line() {
        let key = random_key();
        let report = HostKeyReport::new("Example.COM", 2222, &key);
        assert!(
            report
                .known_hosts_line
                .starts_with("[example.com]:2222 ssh-ed25519 ")
        );
        assert_eq!(
            report.fingerprint,
            key.fingerprint(HashAlg::Sha256).to_string()
        );
    }
}
