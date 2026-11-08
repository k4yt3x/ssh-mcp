//! Local paths a tool argument names: key files, known_hosts files and transfer endpoints.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use crate::output::{ToolError, format_size};

/// Read a small text file a tool argument names, such as a key or a known_hosts file. Anything that
/// is not a regular file (a device, a FIFO, this process's stdin) is refused, and so is a file
/// larger than `max_bytes`, so a mistaken path cannot exhaust memory or block on input.
pub(crate) fn read_small_file(
    argument: &str,
    path: &Path,
    max_bytes: u64,
) -> Result<String, ToolError> {
    let failure = |error: std::io::Error| {
        ToolError::new(format!(
            "{argument} {} could not be read: {error}",
            path.display()
        ))
    };
    let file = open_regular_file(path, true)
        .map_err(failure)?
        .ok_or_else(|| {
            ToolError::new(format!(
                "{argument} {} is not a regular file.",
                path.display()
            ))
        })?;
    let mut text = String::new();
    file.take(max_bytes + 1)
        .read_to_string(&mut text)
        .map_err(failure)?;
    if text.len() as u64 > max_bytes {
        return Err(ToolError::new(format!(
            "{argument} {} is larger than {}.",
            path.display(),
            format_size(max_bytes)
        )));
    }
    Ok(text)
}

/// Open a local file to read, or return `None` when it is not a regular file (a folder, a device,
/// a FIFO, a socket, or a symlink when `follow_symlink` is false). The type is checked again on
/// the opened file, so a file replaced by something else after the first check is still refused,
/// and the open does not wait for a FIFO's writer.
pub(crate) fn open_regular_file(
    path: &Path,
    follow_symlink: bool,
) -> std::io::Result<Option<std::fs::File>> {
    // Checked before the open as well, because opening some devices has effects of its own.
    let metadata = if follow_symlink {
        std::fs::metadata(path)?
    } else {
        std::fs::symlink_metadata(path)?
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        if follow_symlink {
            libc::O_NONBLOCK
        } else {
            libc::O_NONBLOCK | libc::O_NOFOLLOW
        },
    );
    let file = match options.open(path) {
        #[cfg(unix)]
        Err(error) if !follow_symlink && error.raw_os_error() == Some(libc::ELOOP) => {
            return Ok(None);
        }
        opened => opened?,
    };
    Ok(file.metadata()?.is_file().then_some(file))
}

/// Resolve a local path argument, which must be absolute, `~`, or start with `~/` or `~\`.
///
/// Relative paths are refused because this server's working directory is wherever the harness
/// started it, which is not the directory the agent is working in. The refusal does not quote the
/// argument, which may be a private key passed in the wrong argument.
pub(crate) fn resolve_local_path(argument: &str, input: &str) -> Result<PathBuf, ToolError> {
    if input == "~" || input.starts_with("~/") || input.starts_with("~\\") {
        let home = std::env::home_dir().ok_or_else(|| {
            ToolError::new(format!(
                "{argument}: the home directory of this machine could not be determined; use an absolute path"
            ))
        })?;
        let rest = input.get(2..).unwrap_or("");
        return Ok(if rest.is_empty() {
            home
        } else {
            home.join(rest)
        });
    }
    let path = PathBuf::from(input);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(ToolError::new(format!(
            "{argument} must be an absolute path or start with ~/."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_is_refused() {
        assert!(resolve_local_path("local_path", "keys/id").is_err());
        assert!(resolve_local_path("local_path", "./id").is_err());
    }

    #[test]
    fn a_refused_path_is_not_quoted_back() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA";
        let refused = resolve_local_path("private_key_file", key).unwrap_err();
        assert!(
            !refused.message().contains("b3BlbnNzaC"),
            "{}",
            refused.message()
        );
    }

    #[test]
    fn a_tilde_path_resolves_under_home() {
        let Some(home) = std::env::home_dir() else {
            return;
        };
        assert_eq!(
            resolve_local_path("local_path", "~/a/b").unwrap(),
            home.join("a/b")
        );
        assert_eq!(resolve_local_path("local_path", "~").unwrap(), home);
    }
}
