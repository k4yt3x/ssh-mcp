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
    if !std::fs::metadata(path).map_err(failure)?.is_file() {
        return Err(ToolError::new(format!(
            "{argument} {} is not a regular file.",
            path.display()
        )));
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(failure)?
        .take(max_bytes + 1)
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

/// Resolve a local path argument, which must be absolute, `~`, or start with `~/` or `~\`.
///
/// Relative paths are refused because this server's working directory is wherever the harness
/// started it, which is not the directory the agent is working in.
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
            "{argument} must be an absolute path or start with ~/ (got \"{input}\")"
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
