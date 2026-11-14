//! Fail-closed secret value and file path resolution helpers (`AGENTS.md` §3).

use alloc::string::{String, ToString};
use std::path::Path;

/// Reads and trims a secret from `path`, failing closed (`None`) on any I/O error,
/// non-regular file, or empty/whitespace-only contents.
///
/// Never falls back to returning `path` as the secret token.
#[must_use]
pub fn resolve_secret_file(path: impl AsRef<Path>) -> Option<String> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() || !path.is_file() {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Resolves a secret specification that may contain either a literal secret or a file path.
///
/// Any string looking like a filesystem path (starting with `/`, `./`, `../`, `~/`, or
/// containing `/` or `\`) is resolved strictly as a file path and fails closed (`None`) if
/// the file is missing, unreadable, or empty.
#[must_use]
pub fn resolve_secret_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let is_path = trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("~/")
        || trimmed.contains('/')
        || trimmed.contains('\\');
    if is_path {
        resolve_secret_file(trimmed)
    } else {
        Some(trimmed.to_string())
    }
}

/// Resolves a secret from `env_var` via [`resolve_secret_value`].
#[must_use]
pub fn resolve_secret_env(env_var: &str) -> Option<String> {
    let raw = std::env::var(env_var).ok()?;
    resolve_secret_value(&raw)
}

/// Resolves a secret configured via either `file_env_var` (strict path) or `env_var`.
///
/// When `file_env_var` is present and non-empty, it takes precedence and fails closed (`None`)
/// without falling back to `env_var` if the referenced file cannot be read.
#[must_use]
pub fn resolve_secret_with_file_var(env_var: &str, file_env_var: &str) -> Option<String> {
    if let Ok(file_val) = std::env::var(file_env_var) {
        let trimmed = file_val.trim();
        if !trimmed.is_empty() {
            return resolve_secret_file(trimmed);
        }
    }
    resolve_secret_env(env_var)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_literal_and_fails_closed_on_missing_path() {
        assert_eq!(
            resolve_secret_value("  plain-token-123 \n"),
            Some("plain-token-123".to_string())
        );
        assert_eq!(resolve_secret_value("   "), None);
        assert_eq!(
            resolve_secret_value("/nonexistent/path/to/secret.txt"),
            None
        );
        assert_eq!(resolve_secret_value("./missing/secret.txt"), None);
        assert_eq!(resolve_secret_file(""), None);
    }

    #[cfg(not(miri))]
    #[test]
    fn reads_and_trims_secret_file_and_fails_closed_when_empty() {
        use alloc::format;
        let dir = std::env::temp_dir().join(format!("mu-auth-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let valid = dir.join("proxy.secret");
        let empty = dir.join("empty.secret");
        std::fs::write(&valid, "  edge-secret-value\n").unwrap();
        std::fs::write(&empty, "  \n  ").unwrap();

        assert_eq!(
            resolve_secret_file(&valid),
            Some("edge-secret-value".to_string())
        );
        assert_eq!(
            resolve_secret_value(valid.to_str().unwrap()),
            Some("edge-secret-value".to_string())
        );
        assert_eq!(resolve_secret_file(&empty), None);

        let _ = std::fs::remove_file(&valid);
        let _ = std::fs::remove_file(&empty);
        let _ = std::fs::remove_dir(&dir);
    }
}
