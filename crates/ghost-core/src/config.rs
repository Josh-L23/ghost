//! Local configuration with safe defaults and validation.

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::{fsutil, identity, protocol::read_bounded};

const MAX_FILE_BYTES: usize = 16 * 1024;
pub const MAX_CONNECTIONS_CEILING: usize = 8;
pub const MAX_COMMAND_QUEUE_CEILING: usize = 128;
pub const MAX_EVENT_QUEUE_CEILING: usize = 128;
pub const MAX_WRITE_QUEUE_CEILING: usize = 16;
pub const MAX_HISTORY_MESSAGES_CEILING: usize = 10_000;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
    Invalid(String),
    DataDirectoryUnavailable,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "config storage error: {error}"),
            Self::Parse(error) => write!(f, "config file is malformed: {error}"),
            Self::Invalid(error) => write!(f, "invalid configuration: {error}"),
            Self::DataDirectoryUnavailable => {
                f.write_str("could not determine the local data directory")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub username: String,
    pub listen_addr: String,
    pub history_enabled: bool,
    pub relay_enabled: bool,
    pub limits: Limits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_connections: usize,
    pub max_command_queue: usize,
    pub max_event_queue: usize,
    pub max_write_queue: usize,
    pub max_history_messages: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            max_command_queue: 128,
            max_event_queue: 128,
            max_write_queue: 16,
            max_history_messages: 200,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            username: "ghost".to_owned(),
            listen_addr: "127.0.0.1:0".to_owned(),
            history_enabled: true,
            relay_enabled: false,
            limits: Limits::default(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !identity::is_valid_username(&self.username) {
            return Err(ConfigError::Invalid(
                "username must be 1-64 printable characters without slashes or surrounding whitespace".into(),
            ));
        }
        self.listen_socket_addr()?;
        self.limits.validate()?;
        Ok(())
    }

    pub fn listen_socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen_addr.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid(
                "listen_addr must be a valid socket address like 127.0.0.1:7000 or 127.0.0.1:0"
                    .into(),
            )
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = read_bounded(path.as_ref(), MAX_FILE_BYTES)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ConfigError::Parse("file must be valid UTF-8 text".into()))?;
        let config: Config =
            toml::from_str(&text).map_err(|error| ConfigError::Parse(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        let config = Self::default();
        config.validate()?;
        config.save(path)?;
        Ok(config)
    }

    pub fn load_or_safe_default(
        path: impl AsRef<Path>,
    ) -> Result<(Self, Option<PathBuf>), ConfigError> {
        let path = path.as_ref();
        match Self::load_or_create(path) {
            Ok(config) => Ok((config, None)),
            Err(error) => {
                let quarantined = fsutil::quarantine(path, &error.to_string())?;
                let fallback = Self::default();
                fallback.save(path)?;
                Ok((fallback, Some(quarantined)))
            }
        }
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        self.validate()?;
        let path = path.as_ref();
        let text = toml::to_string_pretty(self)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        fsutil::atomic_write(path, text.as_bytes(), 0o600, true)?;
        Ok(())
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "limits.max_connections",
            self.max_connections,
            1,
            MAX_CONNECTIONS_CEILING,
        )?;
        check_range(
            "limits.max_command_queue",
            self.max_command_queue,
            1,
            MAX_COMMAND_QUEUE_CEILING,
        )?;
        check_range(
            "limits.max_event_queue",
            self.max_event_queue,
            1,
            MAX_EVENT_QUEUE_CEILING,
        )?;
        check_range(
            "limits.max_write_queue",
            self.max_write_queue,
            1,
            MAX_WRITE_QUEUE_CEILING,
        )?;
        check_range(
            "limits.max_history_messages",
            self.max_history_messages,
            0,
            MAX_HISTORY_MESSAGES_CEILING,
        )?;
        Ok(())
    }
}

fn check_range(name: &str, value: usize, min: usize, max: usize) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::Invalid(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(())
}

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    identity::default_data_dir()
        .map(|dir| dir.join("config.toml"))
        .map_err(|_| ConfigError::DataDirectoryUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn defaults_are_valid_and_parseable() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(
            config.listen_socket_addr().unwrap(),
            "127.0.0.1:0".parse().unwrap()
        );
        assert!(config.history_enabled);
        assert!(!config.relay_enabled);
    }

    #[test]
    fn missing_config_is_created_with_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(!path.exists());

        let config = Config::load_or_create(&path).unwrap();
        assert_eq!(config, Config::default());
        assert!(path.exists());

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded, Config::default());
    }

    #[test]
    fn malformed_config_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "username = [not valid").unwrap();

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::Parse(_)));
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn corrupt_config_is_quarantined_and_defaults_are_restored() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "username = [not valid").unwrap();

        let (config, quarantined) = Config::load_or_safe_default(&path).unwrap();
        assert_eq!(config, Config::default());
        let quarantined = quarantined.expect("expected quarantine path");
        assert!(quarantined.exists());
        assert!(quarantined.to_string_lossy().contains("corrupt"));
        assert_eq!(Config::load(&path).unwrap(), Config::default());
    }

    #[test]
    fn invalid_values_are_rejected_with_actionable_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        fs::write(
            &path,
            r#"
username = "ghost"
listen_addr = "not-an-address"
history_enabled = true
relay_enabled = false
"#,
        )
        .unwrap();
        let error = Config::load(&path).unwrap_err();
        assert!(error.to_string().contains("listen_addr"));

        let config = Config {
            username: " bad ".into(),
            ..Default::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("username")
        );

        let config = Config {
            limits: Limits {
                max_connections: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("max_connections")
        );

        let config = Config {
            limits: Limits {
                max_history_messages: 10_001,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("max_history_messages")
        );

        let config = Config {
            limits: Limits {
                max_connections: 65,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn oversized_config_file_is_rejected_before_parsing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();

        let error = Config::load(&path).unwrap_err();
        assert!(error.to_string().contains("maximum allowed size"));
    }

    #[test]
    fn reload_reads_updated_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::load_or_create(&path).unwrap();
        config.listen_addr = "127.0.0.1:7777".into();
        config.history_enabled = false;
        config.relay_enabled = true;
        config.limits.max_connections = 4;
        config.save(&path).unwrap();

        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.listen_addr, "127.0.0.1:7777");
        assert!(!reloaded.history_enabled);
        assert!(reloaded.relay_enabled);
        assert_eq!(reloaded.limits.max_connections, 4);
    }

    #[test]
    fn config_has_no_secret_fields() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        let lower = text.to_lowercase();
        assert!(!lower.contains("password"));
        assert!(!lower.contains("passphrase"));
        assert!(!lower.contains("private"));
        assert!(!lower.contains("secret"));
        assert!(!lower.contains("session_key"));
        assert!(!lower.contains("plaintext"));
    }
}
