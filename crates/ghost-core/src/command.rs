//! Command parsing for the terminal interface.

use std::net::SocketAddr;

/// A parsed user action. Message text is kept as a single value after the command arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    WhoAmI,
    Peers,
    Verify { peer: String, fingerprint: String },
    Block(String),
    Unblock(String),
    Scan,
    Listen(SocketAddr),
    Connect(SocketAddr),
    Ping(SocketAddr),
    Disconnect(SocketAddr),
    Message { peer: String, text: String },
    Open(String),
    History(Option<String>),
    RelayStatus,
    RelaySetEnabled(bool),
    Clear,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError(pub String);

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CommandError {}

/// Parse a slash-prefixed command. Quoted arguments support spaces and backslash escaping.
pub fn parse(input: &str) -> Result<Command, CommandError> {
    let input = input.trim();
    if !input.starts_with('/') {
        return Err(CommandError(
            "Messages must use /msg <peer> <text> for now.".into(),
        ));
    }

    let words = tokenize(&input[1..])?;
    let Some(name) = words.first().map(String::as_str) else {
        return Err(CommandError("Enter a command. Try /help.".into()));
    };
    let args = &words[1..];

    if name == "relay" {
        return match args {
            [arg] if arg == "status" => Ok(Command::RelayStatus),
            [arg] if arg == "enable" => Ok(Command::RelaySetEnabled(true)),
            [arg] if arg == "disable" => Ok(Command::RelaySetEnabled(false)),
            _ => Err(CommandError("Usage: /relay status|enable|disable".into())),
        };
    }

    match (name, args) {
        ("help", []) => Ok(Command::Help),
        ("whoami", []) => Ok(Command::WhoAmI),
        ("peers", []) => Ok(Command::Peers),
        ("verify", [peer, fingerprint]) => Ok(Command::Verify {
            peer: peer.clone(),
            fingerprint: fingerprint.clone(),
        }),
        ("block", [peer]) => Ok(Command::Block(peer.clone())),
        ("unblock", [peer]) => Ok(Command::Unblock(peer.clone())),
        ("scan", []) => Ok(Command::Scan),
        ("listen", [address]) => address
            .parse()
            .map(Command::Listen)
            .map_err(|_| CommandError("Usage: /listen <ip:port>".into())),
        ("connect", [address]) => address
            .parse()
            .map(Command::Connect)
            .map_err(|_| CommandError("Usage: /connect <ip:port>".into())),
        ("ping", [address]) => address
            .parse()
            .map(Command::Ping)
            .map_err(|_| CommandError("Usage: /ping <ip:port>".into())),
        ("disconnect", [address]) => address
            .parse()
            .map(Command::Disconnect)
            .map_err(|_| CommandError("Usage: /disconnect <ip:port>".into())),
        ("msg", [peer, rest @ ..]) if !rest.is_empty() => Ok(Command::Message {
            peer: peer.clone(),
            text: rest.join(" "),
        }),
        ("open", [peer]) => Ok(Command::Open(peer.clone())),
        ("history", []) => Ok(Command::History(None)),
        ("history", [conversation]) => Ok(Command::History(Some(conversation.clone()))),
        ("clear", []) => Ok(Command::Clear),
        ("quit", []) => Ok(Command::Quit),
        ("group", _) => Err(CommandError(
            "Group commands are planned but not implemented yet.".into(),
        )),
        _ => Err(CommandError(
            "Unknown command or invalid arguments. Try /help.".into(),
        )),
    }
}

fn tokenize(input: &str) -> Result<Vec<String>, CommandError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;

    for ch in input.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            started = true;
        } else if ch == '\\' {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                word.push(ch);
            }
            started = true;
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            started = true;
        } else if ch.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(ch);
            started = true;
        }
    }

    if escaped {
        word.push('\\');
    }
    if quote.is_some() {
        return Err(CommandError("Unclosed quote in command.".into()));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trust_commands() {
        assert_eq!(
            parse("/verify ada 0123456789abcdef").unwrap(),
            Command::Verify {
                peer: "ada".into(),
                fingerprint: "0123456789abcdef".into(),
            }
        );
        assert_eq!(parse("/block ada").unwrap(), Command::Block("ada".into()));
        assert_eq!(
            parse("/unblock ada").unwrap(),
            Command::Unblock("ada".into())
        );
        assert!(parse("/verify ada").is_err());
    }

    #[test]
    fn parses_transport_commands() {
        assert_eq!(
            parse("/listen 127.0.0.1:9000").unwrap(),
            Command::Listen("127.0.0.1:9000".parse().unwrap())
        );
        assert_eq!(
            parse("/ping 127.0.0.1:9001").unwrap(),
            Command::Ping("127.0.0.1:9001".parse().unwrap())
        );
        assert!(parse("/listen nope").is_err());
    }
}
