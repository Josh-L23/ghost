use std::{
    collections::HashMap,
    error::Error,
    io,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ghost_core::{
    command::{self, Command},
    dedup::ReplayCache,
    delivery::{self, DeliveryState, PendingQueue, TrackedMessage},
    identity::{self, Identity, IdentityError, IdentityStore},
    messaging::{self, PrivateMessage},
    protocol::{IdentityId, MessageType},
    session::{self, EstablishedSession, PendingSession},
    trust::{self, TrustRecord, TrustStore},
};
use ghost_network::{ConnectionState, TransportCommand, TransportEvent, TransportHandle};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use zeroize::Zeroizing;

const RECEIPT_TIMEOUT_SECS: u64 = 60;

struct App {
    input: String,
    lines: Vec<String>,
    should_quit: bool,
    identity_label: String,
    fingerprint_short: String,
    fingerprint_full: String,
    trust: TrustStore,
    identity: Identity,
    transport: TransportHandle,
    connections: Vec<(SocketAddr, ConnectionState)>,
    listen_addr: Option<SocketAddr>,
    handshakes: HashMap<SocketAddr, PendingSession>,
    sessions: HashMap<SocketAddr, EstablishedSession>,
    conversations: HashMap<String, Vec<TrackedMessage>>,
    deliveries: PendingQueue,
    dedup: ReplayCache,
}

impl App {
    fn new(identity: Identity, trust: TrustStore, transport: TransportHandle) -> Self {
        let fingerprint = identity.fingerprint();
        let username = identity.username().to_owned();
        let mut app = Self {
            input: String::new(),
            lines: Vec::new(),
            should_quit: false,
            identity_label: identity.username().to_owned(),
            fingerprint_short: fingerprint.short(),
            fingerprint_full: fingerprint.full(),
            trust,
            identity,
            transport,
            connections: Vec::new(),
            listen_addr: None,
            handshakes: HashMap::new(),
            sessions: HashMap::new(),
            conversations: HashMap::new(),
            deliveries: PendingQueue::new(),
            dedup: ReplayCache::new(),
        };
        app.lines.push(format!(
            "Welcome, {username}. Your local identity is ready."
        ));
        app.lines.push(
            "Unverified peers are never trusted automatically; compare fingerprints out-of-band."
                .into(),
        );
        app.lines
            .push("Type /help for available commands. Use /quit or Ctrl-C to exit.".into());
        app
    }

    fn handle_input(&mut self) {
        let input = std::mem::take(&mut self.input);
        if input.trim().is_empty() {
            return;
        }
        self.lines.push(format!("› {input}"));
        match command::parse(&input) {
            Ok(Command::Help) => self.lines.extend([
                "Commands: /help /whoami /peers /verify <peer> <fingerprint>".into(),
                "          /block <peer> /unblock <peer> /scan /listen <ip:port>".into(),
                "          /connect <ip:port> /disconnect <ip:port> /ping <ip:port>".into(),
                "          /msg <peer> <text> /open <peer> /history [peer|group]".into(),
                "          /relay status|enable|disable /clear /quit".into(),
                "/whoami shows your username and identity fingerprint.".into(),
                "Peers may be selected by label, short fingerprint, or full fingerprint.".into(),
                "TCP is manual-only; sessions require verified peer fingerprints.".into(),
                "Delivery indicators are text; a transport write is not a receipt.".into(),
                "Message history is in-memory only; storage and relay services are not implemented yet.".into(),
            ]),
            Ok(Command::WhoAmI) => {
                self.lines
                    .push(format!("Username: {}", self.identity_label));
                self.lines
                    .push(format!("Fingerprint: {}", self.fingerprint_short));
                self.lines
                    .push(format!("Full:        {}", self.fingerprint_full));
                self.lines
                    .push("Compare the fingerprint out-of-band before trusting a peer.".into());
            }
            Ok(Command::Peers) => {
                self.lines.push(format!(
                    "Listener: {}",
                    self.listen_addr
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "starting".into())
                ));
                if self.connections.is_empty() {
                    self.lines.push("Connections: none".into());
                } else {
                    self.lines.push("Connections:".into());
                    for (peer, state) in &self.connections {
                        let session = if self.sessions.contains_key(peer) {
                            "verified session"
                        } else if self.handshakes.contains_key(peer) {
                            "handshaking"
                        } else {
                            "no session"
                        };
                        self.lines.push(format!("  [{state:?}] {peer} — {session}"));
                    }
                }
                if self.trust.records().is_empty() {
                    self.lines
                        .push("No known peers. Connect to a peer to learn its identity.".into());
                } else {
                    self.lines
                        .push("Known peers (status is text, not colour-dependent):".into());
                    for record in self.trust.records() {
                        self.lines.push(describe_record(record));
                    }
                }
            }
            Ok(Command::Verify { peer, fingerprint }) => {
                match self.trust.verify(&peer, &fingerprint, now()) {
                    Ok(record) => self.lines.push(format!(
                        "[VERIFIED] {} ({}) is trusted for direct sessions.",
                        record.label(),
                        record.short_fingerprint()
                    )),
                    Err(error) => self.lines.push(format!("Verification failed: {error}")),
                }
            }
            Ok(Command::Block(peer)) => match self.trust.block(&peer, now()) {
                Ok(record) => self.lines.push(format!(
                    "[BLOCKED] {} ({}) will not be trusted.",
                    record.label(),
                    record.short_fingerprint()
                )),
                Err(error) => self.lines.push(format!("Block failed: {error}")),
            },
            Ok(Command::Unblock(peer)) => match self.trust.unblock(&peer, now()) {
                Ok(record) => self.lines.push(format!(
                    "[UNVERIFIED] {} ({}) can now be verified.",
                    record.label(),
                    record.short_fingerprint()
                )),
                Err(error) => self.lines.push(format!("Unblock failed: {error}")),
            },
            Ok(Command::Listen(address)) => {
                self.send_command(TransportCommand::Listen(address));
                self.lines
                    .push(format!("Requesting listener on {address}."));
            }
            Ok(Command::Connect(address)) => {
                self.set_connection_state(address, ConnectionState::Connecting);
                self.send_command(TransportCommand::Connect(address));
                self.lines.push(format!("Connecting to {address}."));
            }
            Ok(Command::Disconnect(address)) => {
                self.send_command(TransportCommand::Disconnect(address));
                self.set_connection_state(address, ConnectionState::Disconnected);
                self.lines.push(format!("Closing connection to {address}."));
            }
            Ok(Command::Ping(address)) => {
                let plaintext = format!("PING from {}", self.identity_label);
                let framed = self.sessions.get_mut(&address).and_then(|session| {
                    session
                        .encrypt(&self.identity, plaintext.as_bytes(), now())
                        .ok()
                });
                match framed {
                    Some(frame) => {
                        self.send_command(TransportCommand::Send {
                            peer: address,
                            frame,
                        });
                        self.lines
                            .push(format!("Encrypted probe queued for {address}."));
                    }
                    None => self.lines.push(format!(
                        "No established session with {address}. Verify the peer fingerprint first."
                    )),
                }
            }
            Ok(Command::Message { peer, text }) => {
                let Some(address) = self.resolve_peer_address(&peer) else {
                    self.lines.push(format!("No session for peer '{peer}'."));
                    return;
                };
                let recipient = match self.sessions.get(&address) {
                    Some(session) => session.peer_id(),
                    None => {
                        self.lines.push(format!("No session for peer '{peer}'."));
                        return;
                    }
                };
                let result = self.sessions.get_mut(&address).map(|session| {
                    messaging::compose(session, &self.identity, recipient, &text, now())
                });
                match result {
                    Some(Ok((message, frame))) => {
                        let message_id = message.message_id;
                        let label = self.peer_label(&message.recipient);
                        let queued = self
                            .deliveries
                            .insert(message.clone(), now() + RECEIPT_TIMEOUT_SECS)
                            .is_ok();
                        self.record_message(message, DeliveryState::Queued);
                        if !queued {
                            self.set_message_state(&message_id, DeliveryState::Failed);
                            self.lines.push(format!(
                                "Message failed: {}",
                                delivery::DeliveryError::QueueFull
                            ));
                            return;
                        }
                        let sent = self.send_command(TransportCommand::Send {
                            peer: address,
                            frame,
                        });
                        let state = if sent {
                            DeliveryState::Sent
                        } else {
                            DeliveryState::Failed
                        };
                        let _ = self.deliveries.set_state(&message_id, state);
                        self.set_message_state(&message_id, state);
                        self.lines.push(format!(
                            "[MSG] to {label}: {text} [{}]",
                            state.label()
                        ));
                    }
                    Some(Err(error)) => self.lines.push(format!("Message failed: {error}")),
                    None => self.lines.push(format!("No session for peer '{peer}'.")),
                }
            }
            Ok(Command::Open(peer)) => {
                let key = self.resolve_conversation_key(&peer);
                let messages = self.conversations.get(&key).cloned().unwrap_or_default();
                if messages.is_empty() {
                    self.lines
                        .push(format!("No messages yet with '{peer}'."));
                } else {
                    self.lines.push(format!("Conversation with '{peer}':"));
                    for tracked in messages {
                        let direction = if tracked.message.sender == self.identity.identity_id() {
                            "out"
                        } else {
                            "in"
                        };
                        let label = self.peer_label(&tracked.message.sender);
                        self.lines.push(format!(
                            "  [{direction}] {label}: {} [{}]",
                            tracked.message.text,
                            tracked.state.label()
                        ));
                    }
                }
            }
            Ok(Command::Clear) => self.lines.clear(),
            Ok(Command::Quit) => self.should_quit = true,
            Ok(_) => self
                .lines
                .push("This command is recognized, but its service is not implemented yet.".into()),
            Err(error) => self.lines.push(format!("Error: {error}")),
        }
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.transport.try_event() {
            match event {
                TransportEvent::Listening(address) => {
                    self.listen_addr = Some(address);
                    self.lines.push(format!(
                        "[LISTENING] Accepting manual connections on {address}."
                    ));
                }
                TransportEvent::Incoming(peer) => {
                    self.set_connection_state(peer, ConnectionState::Connected);
                    self.lines.push(format!("[INCOMING] {peer} connected."));
                    self.start_handshake(peer);
                }
                TransportEvent::Connected(peer) => {
                    self.set_connection_state(peer, ConnectionState::Connected);
                    self.lines.push(format!("[CONNECTED] {peer}"));
                    self.start_handshake(peer);
                }
                TransportEvent::Disconnected(peer, reason) => {
                    self.set_connection_state(peer, ConnectionState::Disconnected);
                    self.handshakes.remove(&peer);
                    self.sessions.remove(&peer);
                    self.lines.push(format!("[DISCONNECTED] {peer}: {reason}"));
                }
                TransportEvent::Frame { peer, frame } => self.handle_session_frame(peer, frame),
                TransportEvent::Error { peer, message } => {
                    let peer = peer.map(|peer| peer.to_string()).unwrap_or_default();
                    self.lines.push(format!("[NETWORK] {peer} {message}"));
                }
            }
        }
    }

    fn start_handshake(&mut self, peer: SocketAddr) {
        if self.sessions.contains_key(&peer) || self.handshakes.contains_key(&peer) {
            return;
        }
        match session::initiate(&self.identity) {
            Ok((pending, hello)) => {
                self.send_command(TransportCommand::Send { peer, frame: hello });
                self.handshakes.insert(peer, pending);
                self.lines
                    .push(format!("[SESSION] Authentication started with {peer}."));
            }
            Err(error) => self
                .lines
                .push(format!("[SESSION] Could not start authentication: {error}")),
        }
    }

    fn handle_session_frame(&mut self, peer: SocketAddr, frame: Vec<u8>) {
        if let Some(pending) = self.handshakes.remove(&peer) {
            match pending.complete(&self.identity, &mut self.trust, &frame, now()) {
                Ok(session) => {
                    self.lines.push(format!(
                        "[SESSION] Verified {} ({}) with fingerprint {}.",
                        session.peer_label(),
                        session.peer_id(),
                        session::fingerprint_of(&session.peer_id())
                    ));
                    self.sessions.insert(peer, session);
                }
                Err(error) => {
                    self.lines
                        .push(format!("[SESSION] Refused {peer}: {error}"));
                    self.send_command(TransportCommand::Disconnect(peer));
                }
            }
            return;
        }

        let decrypted = match self.sessions.get_mut(&peer) {
            Some(session) => session.decrypt(&frame, now()),
            None => {
                self.lines.push(format!(
                    "[SESSION] Unexpected frame from {peer} before authentication."
                ));
                return;
            }
        };
        let decrypted = match decrypted {
            Ok(frame) => match self.dedup.accept(
                frame.message_id,
                frame.sender,
                frame.message_type,
                frame.created_at,
                now(),
            ) {
                Ok(()) => Ok(frame),
                Err(error) => {
                    self.lines
                        .push(format!("[SESSION] Ignored replayed frame: {error}"));
                    return;
                }
            },
            Err(error) => Err(error),
        };
        match decrypted {
            Ok(decrypted) if decrypted.message_type == MessageType::CONTROL => {
                let plaintext = String::from_utf8_lossy(&decrypted.plaintext);
                self.lines.push(format!("[PING] {peer}: {plaintext}"));
            }
            Ok(decrypted) if decrypted.message_type == MessageType::RECEIPT => {
                let opened = match self.sessions.get(&peer) {
                    Some(session) => messaging::open_receipt_frame(session, decrypted),
                    None => return,
                };
                match opened {
                    Ok(receipt) => match self.deliveries.acknowledge(&receipt.acknowledged) {
                        Ok(tracked) => {
                            self.set_message_state(
                                &receipt.acknowledged,
                                DeliveryState::Acknowledged,
                            );
                            let label = self.peer_label(&tracked.message.recipient);
                            self.lines.push(format!(
                                "[STATE] {label} message acknowledged [{}]",
                                DeliveryState::Acknowledged.label()
                            ));
                        }
                        Err(_) => self.lines.push("[STATE] Ignored unknown receipt.".into()),
                    },
                    Err(error) => self
                        .lines
                        .push(format!("[STATE] Rejected receipt: {error}")),
                }
            }
            Ok(decrypted) => {
                let opened = match self.sessions.get(&peer) {
                    Some(session) => messaging::open_frame(session, decrypted),
                    None => return,
                };
                match opened {
                    Ok(message) => {
                        let label = self.peer_label(&message.sender);
                        let message_id = message.message_id;
                        self.lines.push(format!("[MSG] {label}: {}", message.text));
                        self.record_message(message, DeliveryState::Received);
                        let receipt = self.sessions.get_mut(&peer).map(|session| {
                            messaging::compose_receipt(session, &self.identity, message_id, now())
                        });
                        match receipt {
                            Some(Ok((_, frame))) => {
                                let _ = self.send_command(TransportCommand::Send { peer, frame });
                            }
                            Some(Err(error)) => {
                                self.lines.push(format!("[STATE] Receipt failed: {error}"))
                            }
                            None => {}
                        }
                    }
                    Err(error) => self.lines.push(format!("[MSG] Rejected frame: {error}")),
                }
            }
            Err(error) => self
                .lines
                .push(format!("[SESSION] Rejected frame from {peer}: {error}")),
        }
    }

    fn resolve_peer_address(&self, selector: &str) -> Option<SocketAddr> {
        if let Ok(address) = selector.parse::<SocketAddr>() {
            return self.sessions.contains_key(&address).then_some(address);
        }
        self.sessions.iter().find_map(|(address, session)| {
            let id = session.peer_id();
            let full = identity::fingerprint_from_public_key(&id.0).full();
            let matches = session.peer_label() == selector
                || session::fingerprint_of(&id) == selector
                || full == selector
                || id.to_string() == selector;
            matches.then_some(*address)
        })
    }

    fn resolve_conversation_key(&self, selector: &str) -> String {
        if let Some(address) = self.resolve_peer_address(selector) {
            if let Some(session) = self.sessions.get(&address) {
                return session.peer_id().to_string();
            }
        }
        if let Some(record) = self.trust.records().iter().find(|record| {
            let full = identity::fingerprint_from_public_key(&record.identity_id.0).full();
            record.label() == selector
                || record.short_fingerprint() == selector
                || full == selector
                || record.identity_id.to_string() == selector
        }) {
            return record.identity_id.to_string();
        }
        selector.to_owned()
    }

    fn peer_label(&self, id: &IdentityId) -> String {
        for session in self.sessions.values() {
            if session.peer_id() == *id {
                return session.peer_label().to_owned();
            }
        }
        for record in self.trust.records() {
            if record.identity_id == *id {
                return record.label().to_owned();
            }
        }
        session::fingerprint_of(id)
    }

    fn record_message(&mut self, message: PrivateMessage, state: DeliveryState) {
        let counterparty = if message.sender == self.identity.identity_id() {
            message.recipient
        } else {
            message.sender
        };
        let history = self
            .conversations
            .entry(counterparty.to_string())
            .or_default();
        if history
            .iter()
            .any(|item| item.message.message_id == message.message_id)
        {
            return;
        }
        history.push(TrackedMessage {
            message,
            state,
            expires_at: now() + RECEIPT_TIMEOUT_SECS,
        });
        if history.len() > 200 {
            history.remove(0);
        }
    }

    fn set_message_state(
        &mut self,
        message_id: &ghost_core::protocol::MessageId,
        state: DeliveryState,
    ) {
        for history in self.conversations.values_mut() {
            if let Some(item) = history
                .iter_mut()
                .find(|item| item.message.message_id == *message_id)
            {
                item.state = state;
                return;
            }
        }
    }

    fn expire_pending(&mut self, now: u64) {
        let expired = self.deliveries.expire(now);
        for message_id in expired {
            self.set_message_state(&message_id, DeliveryState::Expired);
            self.lines.push(format!(
                "[STATE] Message expired [{}]",
                DeliveryState::Expired.label()
            ));
        }
    }

    fn set_connection_state(&mut self, peer: SocketAddr, state: ConnectionState) {
        if let Some(entry) = self
            .connections
            .iter_mut()
            .find(|(address, _)| *address == peer)
        {
            entry.1 = state;
        } else {
            self.connections.push((peer, state));
        }
    }

    fn send_command(&mut self, command: TransportCommand) -> bool {
        match self.transport.command(command) {
            Ok(()) => true,
            Err(error) => {
                self.lines.push(format!("Transport error: {error}"));
                false
            }
        }
    }
}

fn describe_record(record: &TrustRecord) -> String {
    let note = match record.state {
        trust::TrustState::Unverified => " claimed name; verify before trusting",
        trust::TrustState::Verified => " verified out-of-band",
        trust::TrustState::Blocked => " revoked; will not be trusted",
    };
    format!(
        "[{}] {} fp={} id={} —{}",
        record.state.label(),
        record.label(),
        record.short_fingerprint(),
        record.identity_id,
        note
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result?;
    Ok(())
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), Box<dyn Error>> {
    let identity = setup_identity(terminal)?;
    let trust = TrustStore::load_or_empty(trust::default_trust_path()?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = runtime.enter();
    let transport = ghost_network::start(ghost_network::default_listen_addr())?;
    let mut app = App::new(identity, trust, transport);

    while !app.should_quit {
        app.drain_events();
        app.expire_pending(now());
        terminal.draw(|frame| draw(frame, &app))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match (key.code, key.modifiers) {
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Esc, _) => {
                        app.should_quit = true
                    }
                    (KeyCode::Enter, _) => app.handle_input(),
                    (KeyCode::Backspace, _) => {
                        app.input.pop();
                    }
                    (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                        app.input.push(ch)
                    }
                    _ => {}
                }
            }
        }
    }
    app.transport.shutdown();
    Ok(())
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let listener = app
        .listen_addr
        .map(|address| format!("LISTENING {address}"))
        .unwrap_or_else(|| "LISTENER STARTING".into());
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " GHOST ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  LOCAL CONSOLE  ·  {listener}  ·  RELAY DISABLED")),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(header, areas[0]);

    let body: Vec<Line<'_>> = app
        .lines
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect();
    let timeline = Paragraph::new(body)
        .block(Block::default().title(" Activity ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(timeline, areas[1]);

    let input = Paragraph::new(format!("› {}", app.input))
        .block(Block::default().title(" Command ").borders(Borders::ALL));
    frame.render_widget(input, areas[2]);

    let verified = app
        .trust
        .records()
        .iter()
        .filter(|record| record.state == trust::TrustState::Verified)
        .count();
    let connected = app
        .connections
        .iter()
        .filter(|(_, state)| *state == ConnectionState::Connected)
        .count();
    frame.render_widget(
        Paragraph::new(format!(
            "Identity: {} ({})  |  Links: {} ({} sessions)  |  Peers: {} ({} verified)  |  Ctrl-C: quit",
            app.identity_label,
            app.fingerprint_short,
            connected,
            app.sessions.len(),
            app.trust.records().len(),
            verified
        )),
        areas[3],
    );
}

type AppTerminal = Terminal<CrosstermBackend<io::Stdout>>;

fn setup_identity(terminal: &mut AppTerminal) -> Result<Identity, Box<dyn Error>> {
    let store = IdentityStore::new(identity::default_identity_path()?);
    if store.exists() {
        return unlock_identity(terminal, &store);
    }

    let mut notice = "First launch: create a local identity.".to_owned();
    loop {
        let username = prompt(terminal, "Username", &notice, false)?;
        if !identity::is_valid_username(&username) {
            notice = "Username must be 1-64 printable characters without slashes.".into();
            continue;
        }

        let passphrase = Zeroizing::new(prompt(
            terminal,
            "Passphrase",
            "At least 8 characters. It is never displayed or logged.",
            true,
        )?);
        if !identity::is_valid_passphrase(passphrase.as_bytes()) {
            notice = "Passphrase must be at least 8 characters.".into();
            continue;
        }

        let confirmation = Zeroizing::new(prompt(terminal, "Repeat passphrase", &notice, true)?);
        if passphrase.as_str() != confirmation.as_str() {
            notice = "Passphrases did not match. Try again.".into();
            continue;
        }

        match store.create(&username, passphrase.as_bytes()) {
            Ok(created) => return Ok(created),
            Err(IdentityError::AlreadyExists) => return unlock_identity(terminal, &store),
            Err(error) => notice = format!("Could not create identity: {error}"),
        }
    }
}

fn unlock_identity(
    terminal: &mut AppTerminal,
    store: &IdentityStore,
) -> Result<Identity, Box<dyn Error>> {
    let mut notice = "Unlock your local identity.".to_owned();
    loop {
        let passphrase = Zeroizing::new(prompt(terminal, "Passphrase", &notice, true)?);
        match store.load(passphrase.as_bytes()) {
            Ok(identity) => return Ok(identity),
            Err(IdentityError::WrongPassphrase) => {
                notice = "Incorrect passphrase. Try again or press Esc to cancel.".into();
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
}

fn prompt(
    terminal: &mut AppTerminal,
    title: &str,
    notice: &str,
    secret: bool,
) -> io::Result<String> {
    let mut input = String::new();
    loop {
        terminal.draw(|frame| draw_prompt(frame, title, notice, &input, secret))?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Esc, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "identity setup cancelled",
                ));
            }
            (KeyCode::Enter, _) if !input.is_empty() => return Ok(input),
            (KeyCode::Backspace, _) => {
                input.pop();
            }
            (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => input.push(ch),
            _ => {}
        }
    }
}

fn draw_prompt(
    frame: &mut ratatui::Frame<'_>,
    title: &str,
    notice: &str,
    input: &str,
    secret: bool,
) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new(" GHOST · LOCAL IDENTITY ")
            .style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::BOTTOM)),
        areas[0],
    );
    frame.render_widget(
        Paragraph::new(notice)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().title(" Notice ").borders(Borders::ALL)),
        areas[1],
    );

    let shown = if secret {
        "*".repeat(input.chars().count())
    } else {
        input.to_owned()
    };
    frame.render_widget(
        Paragraph::new(format!("› {shown}")).block(
            Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL),
        ),
        areas[2],
    );
    frame.render_widget(
        Paragraph::new("Enter to continue · Ctrl-C or Esc to cancel"),
        areas[3],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_core::{
        protocol::{BoundedBytes, IdentityId},
        trust::TrustState,
    };

    #[test]
    fn trust_descriptions_are_textual() {
        let record = TrustRecord {
            identity_id: IdentityId([1; 32]),
            label: BoundedBytes::new(b"ada".to_vec()).unwrap(),
            state: TrustState::Unverified,
            created_at: 1,
            updated_at: 1,
            last_seen: 1,
        };
        let description = describe_record(&record);
        assert!(description.contains("[UNVERIFIED]"));
        assert!(description.contains("verify before trusting"));
    }
}
