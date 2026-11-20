use std::{error::Error, io, time::Duration};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ghost_core::{
    command::{self, Command},
    identity::{self, Identity, IdentityError, IdentityStore},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use zeroize::Zeroizing;

#[derive(Default)]
struct App {
    input: String,
    lines: Vec<String>,
    should_quit: bool,
    identity_label: String,
}

impl App {
    fn new(username: &str) -> Self {
        let mut app = Self {
            identity_label: username.to_owned(),
            ..Self::default()
        };
        app.lines.push(format!(
            "Welcome, {username}. Your local identity is ready."
        ));
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
                "Commands: /help /whoami /peers /scan /connect <ip:port>".into(),
                "          /disconnect <peer> /msg <peer> <text> /open <peer>".into(),
                "          /history [peer|group] /relay status|enable|disable".into(),
                "          /clear /quit".into(),
                "Network, identity, storage, and relay services are not implemented yet.".into(),
            ]),
            Ok(Command::Clear) => self.lines.clear(),
            Ok(Command::Quit) => self.should_quit = true,
            Ok(_) => self
                .lines
                .push("This command is recognized, but its service is not implemented yet.".into()),
            Err(error) => self.lines.push(format!("Error: {error}")),
        }
    }
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
    let mut app = App::new(identity.username());

    while !app.should_quit {
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

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " GHOST ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  LOCAL CONSOLE  ·  NETWORK OFFLINE  ·  RELAY DISABLED"),
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

    frame.render_widget(
        Paragraph::new(format!(
            "Identity: {}  |  Peers: none  |  Ctrl-C: quit",
            app.identity_label
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
