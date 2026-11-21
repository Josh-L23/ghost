//! Bounded, transport-neutral connection adapters.

pub mod discovery;

use ghost_core::protocol::{FRAME_HEADER_LEN, MAX_ENVELOPE_BYTES, MAX_FRAME_BYTES};
use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{
        Mutex, OwnedSemaphorePermit, Semaphore,
        mpsc::{self, error::TrySendError},
    },
    task::JoinHandle,
    time::timeout,
};

pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_QUEUED_EVENTS: usize = 128;
pub const MAX_QUEUED_COMMANDS: usize = 128;
pub const MAX_WRITE_QUEUE: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_BURST: u32 = 64;
const FRAME_REFILL_PER_SEC: u64 = 32;
const RATE_MAP_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkLimits {
    pub max_connections: usize,
    pub max_command_queue: usize,
    pub max_event_queue: usize,
    pub max_write_queue: usize,
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_command_queue: MAX_QUEUED_COMMANDS,
            max_event_queue: MAX_QUEUED_EVENTS,
            max_write_queue: MAX_WRITE_QUEUE,
        }
    }
}

impl NetworkLimits {
    fn clamp(self) -> Self {
        Self {
            max_connections: self.max_connections.clamp(1, MAX_CONNECTIONS),
            max_command_queue: self.max_command_queue.clamp(1, MAX_QUEUED_COMMANDS),
            max_event_queue: self.max_event_queue.clamp(1, MAX_QUEUED_EVENTS),
            max_write_queue: self.max_write_queue.clamp(1, MAX_WRITE_QUEUE),
        }
    }
}

#[derive(Debug)]
pub enum NetworkError {
    Io(std::io::Error),
    Timeout,
    FrameTooLarge(usize),
    CommandQueueClosed,
    CommandQueueFull,
    TooManyConnections,
    AlreadyConnected(SocketAddr),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "transport I/O error: {error}"),
            Self::Timeout => f.write_str("transport operation timed out"),
            Self::FrameTooLarge(length) => {
                write!(f, "frame payload of {length} bytes is too large")
            }
            Self::CommandQueueClosed => f.write_str("transport has stopped"),
            Self::CommandQueueFull => f.write_str("transport command queue is full"),
            Self::TooManyConnections => write!(f, "connection limit of {MAX_CONNECTIONS} reached"),
            Self::AlreadyConnected(peer) => write!(f, "already connected to {peer}"),
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<std::io::Error> for NetworkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TrySendError<TransportCommand>> for NetworkError {
    fn from(error: TrySendError<TransportCommand>) -> Self {
        match error {
            TrySendError::Full(_) => Self::CommandQueueFull,
            TrySendError::Closed(_) => Self::CommandQueueClosed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportCommand {
    Listen(SocketAddr),
    Connect(SocketAddr),
    Disconnect(SocketAddr),
    Send { peer: SocketAddr, frame: Vec<u8> },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    Listening(SocketAddr),
    Incoming(SocketAddr),
    Connected(SocketAddr),
    Disconnected(SocketAddr, String),
    Frame {
        peer: SocketAddr,
        frame: Vec<u8>,
    },
    Error {
        peer: Option<SocketAddr>,
        message: String,
    },
}

pub struct TransportHandle {
    commands: mpsc::Sender<TransportCommand>,
    events: mpsc::Receiver<TransportEvent>,
    task: Option<JoinHandle<()>>,
}

impl TransportHandle {
    pub fn command(&self, command: TransportCommand) -> Result<(), NetworkError> {
        self.commands.try_send(command).map_err(Into::into)
    }

    pub fn try_event(&mut self) -> Option<TransportEvent> {
        self.events.try_recv().ok()
    }

    pub fn shutdown(&mut self) {
        let _ = self.commands.try_send(TransportCommand::Shutdown);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn start(listen: SocketAddr) -> Result<TransportHandle, NetworkError> {
    start_with_limits(listen, NetworkLimits::default())
}

pub fn start_with_limits(
    listen: SocketAddr,
    limits: NetworkLimits,
) -> Result<TransportHandle, NetworkError> {
    let limits = limits.clamp();
    let (command_tx, command_rx) = mpsc::channel(limits.max_command_queue);
    let (event_tx, event_rx) = mpsc::channel(limits.max_event_queue);
    let task = tokio::spawn(driver(listen, command_rx, event_tx, limits));
    Ok(TransportHandle {
        commands: command_tx,
        events: event_rx,
        task: Some(task),
    })
}

pub fn default_listen_addr() -> SocketAddr {
    std::env::var("GHOST_LISTEN")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:0".parse().expect("valid default address"))
}

type Writers = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

#[derive(Debug)]
struct TokenBucket {
    tokens: u32,
    updated: Instant,
}

#[derive(Debug, Default)]
struct FrameRateLimiter {
    buckets: Mutex<HashMap<SocketAddr, TokenBucket>>,
}

impl FrameRateLimiter {
    async fn allow(&self, peer: SocketAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        if !buckets.contains_key(&peer) && buckets.len() >= RATE_MAP_LIMIT {
            buckets.clear();
        }
        let bucket = buckets.entry(peer).or_insert_with(|| TokenBucket {
            tokens: FRAME_BURST,
            updated: now,
        });
        let elapsed_ms = now.saturating_duration_since(bucket.updated).as_millis() as u64;
        let refill = elapsed_ms * FRAME_REFILL_PER_SEC / 1_000;
        bucket.tokens = bucket
            .tokens
            .saturating_add(refill.min(FRAME_BURST as u64) as u32)
            .min(FRAME_BURST);
        bucket.updated = now;
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

async fn driver(
    listen: SocketAddr,
    mut commands: mpsc::Receiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
    limits: NetworkLimits,
) {
    let limits = limits.clamp();
    let writers: Writers = Arc::new(Mutex::new(HashMap::new()));
    let limiter = Arc::new(FrameRateLimiter::default());
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut listener: Option<JoinHandle<()>> = None;
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    start_listener(
        listen,
        &events,
        &writers,
        &permits,
        limits.max_write_queue,
        &mut listener,
    );

    while let Some(command) = commands.recv().await {
        match command {
            TransportCommand::Listen(address) => {
                start_listener(
                    address,
                    &events,
                    &writers,
                    &permits,
                    limits.max_write_queue,
                    &mut listener,
                );
            }
            TransportCommand::Connect(peer) => {
                let event_tx = events.clone();
                let writers = writers.clone();
                let permits = permits.clone();
                let limiter = limiter.clone();
                let write_queue = limits.max_write_queue;
                tasks.push(tokio::spawn(async move {
                    if let Err(error) = connect(
                        peer,
                        event_tx.clone(),
                        writers,
                        permits,
                        limiter,
                        write_queue,
                    )
                    .await
                    {
                        emit_error(&event_tx, peer, error);
                    }
                }));
            }
            TransportCommand::Disconnect(peer) => {
                let writer = writers.lock().await.remove(&peer);
                if let Some(writer) = writer {
                    drop(writer);
                    emit(
                        &events,
                        TransportEvent::Disconnected(peer, "closed by local user".into()),
                    );
                }
            }
            TransportCommand::Send { peer, frame } => {
                if frame.len() > MAX_FRAME_BYTES {
                    emit(
                        &events,
                        TransportEvent::Error {
                            peer: Some(peer),
                            message: "frame exceeds maximum allowed size".into(),
                        },
                    );
                    continue;
                }
                let writer = writers.lock().await.get(&peer).cloned();
                match writer {
                    Some(writer) => {
                        if writer.try_send(frame).is_err() {
                            emit(
                                &events,
                                TransportEvent::Error {
                                    peer: Some(peer),
                                    message: "peer write queue is full or closed".into(),
                                },
                            );
                        }
                    }
                    None => emit(
                        &events,
                        TransportEvent::Error {
                            peer: Some(peer),
                            message: "not connected to peer".into(),
                        },
                    ),
                }
            }
            TransportCommand::Shutdown => break,
        }
    }

    if let Some(listener) = listener.take() {
        listener.abort();
    }
    for task in tasks.drain(..) {
        task.abort();
    }
}

fn start_listener(
    listen: SocketAddr,
    events: &mpsc::Sender<TransportEvent>,
    writers: &Writers,
    permits: &Arc<Semaphore>,
    write_queue: usize,
    listener: &mut Option<JoinHandle<()>>,
) {
    if let Some(old) = listener.take() {
        old.abort();
    }
    let event_tx = events.clone();
    let writers = writers.clone();
    let permits = permits.clone();
    let limiter = Arc::new(FrameRateLimiter::default());
    *listener = Some(tokio::spawn(async move {
        let bound = match TcpListener::bind(listen).await {
            Ok(bound) => bound,
            Err(error) => {
                emit(
                    &event_tx,
                    TransportEvent::Error {
                        peer: None,
                        message: format!("could not listen on {listen}: {error}"),
                    },
                );
                return;
            }
        };
        let local = match bound.local_addr() {
            Ok(local) => local,
            Err(error) => {
                emit(
                    &event_tx,
                    TransportEvent::Error {
                        peer: None,
                        message: format!("could not read listener address: {error}"),
                    },
                );
                return;
            }
        };
        emit(&event_tx, TransportEvent::Listening(local));

        loop {
            let (stream, peer) = match bound.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    emit(
                        &event_tx,
                        TransportEvent::Error {
                            peer: None,
                            message: format!("accept failed: {error}"),
                        },
                    );
                    continue;
                }
            };
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    emit(
                        &event_tx,
                        TransportEvent::Error {
                            peer: Some(peer),
                            message: "connection refused: limit reached".into(),
                        },
                    );
                    drop(stream);
                    continue;
                }
            };
            if writers.lock().await.contains_key(&peer) {
                emit(
                    &event_tx,
                    TransportEvent::Error {
                        peer: Some(peer),
                        message: "already connected to peer".into(),
                    },
                );
                continue;
            }
            emit(&event_tx, TransportEvent::Incoming(peer));
            register_connection(
                stream,
                peer,
                permit,
                event_tx.clone(),
                writers.clone(),
                limiter.clone(),
                write_queue,
            )
            .await;
        }
    }));
}

async fn connect(
    peer: SocketAddr,
    event_tx: mpsc::Sender<TransportEvent>,
    writers: Writers,
    permits: Arc<Semaphore>,
    limiter: Arc<FrameRateLimiter>,
    write_queue: usize,
) -> Result<(), NetworkError> {
    let permit = permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| NetworkError::TooManyConnections)?;
    if writers.lock().await.contains_key(&peer) {
        return Err(NetworkError::AlreadyConnected(peer));
    }
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer))
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(NetworkError::Io)?;
    register_connection(
        stream,
        peer,
        permit,
        event_tx,
        writers,
        limiter,
        write_queue,
    )
    .await;
    Ok(())
}

async fn register_connection(
    stream: TcpStream,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
    event_tx: mpsc::Sender<TransportEvent>,
    writers: Writers,
    limiter: Arc<FrameRateLimiter>,
    write_queue: usize,
) {
    let (writer_tx, writer_rx) = mpsc::channel(write_queue);
    {
        let mut writers = writers.lock().await;
        writers.insert(peer, writer_tx);
    }
    emit(&event_tx, TransportEvent::Connected(peer));

    let (reader, writer) = stream.into_split();
    let writer_events = event_tx.clone();
    let writer_writers = writers.clone();
    tokio::spawn(async move {
        let _permit = permit;
        writer_loop(writer, peer, writer_rx, &writer_events, &writer_writers).await;
    });

    tokio::spawn(async move {
        reader_loop(reader, peer, &event_tx, &writers, &limiter).await;
    });
}

async fn reader_loop(
    mut stream: OwnedReadHalf,
    peer: SocketAddr,
    events: &mpsc::Sender<TransportEvent>,
    writers: &Writers,
    limiter: &FrameRateLimiter,
) {
    loop {
        if !limiter.allow(peer).await {
            emit(
                events,
                TransportEvent::Error {
                    peer: Some(peer),
                    message: "frame rate limit exceeded".into(),
                },
            );
            cleanup(peer, "frame rate limit exceeded".into(), events, writers).await;
            return;
        }
        match timeout(IO_TIMEOUT, read_frame(&mut stream)).await {
            Ok(Ok(frame)) => emit(events, TransportEvent::Frame { peer, frame }),
            Ok(Err(error)) => {
                cleanup(peer, format!("read failed: {error}"), events, writers).await;
                return;
            }
            Err(_) => {
                cleanup(peer, "read timed out".into(), events, writers).await;
                return;
            }
        }
    }
}

async fn writer_loop(
    mut stream: OwnedWriteHalf,
    peer: SocketAddr,
    mut frames: mpsc::Receiver<Vec<u8>>,
    events: &mpsc::Sender<TransportEvent>,
    writers: &Writers,
) {
    while let Some(frame) = frames.recv().await {
        match timeout(IO_TIMEOUT, stream.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                cleanup(peer, format!("write failed: {error}"), events, writers).await;
                return;
            }
            Err(_) => {
                cleanup(peer, "write timed out".into(), events, writers).await;
                return;
            }
        }
    }
    cleanup(peer, "write queue closed".into(), events, writers).await;
}

async fn cleanup(
    peer: SocketAddr,
    reason: String,
    events: &mpsc::Sender<TransportEvent>,
    writers: &Writers,
) {
    if writers.lock().await.remove(&peer).is_some() {
        emit(events, TransportEvent::Disconnected(peer, reason));
    }
}

fn emit(events: &mpsc::Sender<TransportEvent>, event: TransportEvent) {
    let _ = events.try_send(event);
}

fn emit_error(events: &mpsc::Sender<TransportEvent>, peer: SocketAddr, error: NetworkError) {
    emit(
        events,
        TransportEvent::Error {
            peer: Some(peer),
            message: error.to_string(),
        },
    );
}

async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>, NetworkError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    timeout(IO_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(NetworkError::Io)?;

    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_ENVELOPE_BYTES {
        return Err(NetworkError::FrameTooLarge(length));
    }

    let mut payload = vec![0u8; length];
    timeout(IO_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(NetworkError::Io)?;

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + length);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn next_event(handle: &mut TransportHandle) -> TransportEvent {
        loop {
            if let Some(event) = handle.try_event() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn wait_for<F>(handle: &mut TransportHandle, predicate: F) -> TransportEvent
    where
        F: Fn(&TransportEvent) -> bool,
    {
        timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event(handle).await;
                if predicate(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("expected transport event")
    }

    #[tokio::test]
    async fn two_nodes_exchange_framed_bytes() {
        let mut alice = start("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut bob = start("127.0.0.1:0".parse().unwrap()).unwrap();

        let TransportEvent::Listening(bob_addr) = wait_for(&mut bob, |event| {
            matches!(event, TransportEvent::Listening(_))
        })
        .await
        else {
            panic!("expected listener");
        };

        alice.command(TransportCommand::Connect(bob_addr)).unwrap();
        let TransportEvent::Incoming(alice_addr) = wait_for(&mut bob, |event| {
            matches!(event, TransportEvent::Incoming(_))
        })
        .await
        else {
            panic!("expected incoming connection");
        };

        let frame = vec![0, 0, 0, 3, 1, 2, 3];
        alice
            .command(TransportCommand::Send {
                peer: bob_addr,
                frame: frame.clone(),
            })
            .unwrap();
        let TransportEvent::Frame {
            frame: received, ..
        } = wait_for(&mut bob, |event| {
            matches!(event, TransportEvent::Frame { .. })
        })
        .await
        else {
            panic!("expected frame");
        };
        assert_eq!(received, frame);

        bob.command(TransportCommand::Send {
            peer: alice_addr,
            frame: vec![0, 0, 0, 3, 4, 5, 6],
        })
        .unwrap();
        let TransportEvent::Frame { frame: reply, .. } = wait_for(&mut alice, |event| {
            matches!(event, TransportEvent::Frame { .. })
        })
        .await
        else {
            panic!("expected reply");
        };
        assert_eq!(reply, vec![0, 0, 0, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_is_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let oversized = (MAX_ENVELOPE_BYTES + 1) as u32;
        client.write_all(&oversized.to_be_bytes()).await.unwrap();

        let result = timeout(Duration::from_secs(5), read_frame(&mut server))
            .await
            .unwrap();
        assert!(matches!(result, Err(NetworkError::FrameTooLarge(_))));
    }

    #[test]
    fn limits_are_clamped_to_safe_ceilings() {
        let limits = NetworkLimits {
            max_connections: 1_000,
            max_command_queue: 0,
            max_event_queue: 4,
            max_write_queue: 500,
        }
        .clamp();
        assert_eq!(limits.max_connections, MAX_CONNECTIONS);
        assert_eq!(limits.max_command_queue, 1);
        assert_eq!(limits.max_event_queue, 4);
        assert_eq!(limits.max_write_queue, MAX_WRITE_QUEUE);
    }

    #[tokio::test]
    async fn frame_rate_limiter_bounds_bursts_and_refills() {
        let limiter = FrameRateLimiter::default();
        let peer: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        for _ in 0..FRAME_BURST {
            assert!(limiter.allow(peer).await);
        }
        assert!(!limiter.allow(peer).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(limiter.allow(peer).await);
    }

    #[tokio::test]
    async fn oversized_outbound_frame_is_rejected() {
        let mut handle = start("127.0.0.1:0".parse().unwrap()).unwrap();
        handle
            .command(TransportCommand::Send {
                peer: "127.0.0.1:7000".parse().unwrap(),
                frame: vec![0; MAX_FRAME_BYTES + 1],
            })
            .unwrap();
        let event = wait_for(&mut handle, |event| {
            matches!(
                event,
                TransportEvent::Error { message, .. }
                    if message == "frame exceeds maximum allowed size"
            )
        })
        .await;
        assert!(matches!(event, TransportEvent::Error { .. }));
    }

    #[tokio::test]
    async fn empty_frame_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        let result = timeout(Duration::from_secs(5), read_frame(&mut server))
            .await
            .unwrap();
        assert!(matches!(result, Err(NetworkError::FrameTooLarge(0))));
    }
}
