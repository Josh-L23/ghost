//! Optional local peer discovery using mDNS/DNS-SD.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const SERVICE_TYPE: &str = "_ghost._tcp.local.";
pub const MAX_DISCOVERED_PEERS: usize = 32;
pub const PEER_TTL: Duration = Duration::from_secs(90);

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_LABEL_CHARS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub addr: SocketAddr,
    pub label: String,
    seen_at: Instant,
}

impl DiscoveredPeer {
    pub fn new(addr: SocketAddr, label: String, seen_at: Instant) -> Self {
        Self {
            addr,
            label,
            seen_at,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.seen_at) >= PEER_TTL
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryEvent {
    Found(DiscoveredPeer),
    Gone(SocketAddr),
    Expired(SocketAddr),
    ScanComplete(Vec<DiscoveredPeer>),
    Error(String),
}

#[derive(Debug)]
pub struct DiscoveryError(String);

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DiscoveryError {}

enum DiscoveryCommand {
    Advertise(u16),
    Scan,
    Shutdown,
}

pub struct DiscoveryHandle {
    commands: Sender<DiscoveryCommand>,
    events: Receiver<DiscoveryEvent>,
    worker: Option<JoinHandle<()>>,
}

impl DiscoveryHandle {
    pub fn advertise(&self, port: u16) {
        let _ = self.commands.send(DiscoveryCommand::Advertise(port));
    }

    pub fn scan(&self) {
        let _ = self.commands.send(DiscoveryCommand::Scan);
    }

    pub fn try_event(&self) -> Option<DiscoveryEvent> {
        self.events.try_recv().ok()
    }

    pub fn shutdown(&mut self) {
        let _ = self.commands.send(DiscoveryCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for DiscoveryHandle {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.shutdown();
        }
    }
}

pub fn start(label: String) -> DiscoveryHandle {
    let (command_tx, command_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        run(label, command_rx, event_tx);
    });
    DiscoveryHandle {
        commands: command_tx,
        events: event_rx,
        worker: Some(worker),
    }
}

fn run(label: String, commands: Receiver<DiscoveryCommand>, events: Sender<DiscoveryEvent>) {
    let daemon = match ServiceDaemon::new() {
        Ok(daemon) => daemon,
        Err(error) => {
            let _ = events.send(DiscoveryEvent::Error(format!(
                "mDNS could not start: {error}. Manual connection is still available."
            )));
            return;
        }
    };
    let browse = match daemon.browse(SERVICE_TYPE) {
        Ok(browse) => browse,
        Err(error) => {
            let _ = events.send(DiscoveryEvent::Error(format!(
                "mDNS browse failed: {error}. Manual connection is still available."
            )));
            let _ = daemon.shutdown();
            return;
        }
    };

    let mut cache = PeerCache::default();
    let mut self_name = format!("ghost-{}-{}.{}", std::process::id(), 0, SERVICE_TYPE);
    let mut advertised: Option<(String, u16)> = None;

    loop {
        match commands.recv_timeout(POLL_INTERVAL) {
            Ok(DiscoveryCommand::Advertise(port)) => {
                if advertised
                    .as_ref()
                    .is_some_and(|(_, current)| *current == port)
                {
                    continue;
                }
                if let Some((old_name, _)) = advertised.take() {
                    let _ = daemon.unregister(&old_name);
                }
                let instance = format!("ghost-{}-{}", std::process::id(), port);
                let fullname = format!("{instance}.{SERVICE_TYPE}");
                let properties = [("name", sanitize_label(&label)), ("v", "1".to_owned())];
                let info = ServiceInfo::new(
                    SERVICE_TYPE,
                    &instance,
                    "ghost.local.",
                    (),
                    port,
                    &properties[..],
                )
                .map(|info| info.enable_addr_auto());
                match info {
                    Ok(info) => match daemon.register(info) {
                        Ok(()) => {
                            self_name = fullname.clone();
                            advertised = Some((fullname, port));
                        }
                        Err(error) => {
                            let _ = events.send(DiscoveryEvent::Error(format!(
                                "mDNS announcement failed: {error}. Manual connection is still available."
                            )));
                        }
                    },
                    Err(error) => {
                        let _ = events.send(DiscoveryEvent::Error(format!(
                            "mDNS announcement is invalid: {error}. Manual connection is still available."
                        )));
                    }
                }
            }
            Ok(DiscoveryCommand::Scan) => {
                let _ = events.send(DiscoveryEvent::ScanComplete(cache.list()));
            }
            Ok(DiscoveryCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }

        while let Ok(event) = browse.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(service) => {
                    if service.fullname == self_name {
                        continue;
                    }
                    let Some(address) = service.get_addresses_v4().iter().copied().min() else {
                        continue;
                    };
                    let fallback = mdns_sd::instance_name_unescaped(&service.fullname);
                    let label = service
                        .get_property_val_str("name")
                        .map(sanitize_label)
                        .unwrap_or_else(|| sanitize_label(&fallback));
                    let peer = DiscoveredPeer::new(
                        SocketAddr::new(IpAddr::V4(address), service.port),
                        label,
                        Instant::now(),
                    );
                    cache.insert(service.fullname.clone(), peer.clone());
                    let _ = events.send(DiscoveryEvent::Found(peer));
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    if let Some(addr) = cache.remove(&fullname) {
                        let _ = events.send(DiscoveryEvent::Gone(addr));
                    }
                }
                _ => {}
            }
        }

        for addr in cache.expire(Instant::now()) {
            let _ = events.send(DiscoveryEvent::Expired(addr));
        }
    }

    if let Some((name, _)) = advertised {
        let _ = daemon.unregister(&name);
    }
    let _ = daemon.shutdown();
}

fn sanitize_label(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .take(MAX_LABEL_CHARS)
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect();
    if cleaned.trim().is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

#[derive(Default)]
struct PeerCache {
    entries: HashMap<String, DiscoveredPeer>,
}

impl PeerCache {
    fn insert(&mut self, fullname: String, peer: DiscoveredPeer) {
        self.entries.insert(fullname, peer);
        while self.entries.len() > MAX_DISCOVERED_PEERS {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, found)| found.seen_at)
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, fullname: &str) -> Option<SocketAddr> {
        self.entries.remove(fullname).map(|peer| peer.addr)
    }

    fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        let stale: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, peer)| peer.is_expired(now))
            .map(|(name, _)| name.clone())
            .collect();
        let mut addresses = Vec::new();
        for name in stale {
            if let Some(peer) = self.entries.remove(&name) {
                addresses.push(peer.addr);
            }
        }
        addresses
    }

    fn list(&self) -> Vec<DiscoveredPeer> {
        let mut peers: Vec<DiscoveredPeer> = self.entries.values().cloned().collect();
        peers.sort_by(|left, right| {
            left.label
                .cmp(&right.label)
                .then_with(|| left.addr.cmp(&right.addr))
        });
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(octet: u8, seen_at: Instant) -> DiscoveredPeer {
        DiscoveredPeer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, octet)), 9000),
            format!("peer-{octet}"),
            seen_at,
        )
    }

    #[test]
    fn cache_bounds_discovered_peers() {
        let mut cache = PeerCache::default();
        let now = Instant::now();
        for index in 0..(MAX_DISCOVERED_PEERS + 5) {
            let seen_at = now + Duration::from_millis(index as u64);
            cache.insert(format!("peer-{index}"), peer(index as u8, seen_at));
        }
        assert_eq!(cache.list().len(), MAX_DISCOVERED_PEERS);
        assert!(!cache.list().iter().any(|found| found.label == "peer-0"));
        assert!(
            cache
                .list()
                .iter()
                .any(|found| found.label == format!("peer-{}", MAX_DISCOVERED_PEERS + 4))
        );
    }

    #[test]
    fn cache_expires_stale_peers() {
        let mut cache = PeerCache::default();
        let seen_at = Instant::now() - PEER_TTL;
        cache.insert("stale".into(), peer(10, seen_at));
        cache.insert("fresh".into(), peer(11, Instant::now()));

        let expired = cache.expire(Instant::now());
        assert_eq!(expired, vec![peer(10, seen_at).addr]);
        assert_eq!(cache.list().len(), 1);
        assert_eq!(cache.list()[0].addr, peer(11, Instant::now()).addr);
    }

    #[test]
    fn cache_removes_peers_by_service_name() {
        let mut cache = PeerCache::default();
        let now = Instant::now();
        cache.insert("instance._ghost._tcp.local.".into(), peer(12, now));
        assert_eq!(
            cache.remove("instance._ghost._tcp.local."),
            Some(peer(12, now).addr)
        );
        assert!(cache.list().is_empty());
    }

    #[test]
    fn labels_are_bounded_and_sanitized() {
        let raw = format!("{}\u{7}tail", "x".repeat(MAX_LABEL_CHARS + 10));
        let label = sanitize_label(&raw);
        assert_eq!(label.chars().count(), MAX_LABEL_CHARS);
        assert!(!label.chars().any(char::is_control));
        assert_eq!(sanitize_label("   "), "unknown");
    }
}
