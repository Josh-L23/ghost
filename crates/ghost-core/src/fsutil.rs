use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32, overwrite: bool) -> io::Result<()> {
    #[cfg(not(unix))]
    let _ = mode;

    if let Some(parent) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }

    let temp = temp_path(path);
    let result = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if overwrite {
            fs::rename(&temp, path)?;
        } else {
            fs::hard_link(&temp, path)?;
        }
        sync_parent(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn quarantine(path: &Path, reason: &str) -> io::Result<PathBuf> {
    let _ = reason;
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "cannot quarantine a missing file",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("ghost-data");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut target = parent.join(format!("{name}.corrupt.{stamp}"));
    let mut suffix = 0;
    while target.exists() {
        suffix += 1;
        target = parent.join(format!("{name}.corrupt.{stamp}.{suffix}"));
    }
    fs::rename(path, &target)?;
    sync_parent(path);
    Ok(target)
}

fn temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("ghost-data");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{name}.{}.{stamp}.{unique}.tmp",
        std::process::id()
    ))
}

fn sync_parent(path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ghost-fsutil-{}-{}-{name}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let dir = test_dir("replace");
        let path = dir.join("state.bin");
        atomic_write(&path, b"first", 0o600, true).unwrap();
        atomic_write(&path, b"second", 0o600, true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_write_can_refuse_overwrite() {
        let dir = test_dir("create");
        let path = dir.join("state.bin");
        atomic_write(&path, b"first", 0o600, false).unwrap();
        assert!(atomic_write(&path, b"second", 0o600, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quarantine_moves_unreadable_data() {
        let dir = test_dir("quarantine");
        let path = dir.join("state.bin");
        fs::write(&path, b"bad").unwrap();
        let moved = quarantine(&path, "test").unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&moved).unwrap(), b"bad");
        fs::remove_dir_all(dir).unwrap();
    }
}
