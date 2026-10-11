//! Locks shared with other clm processes, and with Claude Code itself.
//!
//! A file lock is a file created exclusively, holding a token; one older than its stale time
//! was left by a process that died holding it and is taken over. A directory lock is the
//! `mkdir` lock proper-lockfile takes - the kind Claude Code takes on its credential - kept
//! fresh by touching it while it is held.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use crate::util::{mtime_ms, now_ms, sleep_ms, touch};

pub struct FileLock {
    path: PathBuf,
    token: String,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).map(|t| t == self.token).unwrap_or(false) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_exclusive(path: &Path, token: &str) -> std::io::Result<bool> {
    match fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(mut f) => {
            f.write_all(token.as_bytes())?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

fn new_token() -> String {
    format!("{}-{:x}", std::process::id(), now_ms() ^ (std::process::id() as i64).rotate_left(17))
}

/// Takes the lock at `path`, waiting up to `wait_ms` while another live holder has it.
/// None when it is still held at the end of the wait.
pub fn acquire_file_lock(path: &Path, stale_ms: i64, wait_ms: i64) -> std::io::Result<Option<FileLock>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let token = new_token();
    let deadline = now_ms() + wait_ms;
    loop {
        if create_exclusive(path, &token)? {
            return Ok(Some(FileLock { path: path.to_path_buf(), token }));
        }
        match (fs::read_to_string(path), mtime_ms(path)) {
            (Ok(held), Some(mtime)) if now_ms() - mtime >= stale_ms => {
                // Taken over only if it is still the stale holder's.
                if fs::read_to_string(path).map(|t| t == held).unwrap_or(false) {
                    let _ = fs::remove_file(path);
                }
                continue;
            }
            (Err(e), _) if e.kind() == ErrorKind::NotFound => continue,
            _ => {}
        }
        if now_ms() >= deadline {
            return Ok(None);
        }
        sleep_ms(50);
    }
}

pub struct DirLock {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    refresher: Option<JoinHandle<()>>,
}

impl Drop for DirLock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.refresher.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_dir(&self.path);
    }
}

pub struct DirLockOptions {
    pub stale_ms: i64,
    pub update_ms: u64,
    pub wait_ms: i64,
    pub retry_ms: u64,
}

/// Takes a proper-lockfile style directory lock. None while another holder keeps it fresh
/// past the wait; an error when the lock cannot be created at all.
pub fn acquire_dir_lock(path: &Path, opts: &DirLockOptions) -> std::io::Result<Option<DirLock>> {
    let deadline = now_ms() + opts.wait_ms;
    loop {
        match fs::create_dir(path) {
            Ok(()) => break,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                match mtime_ms(path) {
                    Some(m) if now_ms() - m > opts.stale_ms => {
                        let _ = fs::remove_dir_all(path);
                        continue;
                    }
                    None => continue,
                    _ => {}
                }
                if now_ms() >= deadline {
                    return Ok(None);
                }
                sleep_ms(opts.retry_ms.max(10));
            }
            Err(e) => return Err(e),
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let held = path.to_path_buf();
    let update = opts.update_ms.max(50);
    let refresher = std::thread::spawn(move || {
        let mut waited = 0u64;
        while !flag.load(Ordering::SeqCst) {
            sleep_ms(50);
            waited += 50;
            if waited >= update {
                waited = 0;
                touch(&held);
            }
        }
    });
    Ok(Some(DirLock { path: path.to_path_buf(), stop, refresher: Some(refresher) }))
}

/// The registry lock: re-reading, changing and saving one small file.
pub fn with_registry_lock<T>(f: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
    let path = crate::util::locks_dir().join("registry.lock");
    let lock = acquire_file_lock(&path, 5_000, 10_000)?;
    if lock.is_none() {
        anyhow::bail!(
            "Timed out waiting for another clm process to release {}. If none is running, delete that file and try again.",
            path.display()
        );
    }
    let result = f();
    drop(lock);
    result
}
