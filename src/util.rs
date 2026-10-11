//! Filesystem and JSON helpers shared by every module.

use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// The home directory, as Node's `os.homedir()` reads it on POSIX: `$HOME`.
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// clm's own data: `~/.clm`.
pub fn data_dir() -> PathBuf {
    home().join(".clm")
}

/// The original clausona's data, which `clm init` imports from and never writes to.
pub fn legacy_dir() -> PathBuf {
    home().join(".clausona")
}

pub fn registry_path() -> PathBuf {
    data_dir().join("profiles.json")
}

pub fn usage_path() -> PathBuf {
    data_dir().join("usage.json")
}

pub fn locks_dir() -> PathBuf {
    data_dir().join("locks")
}

/// Whether anything (a file, a directory, a link - even a dangling one) is at `p`.
pub fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

pub fn is_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// A directory itself, not a link to one.
pub fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

pub fn realpath(p: &Path) -> Option<PathBuf> {
    fs::canonicalize(p).ok()
}

/// `path.resolve`: absolute and lexically normalized, without touching the filesystem.
pub fn resolve(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")).join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// realpath, falling back to `resolve` for a path that does not exist.
pub fn real_or_resolved(p: &Path) -> PathBuf {
    realpath(p).unwrap_or_else(|| resolve(p))
}

/// `p` with the home directory written as `~`, for messages.
pub fn shown(p: &Path) -> String {
    shown_str(&p.to_string_lossy())
}

pub fn shown_str(s: &str) -> String {
    let h = home();
    let h = h.to_string_lossy();
    if h.len() > 1
        && let Some(rest) = s.strip_prefix(h.as_ref()) {
            return format!("~{rest}");
        }
    s.to_string()
}

/// `~` or `~/…` expanded against the home directory.
pub fn expand_tilde(input: &str) -> PathBuf {
    if input == "~" {
        return home();
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return home().join(rest);
    }
    PathBuf::from(input)
}

pub fn warn(message: &str) {
    eprintln!("  warn: {message}");
}

pub fn read_text(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

/// The parsed JSON at `p`, or None when it is missing or does not parse.
pub fn read_json(p: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(p).ok()?).ok()
}

/// A JSON object at `p`, or an empty one.
pub fn read_json_object(p: &Path) -> serde_json::Map<String, Value> {
    match read_json(p) {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    }
}

/// JSON as `JSON.stringify(value, null, 2)` writes it, with a trailing newline.
pub fn to_pretty(value: &Value) -> String {
    let mut s = serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".into());
    s.push('\n');
    s
}

/// Writes `value` through a temp file and a rename, so a reader never sees half of it. `mode`
/// is for clm's own files only; a tool's files keep the mode the tool gave them.
pub fn write_json(p: &Path, value: &Value, mode: Option<u32>) -> io::Result<()> {
    write_atomic(p, to_pretty(value).as_bytes(), mode)
}

pub fn write_atomic(p: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}.tmp.{}", p.display(), std::process::id()));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        if let Some(m) = mode {
            opts.mode(m);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    if let Err(e) = fs::rename(&tmp, p) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Some(m) = mode {
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(m));
    }
    Ok(())
}

/// Writes `value` unless the file already holds the same JSON; true when it wrote.
pub fn write_json_if_changed(p: &Path, value: &Value) -> io::Result<bool> {
    if let Some(current) = read_json(p)
        && &current == value {
            return Ok(false);
        }
    write_json(p, value, None)?;
    Ok(true)
}

/// `rm -rf`, quietly.
pub fn remove_all(p: &Path) {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// Copies `src` to `dst` recursively; links are copied as links, with the target they hold.
pub fn copy_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(src)?;
        std::os::unix::fs::symlink(target, dst)?;
    } else if ft.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        fs::copy(src, dst)?;
    }
    Ok(())
}

/// Renames `source` to `dest`, or copies it there and removes it across filesystems. The copy
/// is made under a name of its own and renamed into place once whole.
pub fn move_to(source: &Path, dest: &Path) -> io::Result<()> {
    match fs::rename(source, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            let partial = PathBuf::from(format!("{}.clausona-move-{}", dest.display(), std::process::id()));
            remove_all(&partial);
            let result = copy_recursive(source, &partial).and_then(|_| {
                if exists(dest) {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", dest.display())));
                }
                fs::rename(&partial, dest)
            });
            if let Err(err) = result {
                remove_all(&partial);
                return Err(err);
            }
            remove_all(source);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub fn read_dir_names(p: &Path) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(p) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

/// The entries of a directory with whether each is a directory (not following links).
pub fn read_dir_entries(p: &Path) -> Vec<(String, fs::FileType)> {
    let mut out: Vec<(String, fs::FileType)> = match fs::read_dir(p) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_type().ok().map(|t| (e.file_name().to_string_lossy().into_owned(), t)))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn mtime_ms(p: &Path) -> Option<i64> {
    let m = fs::metadata(p).ok()?;
    let t = m.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64)
}

pub fn lmtime_ms(p: &Path) -> Option<i64> {
    let m = fs::symlink_metadata(p).ok()?;
    let t = m.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64)
}

/// Sets a path's access and modification times to now.
pub fn touch(p: &Path) {
    if let Ok(c) = CString::new(p.as_os_str().as_bytes()) {
        unsafe {
            libc::utimes(c.as_ptr(), std::ptr::null());
        }
    }
}

pub fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

pub fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// The current time as `new Date().toISOString()` writes it.
pub fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// A string as one POSIX shell word that means exactly itself.
pub fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn is_posix_env_name(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `child` is `parent` or lies inside it. Both absolute and normalized.
pub fn is_within(parent: &Path, child: &Path) -> bool {
    child.starts_with(parent)
}

/// Removes `dir` and every directory under it left empty. rmdir alone, so nothing that holds a
/// file or a link goes.
pub fn remove_empty_dirs(dir: &Path) {
    if !is_real_dir(dir) {
        return;
    }
    for name in read_dir_names(dir) {
        remove_empty_dirs(&dir.join(name));
    }
    let _ = fs::remove_dir(dir);
}

/// Whether a directory holds anything - or is something other than a directory.
pub fn dir_occupied(p: &Path) -> bool {
    match fs::symlink_metadata(p) {
        Err(_) => false,
        Ok(m) if !m.is_dir() => true,
        Ok(_) => !read_dir_names(p).is_empty(),
    }
}
