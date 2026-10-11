//! Terminal styling: the colors and boxes the CLI prints with.

use std::sync::OnceLock;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return false;
        }
        if std::env::var_os("FORCE_COLOR").is_some_and(|v| v != "0") {
            return true;
        }
        crate::util::isatty(1)
    })
}

fn hex(color: &str, s: &str) -> String {
    if !enabled() {
        return s.to_string();
    }
    let c = color.trim_start_matches('#');
    let r = u8::from_str_radix(&c[0..2], 16).unwrap_or(255);
    let g = u8::from_str_radix(&c[2..4], 16).unwrap_or(255);
    let b = u8::from_str_radix(&c[4..6], 16).unwrap_or(255);
    format!("\x1b[38;2;{r};{g};{b}m{s}\x1b[39m")
}

pub const BRAND_LIGHT: &str = "#818cf8";
pub const SECONDARY: &str = "#a1a1aa";
pub const MUTED: &str = "#71717a";
pub const DIM: &str = "#3f3f46";
pub const HEALTHY: &str = "#10b981";
pub const WARNING: &str = "#f59e0b";
pub const ERROR: &str = "#ef4444";

pub fn bold(s: &str) -> String {
    if !enabled() {
        return s.to_string();
    }
    format!("\x1b[1m{s}\x1b[22m")
}
pub fn dim(s: &str) -> String {
    hex(MUTED, s)
}
pub fn dimmer(s: &str) -> String {
    hex(DIM, s)
}
pub fn accent(s: &str) -> String {
    hex(BRAND_LIGHT, s)
}
pub fn secondary(s: &str) -> String {
    hex(SECONDARY, s)
}
pub fn green(s: &str) -> String {
    hex(HEALTHY, s)
}
pub fn red(s: &str) -> String {
    hex(ERROR, s)
}
pub fn yellow(s: &str) -> String {
    hex(WARNING, s)
}

pub fn ok_icon() -> String {
    hex(HEALTHY, "✔")
}
pub fn fail_icon() -> String {
    hex(ERROR, "✘")
}
pub fn warn_icon() -> String {
    hex(WARNING, "⚠")
}

pub fn success(msg: &str) -> String {
    format!("  {} {msg}", ok_icon())
}

pub fn heading(title: &str) -> String {
    let rest = 42usize.saturating_sub(visible_len(title) + 5);
    format!("  {} {} {}", dim(&"─".repeat(3)), bold(title), dim(&"─".repeat(rest)))
}

/// Groups a count with commas, as `toLocaleString("en-US")` does.
pub fn thousands(value: u64) -> String {
    let s = value.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn styled_cost(value: f64) -> String {
    if value <= 0.0 {
        return dim("—");
    }
    let text = format!("${value:.2}");
    if value >= 5.0 { yellow(&text) } else { text }
}

pub fn styled_count(value: u64) -> String {
    if value == 0 { dim("—") } else { thousands(value) }
}

pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

pub fn visible_len(s: &str) -> usize {
    strip_ansi(s).chars().count()
}

pub fn pad_end(s: &str, width: usize) -> String {
    let need = width.saturating_sub(visible_len(s));
    format!("{s}{}", " ".repeat(need))
}

pub fn pad_plain(s: &str, width: usize) -> String {
    let need = width.saturating_sub(s.chars().count());
    format!("{s}{}", " ".repeat(need))
}

/// Plain text cut to fit a column, marking the cut with an ellipsis.
pub fn truncate(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let n = s.chars().count();
    if n <= width {
        return s.to_string();
    }
    if width == 1 {
        return "…".into();
    }
    let head: String = s.chars().take(width - 1).collect();
    format!("{head}…")
}

pub fn boxed(title: &str, lines: &[String]) -> String {
    let max_content = lines.iter().map(|l| visible_len(l)).max().unwrap_or(0);
    let width = 42usize.max(max_content + 4);
    let v = dim("│");
    let h = dim("─");
    let title_len = title.chars().count();
    let title_line = format!(
        "{}{} {} {}{}",
        dim("╭"),
        h,
        accent(title),
        h.repeat(width.saturating_sub(title_len + 3)),
        dim("╮")
    );
    let empty = format!("{v}{}{v}", " ".repeat(width));
    let bottom = format!("{}{}{}", dim("╰"), h.repeat(width), dim("╯"));
    let mut out = vec![format!("  {title_line}"), format!("  {empty}")];
    for line in lines {
        let pad = width.saturating_sub(2 + visible_len(line));
        out.push(format!("  {v}  {line}{}{v}", " ".repeat(pad)));
    }
    out.push(format!("  {empty}"));
    out.push(format!("  {bottom}"));
    out.join("\n")
}

pub fn help_section(title: &str, items: &[(&str, &str)]) -> String {
    let max = items.iter().map(|(c, _)| c.len()).max().unwrap_or(0);
    let mut rows = vec![format!("  {}", bold(title))];
    for (cmd, desc) in items {
        rows.push(format!("    {}{}", accent(&pad_plain(cmd, max + 2)), dim(desc)));
    }
    rows.join("\n")
}

/// A usage line with each `<placeholder>` highlighted.
pub fn help_usage(text: &str) -> String {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"<([^>]+)>").unwrap());
    let replaced = re.replace_all(text, |c: &regex::Captures| accent(&format!("<{}>", &c[1])));
    format!("    {replaced}")
}

/// `label` padded as one of the `Key        value` rows of a box.
pub fn row(label: &str, value: &str) -> String {
    format!("{}{value}", secondary(&pad_plain(label, 12)))
}
