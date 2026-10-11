//! How `list`, `usage`, `doctor` and `config --show` print.

use chrono::{Datelike, Local};

use crate::env::{display_name, profile_display_name};
use crate::service::ListItem;
use crate::style::*;
use crate::types::{DoctorResult, QuotaWindow, Tool, UsagePeriod, UsageSummary};
use crate::util::now_ms;

pub fn local_timezone_label() -> String {
    let now = Local::now();
    let tz = std::env::var("TZ").ok().filter(|t| !t.is_empty()).unwrap_or_else(|| {
        std::fs::read_link("/etc/localtime")
            .ok()
            .and_then(|p| {
                let s = p.to_string_lossy().into_owned();
                s.split("zoneinfo/").nth(1).map(String::from)
            })
            .unwrap_or_else(|| "local".into())
    });
    format!("{tz} (UTC{})", now.format("%:z"))
}

fn reset_ms(resets_at: Option<&str>) -> Option<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(resets_at?).ok()?;
    Some(t.timestamp_millis() - now_ms())
}

pub fn format_reset_short(resets_at: Option<&str>) -> String {
    let Some(ms) = reset_ms(resets_at) else { return String::new() };
    if ms <= 0 {
        return "now".into();
    }
    let minutes = ms / 60_000;
    if minutes >= 1440 {
        format!("{}d", minutes / 1440)
    } else if minutes >= 60 {
        format!("{}h", minutes / 60)
    } else {
        format!("{}m", minutes.max(1))
    }
}

fn format_percent(w: &QuotaWindow) -> String {
    format!("{}%", w.used_percent.round() as i64)
}

fn styled_quota(window: Option<&QuotaWindow>, state: Option<&str>) -> String {
    let (Some(w), Some(state)) = (window, state) else { return dim("—") };
    let text = format_percent(w);
    if state != "ok" {
        return dimmer(&text);
    }
    if w.used_percent >= 90.0 {
        red(&text)
    } else if w.used_percent >= 75.0 {
        yellow(&text)
    } else {
        text
    }
}

fn quota_cell(window: Option<&QuotaWindow>, state: Option<&str>, with_reset: bool) -> String {
    let percent = styled_quota(window, state);
    match window {
        Some(w) if with_reset => {
            let reset = format_reset_short(w.resets_at.as_deref());
            if reset.is_empty() { percent } else { format!("{percent} {}", dimmer(&reset)) }
        }
        _ => percent,
    }
}

/// A model id cut to a column by its middle, so the gateway and the variant both stay.
pub fn fit_model(model: Option<&str>, width: usize) -> String {
    let text = model.unwrap_or("—");
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".into();
    }
    let keep = width - 1;
    let tail = (keep * 2).div_ceil(3);
    let head: String = chars[..keep - tail].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{head}…{end}")
}

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Profile,
    Account,
    Model,
    Session,
    Weekly,
    Cost,
    Input,
    Output,
}

struct Layout {
    keys: Vec<Col>,
    reset: bool,
    profile_width: usize,
    account_width: usize,
}

fn col_width(c: Col, l: &Layout) -> usize {
    match c {
        Col::Profile => l.profile_width,
        Col::Account => l.account_width,
        Col::Session | Col::Weekly => {
            if l.reset {
                11
            } else {
                7
            }
        }
        Col::Model => 24,
        Col::Cost => 12,
        Col::Input => 14,
        Col::Output => 10,
    }
}

fn layout_width(l: &Layout) -> usize {
    4 + l.keys.iter().map(|k| col_width(*k, l)).sum::<usize>()
}

fn candidate_layouts(show_quota: bool, show_model: bool) -> Vec<Layout> {
    let tails: [&[Col]; 4] = [&[Col::Cost, Col::Input, Col::Output], &[Col::Cost, Col::Input], &[Col::Cost], &[]];
    let quota: Vec<Col> = if show_quota { vec![Col::Session, Col::Weekly] } else { vec![] };
    let mk = |keys: Vec<Col>, reset: bool, pw: usize, aw: usize| Layout { keys, reset, profile_width: pw, account_width: aw };
    let mut out = Vec::new();
    if show_model {
        for t in tails {
            let mut keys = vec![Col::Profile, Col::Account, Col::Model];
            keys.extend(&quota);
            keys.extend_from_slice(t);
            out.push(mk(keys, show_quota, 20, 32));
        }
    }
    if !show_quota {
        for t in tails {
            let mut keys = vec![Col::Profile, Col::Account];
            keys.extend_from_slice(t);
            out.push(mk(keys, false, 20, 32));
        }
        out.push(mk(vec![Col::Profile, Col::Account, Col::Cost], false, 14, 22));
        return out;
    }
    for t in tails {
        let mut keys = vec![Col::Profile, Col::Account];
        keys.extend(&quota);
        keys.extend_from_slice(t);
        out.push(mk(keys, true, 20, 32));
    }
    let mut base = vec![Col::Profile, Col::Account];
    base.extend(&quota);
    out.push(mk(base.clone(), false, 20, 32));
    out.push(mk(base, false, 14, 22));
    out
}

fn terminal_width() -> usize {
    if let Some(c) = std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()) {
        return c;
    }
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    120
}

fn quota_note(state: &str) -> &'static str {
    match state {
        "expired" => "sign-in has lapsed — run `clm login <profile>`",
        "missing" => "no stored credential for this profile",
        "cooldown" => "quota endpoint is rate limited; retrying later",
        _ => "quota lookup failed",
    }
}

pub fn render_list(items: &[ListItem]) -> String {
    let now = Local::now();
    let week_ago = now - chrono::Duration::days(7);
    let range = format!("{}/{} – {}/{}", week_ago.month(), week_ago.day(), now.month(), now.day());
    let mut sorted: Vec<&ListItem> = items.iter().collect();
    sorted.sort_by(|a, b| {
        let ta = a.profile.tool() != Tool::Claude;
        let tb = b.profile.tool() != Tool::Claude;
        ta.cmp(&tb).then(b.profile.primary().cmp(&a.profile.primary())).then(a.id.cmp(&b.id))
    });
    let show_quota = sorted.iter().any(|i| i.quota.is_some());
    let show_model = sorted.iter().any(|i| i.model.is_some());
    let available = terminal_width();
    let layouts = candidate_layouts(show_quota, show_model);
    let last = layouts.len() - 1;
    let idx = layouts.iter().position(|l| layout_width(l) <= available).unwrap_or(last);
    let layout = &layouts[idx];
    let widths: Vec<usize> = layout.keys.iter().map(|k| col_width(*k, layout)).collect();
    let label = |c: Col| match c {
        Col::Profile => "PROFILE",
        Col::Account => "ACCOUNT",
        Col::Model => "MODEL",
        Col::Session => "5H",
        Col::Weekly => "7D",
        Col::Cost => "COST",
        Col::Input => "INPUT",
        Col::Output => "OUTPUT",
    };
    let header = format!(
        "    {}",
        layout.keys.iter().zip(&widths).map(|(k, w)| secondary(&pad_plain(label(*k), *w))).collect::<String>()
    );
    let sep = format!("    {}", dimmer(&"─".repeat(widths.iter().sum())));
    let spend_shown = layout.keys.iter().any(|k| matches!(k, Col::Cost | Col::Input | Col::Output));
    let has_codex = sorted.iter().any(|i| i.profile.tool() == Tool::Codex);

    let mut rows = Vec::new();
    for item in &sorted {
        let marker = if item.is_active { accent("▸") } else { " ".into() };
        let codex = item.profile.tool() == Tool::Codex;
        let state = item.quota.as_ref().map(|q| q.state.as_str());
        let cell = |c: Col| -> String {
            match c {
                Col::Profile => {
                    let name = truncate(&item.id, layout.profile_width - 1);
                    if item.is_active { accent(&name) } else { name }
                }
                Col::Account => {
                    let dn = profile_display_name(&item.profile);
                    let account = truncate(if dn.trim().is_empty() { "—" } else { dn.as_str() }, layout.account_width - 1);
                    if item.is_active { account } else { secondary(&account) }
                }
                Col::Model => {
                    let model = fit_model(item.model.as_deref(), 23);
                    if item.model.is_none() {
                        dim(&model)
                    } else if item.is_active {
                        model
                    } else {
                        secondary(&model)
                    }
                }
                Col::Session => quota_cell(item.quota.as_ref().and_then(|q| q.windows.session.as_ref()), state, layout.reset),
                Col::Weekly => quota_cell(item.quota.as_ref().and_then(|q| q.windows.weekly.as_ref()), state, layout.reset),
                Col::Cost => if codex { dim("—") } else { styled_cost(item.week.cost) },
                Col::Input => if codex { dim("—") } else { styled_count(item.week.input_tokens) },
                Col::Output => if codex { dim("—") } else { styled_count(item.week.output_tokens) },
            }
        };
        let n = layout.keys.len();
        let cells: String = layout
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| if i == n - 1 { cell(*k) } else { pad_end(&cell(*k), widths[i]) })
            .collect();
        let suffix = if codex && spend_shown { format!("  {}", dim("*")) } else { String::new() };
        rows.push(format!("  {marker} {cells}{suffix}"));
    }
    let mut notes = Vec::new();
    if has_codex && spend_shown {
        notes.push("* cost and token tracking are not available for codex".to_string());
    }
    let mut states: Vec<&str> = Vec::new();
    for item in &sorted {
        if let Some(q) = &item.quota
            && q.state != "ok" && !states.contains(&q.state.as_str()) {
                states.push(q.state.as_str());
            }
    }
    for s in states {
        notes.push(format!("{s}: {}", quota_note(s)));
    }
    let mut out = vec![String::new(), format!("  {}  {}", dim(&range), dim(&local_timezone_label())), String::new(), header, sep];
    out.extend(rows);
    out.extend(notes.into_iter().map(|n| format!("  {}", dim(&n))));
    out.push(String::new());
    out.join("\n")
}

fn period_label(period: UsagePeriod) -> &'static str {
    match period {
        UsagePeriod::Today => "Today",
        UsagePeriod::Week => "This week",
        UsagePeriod::Month => "This month",
        UsagePeriod::All => "All time",
    }
}

pub fn render_usage(data: &[(String, UsageSummary)], single: bool, period: UsagePeriod) -> String {
    let tz = if period == UsagePeriod::All { String::new() } else { format!(" {}", dim(&format!("({})", local_timezone_label()))) };
    if single {
        let (name, s) = &data[0];
        return [
            String::new(),
            heading(&format!("{name} {} {}{tz}", dim("·"), period_label(period))),
            String::new(),
            format!("    {}{}", secondary(&pad_plain("Cost", 16)), styled_cost(s.cost)),
            format!("    {}{}", secondary(&pad_plain("Input tokens", 16)), styled_count(s.input_tokens)),
            format!("    {}{}", secondary(&pad_plain("Output tokens", 16)), styled_count(s.output_tokens)),
            String::new(),
        ]
        .join("\n");
    }
    let total_cost: f64 = data.iter().map(|(_, s)| s.cost).sum();
    let total_in: u64 = data.iter().map(|(_, s)| s.input_tokens).sum();
    let total_out: u64 = data.iter().map(|(_, s)| s.output_tokens).sum();
    let mut cells: Vec<Vec<String>> = data
        .iter()
        .map(|(n, s)| vec![n.clone(), styled_cost(s.cost), styled_count(s.input_tokens), styled_count(s.output_tokens)])
        .collect();
    cells.push(vec![bold("Total"), bold(&styled_cost(total_cost)), styled_count(total_in), styled_count(total_out)]);
    let labels = ["PROFILE", "COST", "INPUT", "OUTPUT"];
    let mins = [16, 14, 14, 14];
    let widths: Vec<usize> =
        (0..4).map(|i| cells.iter().map(|c| visible_len(&c[i]) + 2).max().unwrap_or(0).max(mins[i])).collect();
    let header = format!("    {}", (0..4).map(|i| secondary(&pad_plain(labels[i], widths[i]))).collect::<String>());
    let sep = format!("    {}", dimmer(&"─".repeat(widths.iter().sum())));
    let line = |c: &Vec<String>| {
        format!("    {}", c.iter().enumerate().map(|(i, s)| if i == 3 { s.clone() } else { pad_end(s, widths[i]) }).collect::<String>())
    };
    let mut out = vec![String::new(), heading(&format!("{}{tz}", period_label(period))), String::new(), header, sep.clone()];
    for c in &cells[..cells.len() - 1] {
        out.push(line(c));
    }
    out.push(sep);
    out.push(line(cells.last().unwrap()));
    out.push(String::new());
    out.join("\n")
}

const CREDENTIAL_KINDS: [&str; 3] = ["missing_json", "missing_keychain", "missing_oauth"];
const SELF_DIRECTED_KINDS: [&str; 14] = [
    "primary_broken_link",
    "missing_config_dir",
    "missing_api_secret",
    "invalid_api_config",
    "shared_api_key_helper",
    "unreadable_settings",
    "plaintext_env_secret",
    "shared_key_source",
    "settings_env_override",
    "env_overrides_endpoint",
    "invalid_env_map",
    "invalid_profile_kind",
    "socket_path_too_long",
    "shared_sqlite_home",
];

fn plural(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

fn offers_repair(result: &DoctorResult) -> bool {
    if result.issues.iter().any(|i| i.kind == "missing_config_dir" || i.kind == "primary_config_dir") {
        return false;
    }
    result.issues.iter().any(|i| !CREDENTIAL_KINDS.contains(&i.kind) && !SELF_DIRECTED_KINDS.contains(&i.kind))
}

pub fn render_doctor(results: &[DoctorResult]) -> String {
    let mut sections = Vec::new();
    for r in results {
        let title = format!("  {} {}", bold(&r.name), dim(&format!("({})", display_name(&r.email, r.label.as_deref()))));
        let warnings = r.issues.iter().filter(|i| i.is_warning()).count();
        let errors = r.issues.len() - warnings;
        if r.issues.is_empty() {
            sections.push(format!("{title}\n    {} {}", ok_icon(), green("healthy")));
            continue;
        }
        let status = if errors == 0 {
            format!("    {} {}", warn_icon(), yellow(&plural(warnings, "warning")))
        } else {
            let extra = if warnings == 0 { String::new() } else { dim(&format!(", {}", plural(warnings, "warning"))) };
            format!("    {} {}{extra}", fail_icon(), red(&plural(errors, "issue")))
        };
        let mut lines = vec![title, status];
        let n = r.issues.len();
        for (i, issue) in r.issues.iter().enumerate() {
            let connector = if i == n - 1 { "╰─" } else { "├─" };
            let marker = if issue.is_warning() { format!("{} ", warn_icon()) } else { String::new() };
            lines.push(format!("    {} {marker}{}", dim(connector), issue.message));
        }
        let needs_login = !r.issues.iter().any(|i| i.kind == "invalid_profile_kind")
            && r.issues.iter().any(|i| CREDENTIAL_KINDS.contains(&i.kind));
        if offers_repair(r) {
            lines.push(format!("       {}", dim(&format!("Run {} to fix", accent(&format!("clm repair {}", r.name))))));
        }
        if needs_login {
            lines.push(format!("       {}", dim(&format!("Run {} to sign in", accent(&format!("clm login {}", r.name))))));
        }
        sections.push(lines.join("\n"));
    }
    let mut all = vec![String::new()];
    all.extend(sections);
    all.push(String::new());
    all.join("\n\n")
}
