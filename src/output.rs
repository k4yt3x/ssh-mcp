//! What goes back to the caller: tool errors, progress notifications and the text formatting every
//! tool shares, with the small helpers several modules use.

use std::{
    fmt,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use rmcp::{
    Peer, RoleServer,
    model::{ProgressNotificationParam, ProgressToken},
    service::RequestContext,
};
use russh::Sig;

/// A failure the agent reads in the tool result. The message says what happened and, when there
/// is one, the remedy.
#[derive(Debug)]
pub(crate) struct ToolError {
    message: String,
}

impl ToolError {
    /// Create an error carrying the message the agent reads.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message the agent reads.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Lock `mutex`, recovering the data when a thread panicked while holding it. Every lock in this
/// server guards state that stays consistent between statements, so the data is still usable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// `bytes` random bytes from the operating system, as lowercase hex.
pub(crate) fn random_hex(bytes: usize) -> Result<String, ToolError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|error| ToolError::new(format!("No randomness is available: {error}")))?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The name of a signal without the `SIG` prefix, as the server reported it. A name the server
/// made up keeps only letters, digits and underscores, at most [`MAX_SIGNAL_NAME_CHARS`] of them,
/// so it cannot add lines or quotes to a result.
pub(crate) fn signal_label(signal: &Sig) -> String {
    let name = match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => {
            let cleaned: String = name
                .chars()
                .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
                .take(MAX_SIGNAL_NAME_CHARS)
                .collect();
            return if cleaned.is_empty() {
                "(unnamed)".to_owned()
            } else {
                cleaned
            };
        }
    };
    name.to_owned()
}

/// The longest signal name a result repeats from the server.
const MAX_SIGNAL_NAME_CHARS: usize = 32;

/// How much of the end of a program's output a status line looks at.
pub(crate) const STATUS_TAIL_BYTES: usize = 512;

/// The most characters of a progress status line.
const STATUS_LINE_CHARS: usize = 200;

/// The last non-blank line among the final bytes of `output`, cleaned of terminal escapes, for a
/// progress status line.
pub(crate) fn last_output_line(output: &[u8]) -> Option<String> {
    let tail = output
        .get(output.len().saturating_sub(STATUS_TAIL_BYTES)..)
        .unwrap_or_default();
    clean_terminal_text(tail)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.chars().take(STATUS_LINE_CHARS).collect())
}

/// The minimum time between two progress notifications for one tool call, and how often a waiting
/// tool looks for a new status line.
pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// Sends `notifications/progress` for one tool call when the caller asked for them with a progress
/// token, at most once per [`PROGRESS_INTERVAL`]. The progress number is the bytes done for a
/// transfer and the whole seconds since the call started otherwise, so it always increases.
pub(crate) struct Progress {
    target: Option<(Peer<RoleServer>, ProgressToken)>,
    started: Instant,
    last_sent: Option<Instant>,
}

impl Progress {
    /// A reporter for the tool call `context` belongs to.
    pub(crate) fn from_context(context: &RequestContext<RoleServer>) -> Self {
        Self {
            target: context
                .meta
                .get_progress_token()
                .map(|token| (context.peer.clone(), token)),
            started: Instant::now(),
            last_sent: None,
        }
    }

    /// A reporter that sends nothing, for calls made outside a request.
    pub(crate) fn none() -> Self {
        Self {
            target: None,
            started: Instant::now(),
            last_sent: None,
        }
    }

    /// Report a status line, dropped when the previous one went out less than
    /// [`PROGRESS_INTERVAL`] ago.
    pub(crate) async fn report(&mut self, message: &str) {
        self.send(message, None, None).await;
    }

    /// Report progress through a known amount of work.
    pub(crate) async fn report_amount(&mut self, message: &str, done: u64, total: u64) {
        #[allow(clippy::cast_precision_loss)]
        self.send(message, Some(done as f64), Some(total as f64))
            .await;
    }

    async fn send(&mut self, message: &str, done: Option<f64>, total: Option<f64>) {
        let Some((peer, token)) = &self.target else {
            return;
        };
        if self
            .last_sent
            .is_some_and(|sent| sent.elapsed() < PROGRESS_INTERVAL)
        {
            return;
        }
        self.last_sent = Some(Instant::now());
        // Sends are at least a second apart, so the whole seconds increase with each one.
        #[allow(clippy::cast_precision_loss)]
        let elapsed_seconds = self.started.elapsed().as_secs() as f64;
        let mut parameters =
            ProgressNotificationParam::new(token.clone(), done.unwrap_or(elapsed_seconds))
                .with_message(message);
        if let Some(total) = total {
            parameters = parameters.with_total(total);
        }
        if let Err(error) = peer.notify_progress(parameters).await {
            tracing::debug!("progress notification was not delivered: {error}");
        }
    }
}

/// Format a byte count for a person: `512 B`, `3.4 KiB`, `12.0 MiB`.
pub(crate) fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or("TiB"))
}

/// Format a duration for a person: `0.4s`, `12.3s`, `4m 05s`.
pub(crate) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 60.0 {
        return format!("{seconds:.1}s");
    }
    let whole = duration.as_secs();
    if whole < 3600 {
        format!("{}m {:02}s", whole / 60, whole % 60)
    } else {
        format!("{}h {:02}m", whole / 3600, (whole % 3600) / 60)
    }
}

/// The largest index no greater than `index` that falls on a UTF-8 character boundary of `text`.
pub(crate) fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// The smallest index no less than `index` that falls on a UTF-8 character boundary of `text`.
fn ceil_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Decode `bytes` as UTF-8, replacing invalid sequences, and keep at most `limit` bytes of text:
/// the start and the end, with a line in between saying how much was left out.
pub(crate) fn decode_with_limit(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= limit {
        return text.into_owned();
    }
    let head_end = floor_char_boundary(&text, limit / 2);
    let tail_start = ceil_char_boundary(&text, text.len() - (limit - limit / 2));
    let omitted = tail_start - head_end;
    format!(
        "{}\n[... {} omitted; raise max_output_bytes or redirect the output to a file ...]\n{}",
        text.get(..head_end).unwrap_or(""),
        format_size(omitted as u64),
        text.get(tail_start..).unwrap_or("")
    )
}

/// Turn bytes a program wrote to a terminal into plain text: escape sequences are removed, a
/// carriage return returns to the start of the line so a redrawn progress line keeps only its
/// last state, and a backspace moves back one character.
pub(crate) fn clean_terminal_text(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut output = String::with_capacity(text.len());
    let mut line: Vec<char> = Vec::new();
    let mut cursor = 0usize;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\u{1b}' => match characters.next() {
                Some('[') => {
                    let mut final_byte = None;
                    for next in characters.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&next) {
                            final_byte = Some(next);
                            break;
                        }
                    }
                    if final_byte == Some('K') {
                        line.truncate(cursor);
                    }
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    // A string such as a window title ends at BEL or ST (ESC \), and, as a
                    // terminal ends it, at CAN, SUB or the start of another escape sequence, which
                    // is then read as one. An unended title must not hide the output after it.
                    while let Some(&next) = characters.peek() {
                        if next == '\u{1b}' {
                            let mut after = characters.clone();
                            after.next();
                            if after.peek() == Some(&'\\') {
                                characters.next();
                                characters.next();
                            }
                            break;
                        }
                        characters.next();
                        if matches!(next, '\u{7}' | '\u{18}' | '\u{1a}') {
                            break;
                        }
                    }
                }
                Some('(' | ')' | '*' | '+' | '#' | '%') => {
                    characters.next();
                }
                _ => {}
            },
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    continue;
                }
                cursor = 0;
            }
            '\n' => {
                output.extend(line.drain(..));
                output.push('\n');
                cursor = 0;
            }
            '\u{8}' => cursor = cursor.saturating_sub(1),
            '\t' => put_character(&mut line, &mut cursor, '\t'),
            character if character.is_control() => {}
            character => put_character(&mut line, &mut cursor, character),
        }
    }
    output.extend(line);
    output
}

fn put_character(line: &mut Vec<char>, cursor: &mut usize, character: char) {
    if let Some(slot) = line.get_mut(*cursor) {
        *slot = character;
    } else {
        line.push(character);
    }
    *cursor += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redrawn_progress_line_keeps_its_last_state() {
        assert_eq!(
            clean_terminal_text(b"10%\r20%\r100%\r\ndone\r\n"),
            "100%\ndone\n"
        );
    }

    #[test]
    fn escape_sequences_are_removed() {
        assert_eq!(
            clean_terminal_text(b"\x1b[1;31mred\x1b[0m \x1b]0;title\x07plain\x1b(B"),
            "red plain"
        );
    }

    #[test]
    fn an_unended_title_does_not_hide_the_output_after_it() {
        assert_eq!(
            clean_terminal_text(b"\x1b]0;title\x1b[31mred\x1b[0m"),
            "red"
        );
        assert_eq!(clean_terminal_text(b"\x1b]0;title\x18after"), "after");
        assert_eq!(clean_terminal_text(b"\x1b]0;title\x1b\\after"), "after");
    }

    #[test]
    fn a_signal_name_from_the_server_cannot_add_text_of_its_own() {
        assert_eq!(signal_label(&Sig::TERM), "TERM");
        assert_eq!(
            signal_label(&Sig::Custom("WINCH\n]; exit code 0 \"".to_owned())),
            "WINCHexitcode0"
        );
        assert_eq!(signal_label(&Sig::Custom("x".repeat(100))).len(), 32);
        assert_eq!(signal_label(&Sig::Custom("\n".to_owned())), "(unnamed)");
    }

    #[test]
    fn erase_line_after_carriage_return_clears_the_old_text() {
        assert_eq!(clean_terminal_text(b"long text\r\x1b[Kshort"), "short");
    }

    #[test]
    fn backspace_moves_back_one_character() {
        assert_eq!(clean_terminal_text(b"abc\x08\x08X"), "aXc");
    }

    #[test]
    fn a_long_output_keeps_its_start_and_end() {
        let text = "a".repeat(100) + &"b".repeat(100);
        let limited = decode_with_limit(text.as_bytes(), 20);
        assert!(limited.starts_with("aaaaaaaaaa\n[..."));
        assert!(limited.ends_with("...]\nbbbbbbbbbb"));
    }

    #[test]
    fn limiting_never_splits_a_character() {
        let text = "é".repeat(50);
        let limited = decode_with_limit(text.as_bytes(), 11);
        assert!(limited.starts_with("éé\n"));
        assert!(limited.ends_with("\nééé"));
    }

    #[test]
    fn short_output_is_kept_whole() {
        assert_eq!(decode_with_limit(b"hello", 5), "hello");
    }

    #[test]
    fn sizes_and_durations_read_naturally() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(3 * 1024 * 1024 / 2), "1.5 MiB");
        assert_eq!(format_duration(Duration::from_millis(400)), "0.4s");
        assert_eq!(format_duration(Duration::from_secs(245)), "4m 05s");
    }
}
