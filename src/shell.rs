//! Persistent shells: a pseudo-terminal on its own channel, whose output is buffered so no result
//! repeats output an earlier one returned, and none is skipped without saying so.
//!
//! In managed mode the server sets the shell's prompts to invisible escape sequences carrying a
//! per-shell nonce, and wraps each `shell_run` command so the shell prints its exit code when it
//! finishes. That lets a result say whether the shell is at its prompt, which command finished and
//! how, and whether a command was left incomplete. Raw mode leaves the terminal untouched.

use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroU16,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use regex::Regex;
use russh::{ChannelMsg, ChannelWriteHalf, client::Msg};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{
    client::{
        CLOSE_TIMEOUT, REQUEST_TIMEOUT, SshHandle, best_effort, bounded, open_session_channel,
    },
    output::{
        PROGRESS_INTERVAL, Progress, STATUS_TAIL_BYTES, ToolError, clean_terminal_text,
        format_duration, format_size, last_output_line, lock, random_hex, signal_label,
    },
};

/// The most output a shell keeps that has not been reported yet. Older output is dropped, and the
/// next result says how much.
const BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// How long output has to stop before `shell_send` and `shell_read` consider it settled.
const SETTLE: Duration = Duration::from_millis(800);

/// How long the login output has to stop before `shell_open` sends the managed-mode setup.
const LOGIN_SETTLE: Duration = Duration::from_millis(400);

/// The most columns or rows a terminal may have; the rendered screen is allocated whole.
const MAX_TERMINAL_SIDE: u16 = 1000;

/// How long `shell_open` waits for the login output to settle and for the shell to answer the
/// managed-mode setup.
const OPEN_WAIT: Duration = Duration::from_secs(5);

/// How long canceling an incomplete command waits for the prompt after each of its steps.
const INTERRUPT_SETTLE: Duration = Duration::from_millis(500);

/// How long the shell has to take input. A program that stops reading its terminal stops the
/// channel from taking more, and russh itself would wait forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most output a result returns when its tool takes no `max_output_bytes`: `shell_open` and
/// `shell_close`.
const UNREQUESTED_OUTPUT_BYTES: usize = 64 * 1024;

/// How much output before the newly arrived output an `until` search covers again, so a match
/// that spans two arrivals is still found.
const UNTIL_OVERLAP_BYTES: u64 = 4096;

/// The longest OSC string, such as a window title, passed to the terminal emulator. Its parser
/// keeps an unended one in memory without limit, so a longer one is cut off there.
const MAX_OSC_BYTES: usize = 4096;

/// The characters of a command a result quotes.
const COMMAND_LABEL_CHARS: usize = 60;

/// The characters of a possible question a result quotes.
const QUESTION_CHARS: usize = 120;

/// The OSC number the markers use. Nothing assigns it, so a terminal ignores the sequences.
const MARKER_NUMBER: &str = "6973";

/// The start of every marker: an OSC string numbered [`MARKER_NUMBER`].
const MARKER_PREFIX: &[u8] = b"\x1b]6973;";

/// The longest marker body, so a stray prefix without its terminator is not buffered forever.
const MARKER_MAX_BYTES: usize = 128;

/// Whether the server manages the shell's prompts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Managed,
    Raw,
}

/// What `view` a shell result shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum View {
    /// The rendered screen when a full-screen program is running, the output stream otherwise.
    Auto,
    Stream,
    Screen,
}

/// The shells of one connection.
#[derive(Default)]
pub(crate) struct ShellTable {
    last_number: u32,
    shells: BTreeMap<u32, Arc<Shell>>,
}

impl ShellTable {
    /// The shell numbered `number`.
    fn get(&self, number: u32) -> Result<Arc<Shell>, ToolError> {
        self.shells.get(&number).cloned().ok_or_else(|| {
            ToolError::new(format!(
                "This connection has no shell {number}. Use connection_status to see its shells."
            ))
        })
    }

    /// One line per shell, for the connection status.
    pub(crate) fn describe(&self) -> Vec<String> {
        self.shells
            .values()
            .map(|shell| {
                let state = shell.lock();
                let mode = match state.mode {
                    Mode::Managed => "managed",
                    Mode::Raw => "raw",
                };
                let activity = if state.closed.is_some() {
                    "exited".to_owned()
                } else if let Some(run) = &state.run {
                    format!(
                        "running `{}` for {}",
                        first_line(&run.command),
                        format_duration(run.started.elapsed())
                    )
                } else if state.mode == Mode::Managed && state.at_prompt {
                    "at the prompt".to_owned()
                } else {
                    "busy".to_owned()
                };
                format!(
                    "shell {} ({}, {mode}): {activity}",
                    shell.number, shell.program
                )
            })
            .collect()
    }
}

/// One persistent shell.
pub(crate) struct Shell {
    number: u32,
    program: String,
    nonce: String,
    writer: ChannelWriteHalf<Msg>,
    state: Mutex<ShellState>,
    changed: Notify,
}

/// A `shell_run` command the shell has not finished.
struct PendingRun {
    command: String,
    started: Instant,
    /// Lines of input the wrapped command spans; a complete command makes the shell print one
    /// continuation prompt fewer than this.
    lines: u64,
    continuation_base: u64,
    interrupted_as_incomplete: bool,
    /// `shell_send` typed into the shell while the command ran, so continuation prompts may be
    /// answers to that input rather than a sign the command is incomplete.
    typed_into: bool,
}

impl PendingRun {
    /// Whether the shell is still reading lines of the command (an unclosed quote, bracket or
    /// here-document) after all of them were sent, so it would wait for input forever.
    fn is_incomplete(&self, continuation_count: u64) -> bool {
        !self.interrupted_as_incomplete
            && !self.typed_into
            && continuation_count.saturating_sub(self.continuation_base) >= self.lines
    }

    /// How the command ended: with its exit code when the done marker reported one, interrupted
    /// when the prompt came back without it.
    fn outcome(self, code: Option<i32>) -> RunOutcome {
        if self.interrupted_as_incomplete {
            return RunOutcome::Incomplete {
                command: self.command,
            };
        }
        let elapsed = self.started.elapsed();
        match code {
            Some(code) => RunOutcome::Exited {
                command: self.command,
                code,
                elapsed,
            },
            None => RunOutcome::Interrupted {
                command: self.command,
                elapsed,
            },
        }
    }
}

/// How a `shell_run` command ended, reported once.
#[derive(Debug, PartialEq, Eq)]
enum RunOutcome {
    Exited {
        command: String,
        code: i32,
        elapsed: Duration,
    },
    Interrupted {
        command: String,
        elapsed: Duration,
    },
    Incomplete {
        command: String,
    },
}

impl RunOutcome {
    fn describe(&self) -> String {
        match self {
            Self::Exited {
                command,
                code,
                elapsed,
            } => format!(
                "`{}` exited with code {code} after {}",
                first_line(command),
                format_duration(*elapsed)
            ),
            Self::Interrupted { command, elapsed } => format!(
                "`{}` was interrupted after {}; its exit code is unknown",
                first_line(command),
                format_duration(*elapsed)
            ),
            Self::Incomplete { command } => format!(
                "`{}` was incomplete (an unclosed quote, bracket or here-document), so it was canceled",
                first_line(command)
            ),
        }
    }
}

struct ShellState {
    mode: Mode,
    /// The managed-mode setup line has been sent, so a prompt marker means the shell answered it.
    setup_sent: bool,
    /// The shell answered the setup after `shell_open` returned; the next result says so once.
    managed_late: bool,
    buffer: OutputBuffer,
    screen: vt100::Parser,
    osc: OscState,
    marker_carry: Vec<u8>,
    continuation_count: u64,
    prompt_count: u64,
    /// The buffer offset right after the most recent prompt marker.
    prompt_offset: u64,
    at_prompt: bool,
    /// A done or wake marker came, and the prompt the shell prints after it has not. That prompt
    /// ends no command, so it must not end one started in between.
    prompt_owed: bool,
    /// `shell_send` typed text at the prompt without ending the line, which a `shell_run` command
    /// would be appended to.
    typed_pending: bool,
    run: Option<PendingRun>,
    /// Outcomes no result has reported yet, oldest first.
    finished: VecDeque<RunOutcome>,
    closed: Option<String>,
    closed_reported: bool,
    last_output: Instant,
}

impl ShellState {
    fn new(rows: NonZeroU16, columns: NonZeroU16) -> Self {
        Self {
            mode: Mode::Raw,
            setup_sent: false,
            managed_late: false,
            buffer: OutputBuffer::new(),
            screen: vt100::Parser::new(rows, columns, 0),
            osc: OscState::Outside,
            marker_carry: Vec::new(),
            continuation_count: 0,
            prompt_count: 0,
            prompt_offset: 0,
            at_prompt: false,
            prompt_owed: false,
            typed_pending: false,
            run: None,
            finished: VecDeque::new(),
            closed: None,
            closed_reported: false,
            last_output: Instant::now(),
        }
    }

    /// Take in bytes the shell printed, with the markers carrying `nonce`.
    fn ingest(&mut self, bytes: &[u8], nonce: &str) {
        for piece in split_markers(&mut self.marker_carry, bytes, nonce) {
            match piece {
                Piece::Output(output) => {
                    self.buffer.append(&output);
                    self.screen.process(&screen_bytes(&mut self.osc, &output));
                    self.last_output = Instant::now();
                }
                Piece::Marker(Marker::Continuation) => self.continuation_count += 1,
                Piece::Marker(Marker::Done(code)) => {
                    // The prompt follows at once, and input sent before it is drawn waits in
                    // the terminal, so the shell counts as at its prompt from here.
                    self.at_prompt = true;
                    self.prompt_owed = true;
                    if let Some(run) = self.run.take() {
                        self.finished.push_back(run.outcome(Some(code)));
                    }
                }
                Piece::Marker(Marker::Wake) => self.prompt_owed = true,
                Piece::Marker(Marker::Prompt) => {
                    self.prompt_count += 1;
                    self.prompt_offset = self.buffer.end();
                    if self.mode == Mode::Raw && self.setup_sent {
                        self.mode = Mode::Managed;
                        self.managed_late = true;
                    }
                    if std::mem::take(&mut self.prompt_owed) {
                        continue;
                    }
                    self.at_prompt = true;
                    self.typed_pending = false;
                    if let Some(run) = self.run.take() {
                        self.finished.push_back(run.outcome(None));
                    }
                }
            }
        }
    }

    /// Record that `shell_run` is about to type `command`, whose wrapped form spans `lines`
    /// lines, refusing when the shell is not at a clean prompt.
    fn start_run(&mut self, number: u32, command: &str, lines: u64) -> Result<(), ToolError> {
        if self.mode == Mode::Raw {
            return Err(ToolError::new(format!(
                "Shell {number} is in raw mode, so it cannot report when a command ends; use shell_send and shell_read."
            )));
        }
        if let Some(closed) = &self.closed {
            return Err(ToolError::new(format!(
                "Shell {number} has exited ({closed})."
            )));
        }
        if let Some(run) = &self.run {
            return Err(ToolError::new(format!(
                "Shell {number} is still running `{}`. Use shell_read to wait for it, or shell_send with keys [\"ctrl+c\"] to interrupt it.",
                first_line(&run.command)
            )));
        }
        if !self.at_prompt {
            return Err(ToolError::new(format!(
                "Shell {number} is not at its prompt: a program is running in it. Use shell_read to watch it or shell_send to interact."
            )));
        }
        if self.typed_pending {
            return Err(ToolError::new(format!(
                "Shell {number} has a partly typed line, which the command would be appended to. Finish it with shell_send keys [\"enter\"], or clear it with keys [\"ctrl+u\"]."
            )));
        }
        self.at_prompt = false;
        self.run = Some(PendingRun {
            command: command.to_owned(),
            started: Instant::now(),
            lines,
            continuation_base: self.continuation_count,
            interrupted_as_incomplete: false,
            typed_into: false,
        });
        Ok(())
    }

    /// The result every shell tool returns: the state of shell `number`, then the output nobody
    /// has seen yet.
    fn report(
        &mut self,
        number: u32,
        view: View,
        max_output_bytes: usize,
        note: Option<String>,
    ) -> String {
        let mut lines = Vec::new();
        if let Some(note) = note {
            lines.push(note);
        }
        if std::mem::take(&mut self.managed_late) {
            lines.push(
                "the shell answered the managed-mode setup late, so it is now in managed mode: shell_run reports exit codes"
                    .to_owned(),
            );
        }
        lines.extend(self.finished.drain(..).map(|outcome| outcome.describe()));
        let use_screen = match view {
            View::Screen => true,
            View::Stream => false,
            View::Auto => self.screen.screen().alternate_screen(),
        };
        let mut body = String::new();
        let mut remaining = 0;
        if use_screen {
            let dropped = self.buffer.start.saturating_sub(self.buffer.reported);
            self.buffer.mark_reported();
            let screen = self.screen.screen();
            let (row, column) = screen.cursor_position();
            let contents = screen.contents();
            let contents = contents.trim_end_matches(['\n', ' ']);
            if dropped > 0 {
                body.push_str(&format!(
                    "\n[{} of output was dropped]",
                    format_size(dropped)
                ));
            }
            body.push_str(&format!(
                "\n--- screen (cursor at row {}, column {}; it replaces the output since the last result) ---\n{contents}",
                row + 1,
                column + 1
            ));
        } else {
            let (bytes, dropped, left) = self.buffer.take(max_output_bytes);
            remaining = left;
            if dropped > 0 {
                body.push_str(&format!(
                    "\n[{} of earlier output was dropped before it was read]",
                    format_size(dropped)
                ));
            }
            let cleaned = clean_terminal_text(&bytes);
            let cleaned = cleaned.trim_end_matches('\n');
            if !cleaned.trim().is_empty() {
                body.push('\n');
                body.push_str(cleaned);
            }
            if remaining > 0 {
                body.push_str(&format!(
                    "\n[{} more output is waiting; call shell_read]",
                    format_size(remaining)
                ));
            }
        }
        let at_managed_prompt = self.mode == Mode::Managed && self.at_prompt;
        if let Some(closed) = &self.closed {
            if remaining == 0 {
                lines.push(format!(
                    "the shell has exited ({closed}); shell {number} is gone"
                ));
                self.closed_reported = true;
            } else {
                lines.push(format!(
                    "the shell has exited ({closed}); read the rest of its output with shell_read"
                ));
            }
        } else if let Some(run) = &self.run {
            lines.push(format!(
                "`{}` is still running after {}; it keeps running, so use shell_read to wait for it or shell_send to interact",
                first_line(&run.command),
                format_duration(run.started.elapsed())
            ));
        } else if at_managed_prompt {
            lines.push("at the prompt".to_owned());
        } else if self.mode == Mode::Raw {
            lines.push("raw mode: there is no prompt detection".to_owned());
        } else {
            lines.push("a program is running".to_owned());
        }
        // A full-screen program's last line is screen content, not a question.
        let full_screen = self.screen.screen().alternate_screen();
        if self.closed.is_none()
            && !full_screen
            && !at_managed_prompt
            && self.last_output.elapsed() >= SETTLE
            && let Some(line) = waiting_prompt(&self.buffer)
        {
            lines.push(format!("possibly waiting for input: {line:?}"));
        }
        format!("[shell {number}: {}]{body}", lines.join("; "))
    }
}

/// Where the bytes passed to the terminal emulator stand relative to an OSC string, which the
/// emulator's parser buffers until it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OscState {
    Outside,
    /// After an escape character, which may start an OSC string.
    Escape,
    /// Inside an OSC string, with the bytes of it passed so far.
    Inside(usize),
    /// Inside an OSC string that was cut off; the rest of it is not passed.
    Skipping,
}

/// The bytes of `output` to pass to the terminal emulator: all of them, except that an OSC string
/// longer than [`MAX_OSC_BYTES`] is ended there with CAN and the rest of it left out. The parser
/// ends an OSC string at BEL, CAN, SUB or any escape character, and so does this.
fn screen_bytes(state: &mut OscState, output: &[u8]) -> Vec<u8> {
    let mut passed = Vec::with_capacity(output.len());
    for &byte in output {
        let (next, pass) = match (*state, byte) {
            (OscState::Inside(_), 0x07 | 0x18 | 0x1a) => (OscState::Outside, Some(byte)),
            (OscState::Skipping, 0x07 | 0x18 | 0x1a) => (OscState::Outside, None),
            (_, 0x1b) => (OscState::Escape, Some(byte)),
            (OscState::Escape, b']') => (OscState::Inside(0), Some(byte)),
            // The parser carries out these control characters inside an escape sequence and
            // stays in it.
            (OscState::Escape, 0x00..=0x17 | 0x19 | 0x1c..=0x1f) => (OscState::Escape, Some(byte)),
            (OscState::Inside(length), _) if length >= MAX_OSC_BYTES => {
                (OscState::Skipping, Some(0x18))
            }
            (OscState::Inside(length), _) => (OscState::Inside(length + 1), Some(byte)),
            (OscState::Skipping, _) => (OscState::Skipping, None),
            (OscState::Outside | OscState::Escape, _) => (OscState::Outside, Some(byte)),
        };
        *state = next;
        passed.extend(pass);
    }
    passed
}

/// Output not yet reported, addressed by absolute byte offsets since the shell opened.
struct OutputBuffer {
    data: VecDeque<u8>,
    start: u64,
    reported: u64,
}

impl OutputBuffer {
    fn new() -> Self {
        Self {
            data: VecDeque::new(),
            start: 0,
            reported: 0,
        }
    }

    fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    fn append(&mut self, bytes: &[u8]) {
        self.data.extend(bytes);
        let excess = self.data.len().saturating_sub(BUFFER_BYTES);
        if excess > 0 {
            self.data.drain(..excess);
            self.start += excess as u64;
        }
    }

    /// Bytes from `from` up to `to` that are still held.
    fn between(&self, from: u64, to: u64) -> Vec<u8> {
        let index = |offset: u64| {
            usize::try_from(offset.saturating_sub(self.start))
                .unwrap_or(usize::MAX)
                .min(self.data.len())
        };
        let (first, last) = (index(from), index(to));
        if first >= last {
            return Vec::new();
        }
        self.data.range(first..last).copied().collect()
    }

    /// Bytes from `from` to the end that are still held.
    fn since(&self, from: u64) -> Vec<u8> {
        self.between(from, self.end())
    }

    /// The last `bytes` bytes held.
    fn tail(&self, bytes: usize) -> Vec<u8> {
        self.since(self.end().saturating_sub(bytes as u64))
    }

    /// Take up to `limit` unreported bytes, cut after a newline when the limit cuts the output.
    /// Returns the bytes, how many bytes were dropped before they could be reported, and how
    /// many remain unreported.
    fn take(&mut self, limit: usize) -> (Vec<u8>, u64, u64) {
        let dropped = self.start.saturating_sub(self.reported);
        self.reported = self.reported.max(self.start);
        let mut bytes = self.since(self.reported);
        if bytes.len() > limit {
            bytes.truncate(limit);
            match bytes.iter().rposition(|byte| *byte == b'\n') {
                Some(newline) => bytes.truncate(newline + 1),
                None => bytes.truncate(complete_utf8_prefix(&bytes)),
            }
        }
        self.reported += bytes.len() as u64;
        (bytes, dropped, self.end() - self.reported)
    }

    fn mark_reported(&mut self) {
        self.reported = self.end();
    }
}

/// The length of `bytes` without a UTF-8 character cut off at its end, so a limited read never
/// splits one character across two results.
fn complete_utf8_prefix(bytes: &[u8]) -> usize {
    let tail_start = bytes.len().saturating_sub(3);
    for index in (tail_start..bytes.len()).rev() {
        let byte = bytes.get(index).copied().unwrap_or_default();
        if byte & 0xc0 == 0x80 {
            continue;
        }
        let length = match byte {
            0xf0..=0xf7 => 4,
            0xe0..=0xef => 3,
            0xc0..=0xdf => 2,
            _ => 1,
        };
        return if index + length > bytes.len() {
            index
        } else {
            bytes.len()
        };
    }
    bytes.len()
}

/// A marker the shell printed.
#[derive(Debug, PartialEq, Eq)]
enum Marker {
    Prompt,
    Continuation,
    Done(i32),
    /// Printed by the line sent to wake a shell while an incomplete command is canceled; the
    /// prompt after it ends no command.
    Wake,
}

/// A piece of what the shell printed, in order.
#[derive(Debug, PartialEq, Eq)]
enum Piece {
    Output(Vec<u8>),
    Marker(Marker),
}

/// Split `incoming` into output and markers carrying `nonce`. Bytes that may be the start of a
/// marker split across reads are held in `carry` until the next call; markers with another nonce
/// are removed without effect, so output cannot fake a prompt.
fn split_markers(carry: &mut Vec<u8>, incoming: &[u8], nonce: &str) -> Vec<Piece> {
    let mut data = std::mem::take(carry);
    data.extend_from_slice(incoming);
    let mut pieces = Vec::new();
    let mut output = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let rest = data.get(index..).unwrap_or_default();
        if rest.first() == Some(&0x1b) {
            if rest.len() < MARKER_PREFIX.len() && MARKER_PREFIX.starts_with(rest) {
                carry.extend_from_slice(rest);
                break;
            }
            if rest.starts_with(MARKER_PREFIX) {
                let body_start = MARKER_PREFIX.len();
                match rest
                    .iter()
                    .skip(body_start)
                    .take(MARKER_MAX_BYTES)
                    .position(|byte| *byte == 0x07)
                {
                    Some(length) => {
                        let body = rest
                            .get(body_start..body_start + length)
                            .unwrap_or_default();
                        if let Some(marker) = parse_marker(body, nonce) {
                            if !output.is_empty() {
                                pieces.push(Piece::Output(std::mem::take(&mut output)));
                            }
                            pieces.push(Piece::Marker(marker));
                        }
                        index += body_start + length + 1;
                        continue;
                    }
                    None if rest.len() <= body_start + MARKER_MAX_BYTES => {
                        carry.extend_from_slice(rest);
                        break;
                    }
                    None => {}
                }
            }
        }
        output.push(data.get(index).copied().unwrap_or_default());
        index += 1;
    }
    if !output.is_empty() {
        pieces.push(Piece::Output(output));
    }
    pieces
}

fn parse_marker(body: &[u8], nonce: &str) -> Option<Marker> {
    let body = std::str::from_utf8(body).ok()?;
    let mut fields = body.split(';');
    let kind = fields.next()?;
    if fields.next()? != nonce {
        return None;
    }
    match kind {
        "P" => Some(Marker::Prompt),
        "C" => Some(Marker::Continuation),
        "D" => fields.next()?.trim().parse().ok().map(Marker::Done),
        "W" => Some(Marker::Wake),
        _ => None,
    }
}

/// The shell command that prints the marker of `kind`.
fn marker_command(kind: &str, nonce: &str) -> String {
    format!("printf '\\033]{MARKER_NUMBER};{kind};{nonce}\\007'")
}

/// The setup line sent to a shell that should be managed. It is valid in every POSIX shell
/// (shell-specific syntax goes through `eval`), and it turns off echo and line editing so input
/// is not repeated in the output, sets the prompts to markers, and sets the pagers to `cat` so
/// commands like `git log` and `systemctl status` do not stop in `less`.
fn setup_line(nonce: &str) -> String {
    format!(
        "stty -echo 2>/dev/null; \
         if [ -n \"$BASH_VERSION\" ]; then set +o emacs +o vi; unset PROMPT_COMMAND PS0; fi; \
         if [ -n \"$ZSH_VERSION\" ]; then eval 'unsetopt zle prompt_cr prompt_sp; precmd_functions=(); RPROMPT=\"\"'; fi; \
         PS1=\"$({prompt})\"; \
         PS2=\"$({continuation})\"; \
         export PAGER=cat GIT_PAGER=cat SYSTEMD_PAGER=cat\n",
        prompt = marker_command("P", nonce),
        continuation = marker_command("C", nonce),
    )
}

/// The line sent to wake a shell that may be waiting for a line before it acts on ctrl+c.
fn wake_line(nonce: &str) -> String {
    format!("{}\n", marker_command("W", nonce))
}

/// The longest command line `shell_run` types as it is. A terminal that reads whole lines, as a
/// managed shell's does with its line editor off, holds at most 4095 bytes of one line and drops
/// the rest, so a command with a longer line is sent in pieces the shell joins and evaluates.
const MAX_TYPED_LINE_BYTES: usize = 1024;

/// The characters of a long command in each piece, before quoting.
const COMMAND_PIECE_CHARS: usize = 256;

/// Wrap a `shell_run` command so the shell prints its exit code after it. The braces run it in
/// the shell itself, so `cd` and `export` persist.
fn wrap_command(command: &str, nonce: &str) -> String {
    // The terminal turns a carriage return into a newline, so the shell sees one either way.
    let command = command.replace("\r\n", "\n").replace('\r', "\n");
    let command = command.trim_end_matches('\n');
    let done = format!("printf '\\033]{MARKER_NUMBER};D;{nonce};%d\\007' \"$?\"");
    if command
        .lines()
        .all(|line| line.len() <= MAX_TYPED_LINE_BYTES)
    {
        return format!("{{ {command}\n}}; {done}\n");
    }
    let mut wrapped = String::from("{ __ssh_mcp_command=''\n");
    let characters: Vec<char> = command.chars().collect();
    for piece in characters.chunks(COMMAND_PIECE_CHARS) {
        let piece: String = piece.iter().collect();
        wrapped.push_str(&format!(
            "__ssh_mcp_command=\"$__ssh_mcp_command\"'{}'\n",
            piece.replace('\'', "'\\''")
        ));
    }
    wrapped.push_str(&format!(
        "eval \"$__ssh_mcp_command\"\n}}; {done}; unset __ssh_mcp_command\n"
    ));
    wrapped
}

fn first_line(command: &str) -> String {
    let line = command.lines().next().unwrap_or("");
    let shortened: String = line.chars().take(COMMAND_LABEL_CHARS).collect();
    if shortened.len() < line.len() || command.lines().nth(1).is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

impl Shell {
    fn lock(&self) -> MutexGuard<'_, ShellState> {
        lock(&self.state)
    }

    fn mark_closed(&self, description: String) {
        let mut state = self.lock();
        if state.closed.is_none() {
            state.closed = Some(description);
        }
    }

    /// Send `bytes` to the shell, giving up after [`WRITE_TIMEOUT`] or when `cancel` fires.
    async fn write(
        &self,
        bytes: &[u8],
        cancel: Option<&CancellationToken>,
    ) -> Result<(), ToolError> {
        let canceled = async {
            match cancel {
                Some(cancel) => cancel.cancelled().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            written = tokio::time::timeout(WRITE_TIMEOUT, self.writer.data(bytes)) => match written {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(ToolError::new(format!(
                    "Input could not be sent to the shell: {error}"
                ))),
                Err(_) => Err(ToolError::new(format!(
                    "The shell did not take the input within {}: the program in it is not reading its terminal. Part of the input may have been typed.",
                    format_duration(WRITE_TIMEOUT)
                ))),
            },
            () = canceled => Err(ToolError::new(
                "The call was canceled while the input was being sent; part of it may have been typed.",
            )),
        }
    }

    /// Wait until `check` says so, `deadline` passes, or `cancel` fires, reporting the last line of
    /// output as progress. `check` returns `None` when done, or the time to look again even if
    /// nothing changes.
    async fn wait<F>(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
        progress: &mut Progress,
        mut check: F,
    ) -> WaitEnd
    where
        F: FnMut(&ShellState) -> Option<Option<Instant>>,
    {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (recheck_at, status_line) = {
                let state = self.lock();
                match check(&state) {
                    None => return WaitEnd::Done,
                    Some(at) => (at, last_output_line(&state.buffer.tail(STATUS_TAIL_BYTES))),
                }
            };
            if let Some(line) = status_line {
                progress.report(&line).await;
            }
            let mut wake = deadline.min(Instant::now() + PROGRESS_INTERVAL);
            if let Some(at) = recheck_at {
                wake = wake.min(at);
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {
                    if Instant::now() >= deadline {
                        return WaitEnd::TimedOut;
                    }
                }
                () = cancel.cancelled() => return WaitEnd::Canceled,
            }
        }
    }

    /// Wait up to `limit` for the pending `shell_run` command to end. Returns whether it did.
    async fn wait_for_run_end(&self, limit: Duration) -> bool {
        // The steps that cancel an incomplete command finish even when the call is canceled, so
        // the shell is not left halfway.
        let never = CancellationToken::new();
        let end = self
            .wait(
                Instant::now() + limit,
                &never,
                &mut Progress::none(),
                |state| {
                    if state.run.is_none() || state.closed.is_some() {
                        None
                    } else {
                        Some(None)
                    }
                },
            )
            .await;
        matches!(end, WaitEnd::Done)
    }

    /// Cancel the pending `shell_run` command when the shell is still reading lines of it after
    /// all were sent: ctrl+c, then, when no prompt follows within [`INTERRUPT_SETTLE`], a line
    /// that prints a wake marker. zsh without its line editor takes ctrl+c at a continuation
    /// prompt silently and acts on it when the next line arrives, discarding that line; a shell
    /// that acted on ctrl+c already runs the line, and its wake marker keeps the prompt after it
    /// from ending a later command. Returns whether the command was incomplete.
    async fn cancel_if_incomplete(&self) -> Result<bool, ToolError> {
        {
            let mut guard = self.lock();
            let state = &mut *guard;
            match state.run.as_mut() {
                Some(run)
                    if state.closed.is_none() && run.is_incomplete(state.continuation_count) =>
                {
                    run.interrupted_as_incomplete = true;
                }
                _ => return Ok(false),
            }
        }
        self.write(b"\x03", None).await?;
        if self.wait_for_run_end(INTERRUPT_SETTLE).await {
            return Ok(true);
        }
        self.write(wake_line(&self.nonce).as_bytes(), None).await?;
        self.wait_for_run_end(INTERRUPT_SETTLE).await;
        Ok(true)
    }

    fn report(&self, view: View, max_output_bytes: usize, note: Option<String>) -> String {
        self.lock()
            .report(self.number, view, max_output_bytes, note)
    }
}

enum WaitEnd {
    Done,
    TimedOut,
    Canceled,
}

/// An `until` pattern searched for in the output from `start` on. Each search covers only what
/// arrived since the last one, plus [`UNTIL_OVERLAP_BYTES`] before it for a match that spans the
/// two, so a long wait on streaming output does not search the same output over and over.
struct UntilSearch {
    pattern: Regex,
    start: u64,
    searched_to: Option<u64>,
}

impl UntilSearch {
    fn new(pattern: Regex, start: u64) -> Self {
        Self {
            pattern,
            start,
            searched_to: None,
        }
    }

    fn matches(&mut self, buffer: &OutputBuffer) -> bool {
        let end = buffer.end();
        let from = match self.searched_to {
            Some(searched_to) if searched_to == end => return false,
            Some(searched_to) => searched_to
                .saturating_sub(UNTIL_OVERLAP_BYTES)
                .max(self.start),
            None => self.start,
        };
        self.searched_to = Some(end);
        self.pattern
            .is_match(&clean_terminal_text(&buffer.since(from)))
    }
}

/// The unfinished last line of output when it looks like a question: output that stopped without
/// a newline, such as `Password:` or `[Y/n]`.
fn waiting_prompt(buffer: &OutputBuffer) -> Option<String> {
    let tail = buffer.tail(STATUS_TAIL_BYTES);
    if tail.ends_with(b"\n") {
        return None;
    }
    let text = clean_terminal_text(&tail);
    let line = text.rsplit('\n').next()?.trim_end();
    if line.is_empty() {
        return None;
    }
    let skip = line.chars().count().saturating_sub(QUESTION_CHARS);
    Some(line.chars().skip(skip).collect())
}

/// What `shell_open` needs.
pub(crate) struct OpenRequest {
    /// The program to run instead of the login shell.
    pub(crate) command: Option<String>,
    /// Leave the terminal as the program sets it up.
    pub(crate) raw: bool,
    /// Terminal width.
    pub(crate) columns: u16,
    /// Terminal height.
    pub(crate) rows: u16,
}

/// Open a shell on `handle` and add it to `table`.
pub(crate) async fn open(
    handle: &SshHandle,
    table: &Mutex<ShellTable>,
    request: OpenRequest,
    cancel: &CancellationToken,
) -> Result<String, ToolError> {
    let size = |argument: &str, value: u16| {
        NonZeroU16::new(value)
            .filter(|value| value.get() <= MAX_TERMINAL_SIDE)
            .ok_or_else(|| {
                ToolError::new(format!("{argument} must be from 1 to {MAX_TERMINAL_SIDE}"))
            })
    };
    let columns = size("columns", request.columns)?;
    let rows = size("rows", request.rows)?;
    let nonce = random_hex(8)?;
    let channel = open_session_channel(handle, cancel).await?;
    bounded(
        REQUEST_TIMEOUT,
        "request a terminal",
        channel.request_pty(
            false,
            "xterm-256color",
            u32::from(request.columns),
            u32::from(request.rows),
            0,
            0,
            &[],
        ),
    )
    .await?;
    let program = match &request.command {
        Some(command) => {
            bounded(
                REQUEST_TIMEOUT,
                "start the program",
                channel.exec(false, command.as_bytes()),
            )
            .await?;
            first_line(command)
        }
        None => {
            bounded(
                REQUEST_TIMEOUT,
                "start the shell",
                channel.request_shell(false),
            )
            .await?;
            "login shell".to_owned()
        }
    };
    let (mut reader, writer) = channel.split();

    let shell = {
        let mut table = lock(table);
        table.last_number += 1;
        let number = table.last_number;
        let shell = Arc::new(Shell {
            number,
            program,
            nonce,
            writer,
            state: Mutex::new(ShellState::new(rows, columns)),
            changed: Notify::new(),
        });
        table.shells.insert(number, Arc::clone(&shell));
        shell
    };

    tokio::spawn({
        let shell = Arc::clone(&shell);
        async move {
            let mut exit = None;
            loop {
                match reader.wait().await {
                    Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. }) => {
                        shell.lock().ingest(&data, &shell.nonce);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit = Some(format!("exit status {exit_status}"));
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        exit = Some(format!("killed by signal {}", signal_label(&signal_name)));
                    }
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
                shell.changed.notify_waiters();
            }
            shell.mark_closed(exit.unwrap_or_else(|| "the channel closed".to_owned()));
            shell.changed.notify_waiters();
        }
    });

    let canceled = "Opening the shell was canceled, so it was closed.";
    let mut progress = Progress::none();
    let opened = Instant::now();
    let settled = shell
        .wait(opened + OPEN_WAIT, cancel, &mut progress, |state| {
            if state.closed.is_some() {
                return None;
            }
            if state.buffer.end() > 0 {
                let settled_at = state.last_output + LOGIN_SETTLE;
                if Instant::now() >= settled_at {
                    return None;
                }
                return Some(Some(settled_at));
            }
            Some(None)
        })
        .await;
    if matches!(settled, WaitEnd::Canceled) {
        abandon(table, &shell).await;
        return Err(ToolError::new(canceled));
    }

    let ended_silently = {
        let state = shell.lock();
        state.closed.clone().filter(|_| state.buffer.end() == 0)
    };
    if let Some(ended) = ended_silently {
        lock(table).shells.remove(&shell.number);
        return Err(ToolError::new(format!(
            "The shell ended as soon as it started ({ended}) without printing anything; the server may have refused the terminal."
        )));
    }

    let login_output_end = shell.lock().buffer.end();
    let mut note = None;
    if !request.raw && shell.lock().closed.is_none() {
        shell.lock().setup_sent = true;
        if let Err(error) = shell
            .write(setup_line(&shell.nonce).as_bytes(), Some(cancel))
            .await
        {
            abandon(table, &shell).await;
            return Err(error);
        }
        let answered = shell
            .wait(Instant::now() + OPEN_WAIT, cancel, &mut progress, |state| {
                if state.mode == Mode::Managed || state.closed.is_some() {
                    None
                } else {
                    Some(None)
                }
            })
            .await;
        if matches!(answered, WaitEnd::Canceled) {
            abandon(table, &shell).await;
            return Err(ToolError::new(canceled));
        }
        let login_output = {
            let mut state = shell.lock();
            if state.mode == Mode::Managed {
                // The output before the first prompt is the login output, then the setup line's
                // echo, which is left out.
                state.managed_late = false;
                state.buffer.reported = state.buffer.reported.max(state.prompt_offset);
                Some(state.buffer.between(0, login_output_end))
            } else {
                None
            }
        };
        if let Some(login_output) = login_output {
            let login_text = clean_terminal_text(&login_output);
            let login_text = login_text.trim();
            let mut text = format!(
                "[shell {}: opened in managed mode; shell_run reports exit codes; at the prompt]",
                shell.number
            );
            if !login_text.is_empty() {
                text.push_str("\n--- login output ---\n");
                text.push_str(login_text);
            }
            return Ok(text);
        }
        note = Some(format!(
            "the shell did not answer the managed-mode setup within {} (it may not be a POSIX shell, or it starts slowly), so it is in raw mode: use shell_send and shell_read. If it answers later, a result says it switched to managed mode",
            format_duration(OPEN_WAIT)
        ));
    }
    let opened_note = match note {
        Some(note) => format!("opened; {note}"),
        None => "opened in raw mode".to_owned(),
    };
    let text = shell.report(View::Auto, UNREQUESTED_OUTPUT_BYTES, Some(opened_note));
    forget_if_reported(table, &shell);
    Ok(text)
}

/// Remove a shell whose opening failed from `table` and close it.
async fn abandon(table: &Mutex<ShellTable>, shell: &Shell) {
    lock(table).shells.remove(&shell.number);
    best_effort(
        CLOSE_TIMEOUT,
        "closing the abandoned shell",
        shell.writer.close(),
    )
    .await;
}

/// Forget a shell whose exit the result being returned has reported.
fn forget_if_reported(table: &Mutex<ShellTable>, shell: &Shell) {
    if shell.lock().closed_reported {
        lock(table).shells.remove(&shell.number);
    }
}

/// Look up shell `number` in `table`.
fn find(table: &Mutex<ShellTable>, number: u32) -> Result<Arc<Shell>, ToolError> {
    lock(table).get(number)
}

/// What `shell_run` needs.
pub(crate) struct RunRequest {
    /// The command line, which may span several lines.
    pub(crate) command: String,
    /// How long to wait for it to finish.
    pub(crate) wait: Duration,
    /// The most output the result returns.
    pub(crate) max_output_bytes: usize,
}

/// Run a command in a managed shell and wait for it up to `request.wait`. A canceled call leaves
/// the command running and its output and outcome unread.
pub(crate) async fn run(
    table: &Mutex<ShellTable>,
    number: u32,
    request: RunRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let shell = find(table, number)?;
    if request.command.trim().is_empty() {
        return Err(ToolError::new("command is empty"));
    }
    let wrapped = wrap_command(&request.command, &shell.nonce);
    shell.lock().start_run(
        number,
        &request.command,
        wrapped.matches('\n').count() as u64,
    )?;
    if let Err(error) = shell.write(wrapped.as_bytes(), None).await {
        // The command may be partly typed, so the shell is not taken to be at its prompt.
        shell.lock().run = None;
        return Err(error);
    }

    let deadline = Instant::now() + request.wait;
    loop {
        let end = shell
            .wait(deadline, cancel, progress, |state| {
                let Some(run) = &state.run else {
                    return None;
                };
                if state.closed.is_some() || run.is_incomplete(state.continuation_count) {
                    None
                } else {
                    Some(None)
                }
            })
            .await;
        match end {
            WaitEnd::Done => {
                if !shell.cancel_if_incomplete().await? {
                    break;
                }
            }
            WaitEnd::TimedOut => break,
            WaitEnd::Canceled => {
                return Err(ToolError::new(
                    "The call was canceled. Nothing was interrupted: the command's output and outcome wait for shell_read.",
                ));
            }
        }
    }
    let text = shell.report(View::Auto, request.max_output_bytes, None);
    forget_if_reported(table, &shell);
    Ok(text)
}

/// What `shell_send` needs.
pub(crate) struct SendRequest {
    /// Text typed as it is.
    pub(crate) text: Option<String>,
    /// Keys pressed after the text.
    pub(crate) keys: Vec<String>,
    /// A regex to wait for in the output that follows.
    pub(crate) until: Option<String>,
    /// The most time to wait.
    pub(crate) wait: Duration,
    /// The most output the result returns.
    pub(crate) max_output_bytes: usize,
}

/// Type into a shell and wait for its answer.
pub(crate) async fn send(
    table: &Mutex<ShellTable>,
    number: u32,
    request: SendRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let shell = find(table, number)?;
    let until = compile_until(request.until.as_deref())?;
    let application_cursor = shell.lock().screen.screen().application_cursor();
    let mut bytes = request.text.clone().unwrap_or_default().into_bytes();
    for key in &request.keys {
        bytes.extend(key_bytes(key, application_cursor).ok_or_else(|| {
            ToolError::new(format!(
                "Unknown key \"{key}\". Keys are enter, tab, escape, backspace, delete, insert, space, up, down, left, right, home, end, page_up, page_down, f1 to f12, and ctrl+ a letter."
            ))
        })?);
    }
    if bytes.is_empty() {
        return Err(ToolError::new("Pass text, keys, or both."));
    }
    let start = {
        let mut guard = shell.lock();
        let state = &mut *guard;
        if let Some(closed) = &state.closed {
            return Err(ToolError::new(format!(
                "Shell {number} has exited ({closed})."
            )));
        }
        if state.mode == Mode::Managed && state.at_prompt {
            for byte in &bytes {
                match byte {
                    b'\r' | b'\n' => {
                        state.at_prompt = false;
                        state.typed_pending = false;
                        break;
                    }
                    // ctrl+u clears the line, and ctrl+c abandons it for a new prompt.
                    0x15 | 0x03 => state.typed_pending = false,
                    _ => state.typed_pending = true,
                }
            }
        }
        if let Some(run) = state.run.as_mut() {
            run.typed_into = true;
        }
        state.buffer.end()
    };
    shell.write(&bytes, Some(cancel)).await?;
    let sent_at = Instant::now();
    let mut until = until.map(|pattern| UntilSearch::new(pattern, start));
    let end = shell
        .wait(sent_at + request.wait, cancel, progress, |state| {
            if state.closed.is_some() {
                return None;
            }
            if let Some(until) = until.as_mut() {
                return if until.matches(&state.buffer) {
                    None
                } else {
                    Some(None)
                };
            }
            let settled_at = state.last_output.max(sent_at) + SETTLE;
            if Instant::now() >= settled_at {
                None
            } else {
                Some(Some(settled_at))
            }
        })
        .await;
    if matches!(end, WaitEnd::Canceled) {
        return Err(ToolError::new(
            "The call was canceled after the input was sent; the output waits for shell_read.",
        ));
    }
    let text = shell.report(View::Auto, request.max_output_bytes, None);
    forget_if_reported(table, &shell);
    Ok(text)
}

/// What `shell_read` needs.
pub(crate) struct ReadRequest {
    /// A regex to wait for in the output not yet returned.
    pub(crate) until: Option<String>,
    /// The most time to wait.
    pub(crate) wait: Duration,
    /// Whether to show the output stream or the rendered screen.
    pub(crate) view: View,
    /// The most output the result returns.
    pub(crate) max_output_bytes: usize,
}

/// Report a shell's state and new output, waiting up to `request.wait` for something to happen.
/// A `shell_run` command found incomplete is canceled, as `shell_run` itself would have.
pub(crate) async fn read(
    table: &Mutex<ShellTable>,
    number: u32,
    request: ReadRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let shell = find(table, number)?;
    let until = compile_until(request.until.as_deref())?;
    if !request.wait.is_zero() {
        let (start, end_before) = {
            let state = shell.lock();
            (
                state.buffer.reported.max(state.buffer.start),
                state.buffer.end(),
            )
        };
        let mut until = until.map(|pattern| UntilSearch::new(pattern, start));
        let called_at = Instant::now();
        let end = shell
            .wait(called_at + request.wait, cancel, progress, |state| {
                if state.closed.is_some() || !state.finished.is_empty() {
                    return None;
                }
                if state
                    .run
                    .as_ref()
                    .is_some_and(|run| run.is_incomplete(state.continuation_count))
                {
                    return None;
                }
                if let Some(until) = until.as_mut() {
                    return if until.matches(&state.buffer) {
                        None
                    } else {
                        Some(None)
                    };
                }
                if state.run.is_some() {
                    return Some(None);
                }
                if state.buffer.end() > end_before {
                    let settled_at = state.last_output + SETTLE;
                    if Instant::now() >= settled_at {
                        return None;
                    }
                    return Some(Some(settled_at));
                }
                Some(None)
            })
            .await;
        if matches!(end, WaitEnd::Canceled) {
            return Err(ToolError::new(
                "The call was canceled; the output waits for the next shell_read.",
            ));
        }
    }
    shell.cancel_if_incomplete().await?;
    let text = shell.report(request.view, request.max_output_bytes, None);
    forget_if_reported(table, &shell);
    Ok(text)
}

/// Close a shell, reporting the output nobody has read.
pub(crate) async fn close(table: &Mutex<ShellTable>, number: u32) -> Result<String, ToolError> {
    let shell = lock(table)
        .shells
        .remove(&number)
        .ok_or_else(|| ToolError::new(format!("This connection has no shell {number}.")))?;
    let (bytes, dropped, remaining) = shell.lock().buffer.take(UNREQUESTED_OUTPUT_BYTES);
    best_effort(CLOSE_TIMEOUT, "closing the shell", shell.writer.close()).await;
    let mut text = format!("[shell {number}: closed]");
    if dropped > 0 {
        text.push_str(&format!(
            "\n[{} of earlier output was dropped before it was read]",
            format_size(dropped)
        ));
    }
    let unread = clean_terminal_text(&bytes);
    let unread = unread.trim_end_matches('\n');
    if !unread.is_empty() {
        text.push_str("\n--- output not read before closing ---\n");
        text.push_str(unread);
    }
    if remaining > 0 {
        text.push_str(&format!(
            "\n[{} more output was discarded]",
            format_size(remaining)
        ));
    }
    Ok(text)
}

fn compile_until(until: Option<&str>) -> Result<Option<Regex>, ToolError> {
    until
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|error| ToolError::new(format!("until is not a valid regex: {error}")))
        })
        .transpose()
}
/// The bytes a terminal sends for a named key, or `None` for a name it does not know.
/// `application_cursor` is the mode full-screen programs switch the arrow keys into.
fn key_bytes(name: &str, application_cursor: bool) -> Option<Vec<u8>> {
    let name = name.trim().to_ascii_lowercase();
    if let Some(letter) = name.strip_prefix("ctrl+") {
        let mut characters = letter.chars();
        let character = characters.next()?;
        if characters.next().is_some() {
            return None;
        }
        return match character {
            'a'..='z' => Some(vec![character as u8 - b'a' + 1]),
            '[' => Some(vec![0x1b]),
            '\\' => Some(vec![0x1c]),
            ']' => Some(vec![0x1d]),
            _ => None,
        };
    }
    let arrow = |letter: u8| {
        if application_cursor {
            vec![0x1b, b'O', letter]
        } else {
            vec![0x1b, b'[', letter]
        }
    };
    let sequence: Vec<u8> = match name.as_str() {
        "enter" | "return" => b"\r".to_vec(),
        "tab" => b"\t".to_vec(),
        "escape" | "esc" => b"\x1b".to_vec(),
        "backspace" => b"\x7f".to_vec(),
        "space" => b" ".to_vec(),
        "up" => arrow(b'A'),
        "down" => arrow(b'B'),
        "right" => arrow(b'C'),
        "left" => arrow(b'D'),
        "home" => b"\x1b[H".to_vec(),
        "end" => b"\x1b[F".to_vec(),
        "insert" => b"\x1b[2~".to_vec(),
        "delete" => b"\x1b[3~".to_vec(),
        "page_up" => b"\x1b[5~".to_vec(),
        "page_down" => b"\x1b[6~".to_vec(),
        "f1" => b"\x1bOP".to_vec(),
        "f2" => b"\x1bOQ".to_vec(),
        "f3" => b"\x1bOR".to_vec(),
        "f4" => b"\x1bOS".to_vec(),
        "f5" => b"\x1b[15~".to_vec(),
        "f6" => b"\x1b[17~".to_vec(),
        "f7" => b"\x1b[18~".to_vec(),
        "f8" => b"\x1b[19~".to_vec(),
        "f9" => b"\x1b[20~".to_vec(),
        "f10" => b"\x1b[21~".to_vec(),
        "f11" => b"\x1b[23~".to_vec(),
        "f12" => b"\x1b[24~".to_vec(),
        _ => return None,
    };
    Some(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef";

    fn marker(kind: &str, extra: &str) -> Vec<u8> {
        format!("\x1b]6973;{kind};{NONCE}{extra}\x07").into_bytes()
    }

    #[test]
    fn markers_are_split_from_output_in_order() {
        let mut carry = Vec::new();
        let mut input = b"hello\r\n".to_vec();
        input.extend(marker("D", ";3"));
        input.extend(marker("P", ""));
        input.extend(b"after");
        let pieces = split_markers(&mut carry, &input, NONCE);
        assert_eq!(pieces, vec![
            Piece::Output(b"hello\r\n".to_vec()),
            Piece::Marker(Marker::Done(3)),
            Piece::Marker(Marker::Prompt),
            Piece::Output(b"after".to_vec()),
        ]);
        assert!(carry.is_empty());
    }

    #[test]
    fn a_marker_split_across_reads_is_reassembled() {
        let whole = marker("P", "");
        for split in 1..whole.len() {
            let mut carry = Vec::new();
            let (first, second) = whole.split_at(split);
            let mut pieces = split_markers(&mut carry, first, NONCE);
            pieces.extend(split_markers(&mut carry, second, NONCE));
            assert_eq!(
                pieces,
                vec![Piece::Marker(Marker::Prompt)],
                "split at {split}"
            );
        }
    }

    #[test]
    fn a_marker_with_another_nonce_has_no_effect() {
        let mut carry = Vec::new();
        let forged = b"\x1b]6973;P;ffffffffffffffff\x07text".to_vec();
        assert_eq!(split_markers(&mut carry, &forged, NONCE), vec![
            Piece::Output(b"text".to_vec())
        ]);
    }

    #[test]
    fn other_escape_sequences_pass_through() {
        let mut carry = Vec::new();
        let input = b"\x1b[31mred\x1b]0;title\x07".to_vec();
        assert_eq!(split_markers(&mut carry, &input, NONCE), vec![
            Piece::Output(input.clone())
        ]);
    }

    #[test]
    fn output_is_reported_exactly_once() {
        let mut buffer = OutputBuffer::new();
        buffer.append(b"one\ntwo\n");
        assert_eq!(buffer.take(1024).0, b"one\ntwo\n");
        assert!(buffer.take(1024).0.is_empty());
        buffer.append(b"three\n");
        assert_eq!(buffer.take(1024).0, b"three\n");
    }

    #[test]
    fn a_limited_take_cuts_after_a_newline_and_leaves_the_rest() {
        let mut buffer = OutputBuffer::new();
        buffer.append(b"line one\nline two\nline three\n");
        let (bytes, dropped, remaining) = buffer.take(12);
        assert_eq!(bytes, b"line one\n");
        assert_eq!(dropped, 0);
        assert_eq!(remaining, 20);
        assert_eq!(buffer.take(1024).0, b"line two\nline three\n");
    }

    #[test]
    fn overflow_reports_how_much_was_dropped() {
        let mut buffer = OutputBuffer::new();
        buffer.append(&vec![b'x'; BUFFER_BYTES + 10]);
        let (bytes, dropped, _) = buffer.take(usize::MAX);
        assert_eq!(dropped, 10);
        assert_eq!(bytes.len(), BUFFER_BYTES);
    }

    #[test]
    fn a_command_with_a_long_line_is_sent_in_short_lines() {
        let command = format!("printf '%s' '{}' | wc -c", "it's".repeat(2000));
        let wrapped = wrap_command(&command, NONCE);
        assert!(wrapped.lines().all(|line| line.len() < 4095), "{wrapped}");
        assert!(wrapped.contains("eval \"$__ssh_mcp_command\""));
        assert!(wrapped.ends_with("unset __ssh_mcp_command\n"));
    }

    #[test]
    fn a_lone_carriage_return_is_a_line_break() {
        assert_eq!(
            wrap_command("echo a\recho b", NONCE).matches('\n').count(),
            3
        );
    }

    #[test]
    fn a_cut_never_splits_a_character() {
        let text = "aé€😀".as_bytes();
        for end in 0..=text.len() {
            let prefix = text.get(..end).unwrap();
            let kept = complete_utf8_prefix(prefix);
            assert!(
                std::str::from_utf8(prefix.get(..kept).unwrap()).is_ok(),
                "end {end}"
            );
            assert!(end - kept < 4);
        }
    }

    #[test]
    fn a_stray_marker_prefix_does_not_swallow_later_output() {
        let mut carry = Vec::new();
        let mut input = b"\x1b]6973;".to_vec();
        input.extend(vec![b'x'; 300]);
        input.extend(b"\x07tail");
        let output: Vec<u8> = split_markers(&mut carry, &input, NONCE)
            .into_iter()
            .flat_map(|piece| match piece {
                Piece::Output(bytes) => bytes,
                Piece::Marker(_) => Vec::new(),
            })
            .collect();
        assert_eq!(output, input);
    }

    #[test]
    fn a_wrapped_command_keeps_its_lines_and_ends_with_the_done_marker() {
        let wrapped = wrap_command("cd /tmp\r\nls\n", NONCE);
        assert_eq!(
            wrapped,
            format!("{{ cd /tmp\nls\n}}; printf '\\033]6973;D;{NONCE};%d\\007' \"$?\"\n")
        );
        assert_eq!(wrapped.matches('\n').count(), 3);
    }

    #[test]
    fn keys_map_to_terminal_sequences() {
        assert_eq!(key_bytes("ctrl+c", false), Some(vec![3]));
        assert_eq!(key_bytes("Enter", false), Some(b"\r".to_vec()));
        assert_eq!(key_bytes("up", false), Some(b"\x1b[A".to_vec()));
        assert_eq!(key_bytes("up", true), Some(b"\x1bOA".to_vec()));
        assert_eq!(key_bytes("f5", false), Some(b"\x1b[15~".to_vec()));
        assert_eq!(key_bytes("ctrl+cc", false), None);
        assert_eq!(key_bytes("hyper", false), None);
    }

    #[test]
    fn a_question_without_a_newline_is_noticed() {
        let mut buffer = OutputBuffer::new();
        buffer.append(b"Reading lists\r\nDo you want to continue? [Y/n] ");
        assert_eq!(
            waiting_prompt(&buffer).as_deref(),
            Some("Do you want to continue? [Y/n]")
        );
        buffer.append(b"\r\n");
        assert_eq!(waiting_prompt(&buffer), None);
    }

    fn state() -> ShellState {
        let side = NonZeroU16::new(40).unwrap();
        ShellState::new(side, side)
    }

    /// A managed shell at its prompt, as `shell_open` leaves it.
    fn managed() -> ShellState {
        let mut state = state();
        state.setup_sent = true;
        state.ingest(&marker("P", ""), NONCE);
        state.managed_late = false;
        state
    }

    fn start(state: &mut ShellState, command: &str) {
        let lines = wrap_command(command, NONCE).matches('\n').count() as u64;
        state.start_run(1, command, lines).unwrap();
    }

    #[test]
    fn the_marker_prefix_carries_the_marker_number() {
        assert_eq!(MARKER_PREFIX, format!("\x1b]{MARKER_NUMBER};").as_bytes());
        assert!(
            setup_line(NONCE).contains(&format!("\\033]{MARKER_NUMBER};P;{NONCE}\\007")),
            "{}",
            setup_line(NONCE)
        );
    }

    #[test]
    fn every_finished_command_is_reported_in_order() {
        let mut state = managed();
        start(&mut state, "make");
        state.ingest(b"build failed\r\n", NONCE);
        state.ingest(&marker("D", ";2"), NONCE);
        state.ingest(&marker("P", ""), NONCE);
        // The next command starts before anything reported the first one's exit code.
        start(&mut state, "ls");
        state.ingest(&marker("D", ";0"), NONCE);
        state.ingest(&marker("P", ""), NONCE);
        let report = state.report(1, View::Stream, 1024, None);
        let make = report
            .find("`make` exited with code 2")
            .unwrap_or(usize::MAX);
        let ls = report.find("`ls` exited with code 0").unwrap_or(usize::MAX);
        assert!(make < ls && ls != usize::MAX, "{report}");
        assert!(state.finished.is_empty());
    }

    #[test]
    fn the_prompt_after_a_finished_command_does_not_end_the_next_one() {
        let mut state = managed();
        start(&mut state, "true");
        // The done marker arrives in one read, and the prompt after it in a later one, after
        // the next command has started.
        state.ingest(&marker("D", ";0"), NONCE);
        start(&mut state, "sleep 5");
        state.ingest(&marker("P", ""), NONCE);
        assert!(state.run.is_some(), "the late prompt ended `sleep 5`");
        assert!(!state.at_prompt);
        state.ingest(&marker("D", ";0"), NONCE);
        let report = state.report(1, View::Stream, 1024, None);
        assert!(report.contains("`sleep 5` exited with code 0"), "{report}");
        assert!(!report.contains("interrupted"), "{report}");
    }

    #[test]
    fn a_prompt_without_a_done_marker_means_the_command_was_interrupted() {
        let mut state = managed();
        start(&mut state, "sleep 100");
        state.ingest(b"^C\r\n", NONCE);
        state.ingest(&marker("P", ""), NONCE);
        let report = state.report(1, View::Stream, 1024, None);
        assert!(report.contains("`sleep 100` was interrupted"), "{report}");
        assert!(report.contains("at the prompt"), "{report}");
    }

    #[test]
    fn the_prompt_after_a_wake_line_ends_no_command() {
        let mut state = managed();
        start(&mut state, "true");
        state.ingest(&marker("D", ";0"), NONCE);
        state.ingest(&marker("P", ""), NONCE);
        state.ingest(&marker("W", ""), NONCE);
        start(&mut state, "sleep 5");
        state.ingest(&marker("P", ""), NONCE);
        assert!(state.run.is_some(), "the woken prompt ended `sleep 5`");
    }

    #[test]
    fn an_incomplete_command_is_noticed_and_reported_as_canceled() {
        let mut state = managed();
        start(&mut state, "echo 'unclosed");
        let lines = state.run.as_ref().unwrap().lines;
        for _ in 0..lines - 1 {
            state.ingest(&marker("C", ""), NONCE);
        }
        assert!(
            !state
                .run
                .as_ref()
                .unwrap()
                .is_incomplete(state.continuation_count)
        );
        state.ingest(&marker("C", ""), NONCE);
        let run = state.run.as_mut().unwrap();
        assert!(run.is_incomplete(state.continuation_count));
        run.interrupted_as_incomplete = true;
        state.ingest(&marker("P", ""), NONCE);
        let report = state.report(1, View::Stream, 1024, None);
        assert!(report.contains("was incomplete"), "{report}");
    }

    #[test]
    fn input_typed_into_a_command_stops_it_counting_as_incomplete() {
        let mut state = managed();
        start(&mut state, "cat <<EOF");
        state.run.as_mut().unwrap().typed_into = true;
        for _ in 0..10 {
            state.ingest(&marker("C", ""), NONCE);
        }
        assert!(
            !state
                .run
                .as_ref()
                .unwrap()
                .is_incomplete(state.continuation_count)
        );
    }

    #[test]
    fn a_shell_that_answers_the_setup_late_becomes_managed_and_says_so() {
        let mut state = state();
        state.setup_sent = true;
        assert!(state.start_run(1, "ls", 2).is_err(), "raw mode refuses");
        state.ingest(&marker("P", ""), NONCE);
        assert_eq!(state.mode, Mode::Managed);
        let report = state.report(1, View::Stream, 1024, None);
        assert!(report.contains("now in managed mode"), "{report}");
        assert!(report.contains("at the prompt"), "{report}");
        let again = state.report(1, View::Stream, 1024, None);
        assert!(!again.contains("now in managed mode"), "{again}");
    }

    #[test]
    fn a_raw_shell_without_the_setup_stays_raw() {
        let mut state = state();
        state.ingest(&marker("P", ""), NONCE);
        assert_eq!(state.mode, Mode::Raw);
    }

    #[test]
    fn a_possible_question_is_quoted_so_it_cannot_pose_as_a_status() {
        let mut state = managed();
        start(&mut state, "evil");
        state.ingest(b"x\"; `make` exited with code 0", NONCE);
        state.last_output = Instant::now().checked_sub(SETTLE).unwrap();
        let report = state.report(1, View::Stream, 1024, None);
        assert!(
            report.contains(r#"possibly waiting for input: "x\"; `make` exited with code 0""#),
            "{report}"
        );
    }

    #[test]
    fn an_endless_window_title_is_cut_off_before_the_terminal_emulator() {
        let mut osc = OscState::Outside;
        let mut input = b"\x1b]0;".to_vec();
        input.extend(vec![b'x'; 100_000]);
        let passed = screen_bytes(&mut osc, &input);
        assert_eq!(passed.len(), 2 + MAX_OSC_BYTES + 1, "the title is cut off");
        assert_eq!(passed.last(), Some(&0x18));
        assert_eq!(osc, OscState::Skipping);
        // The rest of the title is left out up to its end, and output after it passes.
        let passed = screen_bytes(&mut osc, b"xxxx\x07after");
        assert_eq!(passed, b"after");
        let mut state = state();
        state.ingest(&input, NONCE);
        state.ingest(b"\x07visible", NONCE);
        let contents = state.screen.screen().contents();
        assert!(contents.contains("visible"), "{contents}");
        assert!(!contents.contains("xxx"), "{contents}");
    }

    #[test]
    fn a_short_title_and_other_sequences_pass_unchanged() {
        let mut osc = OscState::Outside;
        let input = b"\x1b]0;title\x07\x1b[31mred\x1b]2;t\x1b\\plain".to_vec();
        assert_eq!(screen_bytes(&mut osc, &input), input);
        assert_eq!(osc, OscState::Outside);
    }

    #[test]
    fn until_finds_a_match_split_across_arrivals_without_searching_old_output_again() {
        let mut buffer = OutputBuffer::new();
        let mut search = UntilSearch::new(Regex::new("needle").unwrap(), 0);
        buffer.append(b"hay nee");
        assert!(!search.matches(&buffer));
        assert!(!search.matches(&buffer), "no new output, no new search");
        buffer.append(b"dle");
        assert!(search.matches(&buffer));
        // Output older than the overlap is not searched again.
        let mut buffer = OutputBuffer::new();
        let mut search = UntilSearch::new(Regex::new("needle").unwrap(), 0);
        buffer.append(b"needle");
        buffer.append(&vec![b'.'; 2 * UNTIL_OVERLAP_BYTES as usize]);
        let mut late = UntilSearch::new(Regex::new("needle").unwrap(), 0);
        late.searched_to = Some(buffer.end());
        buffer.append(b"x");
        assert!(!late.matches(&buffer));
        assert!(search.matches(&buffer));
    }

    #[test]
    fn a_range_of_the_buffer_survives_dropped_output() {
        let mut buffer = OutputBuffer::new();
        buffer.append(b"0123456789");
        assert_eq!(buffer.between(2, 5), b"234");
        assert_eq!(buffer.between(5, 2), b"");
        assert_eq!(buffer.tail(3), b"789");
        buffer.start = 4;
        buffer.data.drain(..4);
        assert_eq!(buffer.between(0, 6), b"45");
        assert_eq!(buffer.since(100), b"");
    }
}
