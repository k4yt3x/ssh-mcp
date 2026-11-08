//! One-off commands: each runs on its own channel of an open connection, without a terminal, with
//! stdout and stderr kept apart.

use std::time::{Duration, Instant};

use russh::{ChannelMsg, Sig};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::{
    client::{SshHandle, open_session_channel},
    output::{
        PROGRESS_INTERVAL, Progress, ToolError, decode_with_limit, format_duration, format_size,
        last_output_line, signal_label,
    },
};

/// The most output a command may print, stdout and stderr together, before it is stopped. Bounds
/// this process's memory against a command that writes without end.
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

/// How long a command has to exit after each step of being stopped (TERM, KILL, closing the
/// channel) before the next step.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// How long output is still collected after the command exits. A process it started in the
/// background can hold its output open, and the call must not wait for that process.
const EXIT_DRAIN: Duration = Duration::from_secs(1);

/// One command to run.
pub(crate) struct ExecRequest {
    /// The command line, run by the account's login shell.
    pub(crate) command: String,
    /// Text written to the command's stdin before it is closed.
    pub(crate) stdin: Option<String>,
    /// How long the command may run before it is stopped.
    pub(crate) timeout: Duration,
    /// The most bytes of each stream the result shows.
    pub(crate) max_output_bytes: usize,
}

enum Exit {
    Status(u32),
    Signal { name: String, core_dumped: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopReason {
    TimedOut,
    Canceled,
    OutputLimit,
}

/// Run `request` on a new channel of `handle` and describe the outcome.
pub(crate) async fn run(
    handle: &SshHandle,
    request: ExecRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let mut channel = open_session_channel(handle, cancel).await?;
    channel
        .exec(true, request.command.as_bytes())
        .await
        .map_err(|error| ToolError::new(format!("The command could not be sent: {error}")))?;

    let started = Instant::now();
    // stdin is fed by its own task: a command that does not read it, or prints while it is fed,
    // must neither stop its output from being read nor keep the timeout from firing.
    let stdin_task = tokio::spawn({
        let mut writer = channel.make_writer();
        let stdin = request.stdin.clone().unwrap_or_default();
        async move {
            if let Err(error) = writer.write_all(stdin.as_bytes()).await {
                tracing::debug!("stdin could not be sent: {error}");
            }
            if let Err(error) = writer.shutdown().await {
                tracing::debug!("stdin could not be closed: {error}");
            }
        }
    });
    let mut next_step = tokio::time::Instant::from_std(started + request.timeout);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    let mut stop: Option<StopReason> = None;
    let mut signals_sent: Vec<&str> = Vec::new();
    let mut steps_taken = 0;
    let mut exec_confirmed = false;
    let mut drain_until = None;
    let mut left_output_open = false;
    let mut progress_tick = tokio::time::interval(PROGRESS_INTERVAL);
    progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if exit.is_some() && drain_until.is_none() {
            drain_until = Some(tokio::time::Instant::now() + EXIT_DRAIN);
        }
        tokio::select! {
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    let full = capture(&mut stdout, stderr.len(), &data);
                    if full && stop.is_none() {
                        stop = Some(StopReason::OutputLimit);
                        next_step = tokio::time::Instant::now();
                    }
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let full = capture(&mut stderr, stdout.len(), &data);
                    if full && stop.is_none() {
                        stop = Some(StopReason::OutputLimit);
                        next_step = tokio::time::Instant::now();
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(Exit::Status(exit_status)),
                Some(ChannelMsg::ExitSignal { signal_name, core_dumped, .. }) => {
                    exit = Some(Exit::Signal { name: signal_label(&signal_name), core_dumped });
                }
                Some(ChannelMsg::Success) => exec_confirmed = true,
                Some(ChannelMsg::Failure) if !exec_confirmed => {
                    stdin_task.abort();
                    return Err(ToolError::new("The server refused to run the command."));
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            () = tokio::time::sleep_until(drain_until.unwrap_or(next_step)), if drain_until.is_some() => {
                left_output_open = true;
                if let Err(error) = channel.close().await {
                    tracing::debug!("closing the exec channel failed: {error}");
                }
                break;
            }
            () = tokio::time::sleep_until(next_step) => {
                if stop.is_none() {
                    stop = Some(StopReason::TimedOut);
                }
                match steps_taken {
                    0 => {
                        send_signal(&channel, Sig::TERM).await;
                        signals_sent.push("TERM");
                    }
                    1 => {
                        send_signal(&channel, Sig::KILL).await;
                        signals_sent.push("KILL");
                    }
                    2 => {
                        if let Err(error) = channel.close().await {
                            tracing::debug!("closing the exec channel failed: {error}");
                        }
                    }
                    _ => break,
                }
                steps_taken += 1;
                next_step = tokio::time::Instant::now() + STOP_GRACE;
            }
            () = cancel.cancelled(), if stop.is_none() && exit.is_none() => {
                stop = Some(StopReason::Canceled);
                next_step = tokio::time::Instant::now();
            }
            _ = progress_tick.tick() => {
                let source = if stdout.is_empty() { &stderr } else { &stdout };
                if let Some(line) = last_output_line(source) {
                    progress.report(&line).await;
                }
            }
        }
    }
    stdin_task.abort();

    Ok(describe(
        &request,
        &Ending {
            elapsed: started.elapsed(),
            exit,
            stop,
            signals_sent,
            left_output_open,
        },
        &stdout,
        &stderr,
    ))
}

/// How a command's run ended.
struct Ending {
    elapsed: Duration,
    exit: Option<Exit>,
    stop: Option<StopReason>,
    signals_sent: Vec<&'static str>,
    /// The command exited, but something it started kept its output open past [`EXIT_DRAIN`].
    left_output_open: bool,
}

/// Add `data` to `stream` without letting both streams together pass [`MAX_CAPTURE_BYTES`].
/// Returns whether the bound has been reached.
fn capture(stream: &mut Vec<u8>, other_stream_bytes: usize, data: &[u8]) -> bool {
    let room = MAX_CAPTURE_BYTES.saturating_sub(stream.len() + other_stream_bytes);
    stream.extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
    data.len() >= room
}

async fn send_signal(channel: &russh::Channel<russh::client::Msg>, signal: Sig) {
    if let Err(error) = channel.signal(signal).await {
        tracing::debug!("sending a signal to the command failed: {error}");
    }
}

fn describe(request: &ExecRequest, ending: &Ending, stdout: &[u8], stderr: &[u8]) -> String {
    let Ending {
        elapsed,
        exit,
        stop,
        signals_sent,
        left_output_open,
    } = ending;
    let outcome = match exit {
        Some(Exit::Status(code)) => format!("exit code {code}"),
        Some(Exit::Signal { name, core_dumped }) => {
            let core = if *core_dumped { ", core dumped" } else { "" };
            format!("killed by signal {name}{core}")
        }
        None => "no exit status reported".to_owned(),
    };
    let stopped_with = if signals_sent.is_empty() {
        String::new()
    } else {
        format!(
            " (sent {}; commands it started in the background may still run)",
            signals_sent.join(", then ")
        )
    };
    let left_open = if *left_output_open {
        "; something it started still holds its output open, so output after its exit is missing"
    } else {
        ""
    };
    let headline = match stop {
        None => format!("[{outcome} after {}{left_open}]", format_duration(*elapsed)),
        Some(StopReason::TimedOut) => format!(
            "[timed out after {}{stopped_with}; {outcome}{left_open}]",
            format_duration(request.timeout)
        ),
        Some(StopReason::Canceled) => {
            format!(
                "[canceled after {}{stopped_with}; {outcome}{left_open}]",
                format_duration(*elapsed)
            )
        }
        Some(StopReason::OutputLimit) => format!(
            "[stopped after printing {}{stopped_with}; {outcome}{left_open}]",
            format_size(MAX_CAPTURE_BYTES as u64)
        ),
    };
    let mut text = headline;
    for (name, stream) in [("stdout", stdout), ("stderr", stderr)] {
        if stream.is_empty() {
            continue;
        }
        let decoded = decode_with_limit(stream, request.max_output_bytes);
        text.push_str(&format!("\n--- {name} ---\n"));
        text.push_str(decoded.strip_suffix('\n').unwrap_or(&decoded));
    }
    if stdout.is_empty() && stderr.is_empty() {
        text.push_str("\n(no output)");
    }
    text
}
