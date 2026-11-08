//! One-off commands: each runs on its own channel of an open connection, without a terminal, with
//! stdout and stderr kept apart.

use std::time::{Duration, Instant};

use russh::{ChannelMsg, Sig};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::{
    client::{
        CLOSE_TIMEOUT, REQUEST_TIMEOUT, SshHandle, best_effort, bounded, open_session_channel,
    },
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

/// How long output may pause after the command exits before the call returns. A process it
/// started in the background can hold its output open, and the call must not wait for that
/// process. Output that keeps coming keeps the call reading, up to [`EXIT_DRAIN_LIMIT`]: the server
/// sends the exit status ahead of output it still holds, as it does on a slow link.
const EXIT_DRAIN: Duration = Duration::from_secs(1);

/// The longest the call reads output after the command exits, unless the timeout comes first. A
/// background process that keeps printing holds the call this long.
const EXIT_DRAIN_LIMIT: Duration = Duration::from_secs(10);

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
    mut request: ExecRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let mut channel = open_session_channel(handle, cancel).await?;
    if let Err(error) = bounded(
        REQUEST_TIMEOUT,
        "send the command",
        channel.exec(true, request.command.as_bytes()),
    )
    .await
    {
        best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
        return Err(error);
    }

    let started = Instant::now();
    let timeout_at = tokio::time::Instant::from_std(started + request.timeout);
    // stdin is fed by its own task: a command that does not read it, or prints while it is fed,
    // must neither stop its output from being read nor keep the timeout from firing.
    let stdin_task = tokio::spawn({
        let mut writer = channel.make_writer();
        let stdin = request.stdin.take().unwrap_or_default();
        async move {
            if let Err(error) = writer.write_all(stdin.as_bytes()).await {
                tracing::debug!("stdin could not be sent: {error}");
            }
            if let Err(error) = writer.shutdown().await {
                tracing::debug!("stdin could not be closed: {error}");
            }
        }
    });
    let mut next_step = timeout_at;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    let mut stop: Option<StopReason> = None;
    let mut signals_sent: Vec<&str> = Vec::new();
    let mut steps_taken = 0;
    let mut exec_confirmed = false;
    let mut drain_until = None;
    let mut left_output_open = false;
    let mut unresponsive = false;
    let mut progress_tick = tokio::time::interval(PROGRESS_INTERVAL);
    progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The latest the call reads output after the command exits, set when it exits.
    let mut drain_limit = timeout_at;
    loop {
        if exit.is_some() && drain_until.is_none() {
            let now = tokio::time::Instant::now();
            drain_limit = (now + EXIT_DRAIN_LIMIT)
                .min(timeout_at)
                .max(now + EXIT_DRAIN);
            drain_until = Some(now + EXIT_DRAIN);
        }
        tokio::select! {
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    let full = capture(&mut stdout, stderr.len(), &data);
                    if full && exit.is_some() {
                        left_output_open = true;
                        best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
                        break;
                    }
                    if full && stop.is_none() {
                        stop = Some(StopReason::OutputLimit);
                        next_step = tokio::time::Instant::now();
                    }
                    if exit.is_some() {
                        drain_until = Some((tokio::time::Instant::now() + EXIT_DRAIN).min(drain_limit));
                    }
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let full = capture(&mut stderr, stdout.len(), &data);
                    if full && exit.is_some() {
                        left_output_open = true;
                        best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
                        break;
                    }
                    if full && stop.is_none() {
                        stop = Some(StopReason::OutputLimit);
                        next_step = tokio::time::Instant::now();
                    }
                    if exit.is_some() {
                        drain_until = Some((tokio::time::Instant::now() + EXIT_DRAIN).min(drain_limit));
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(Exit::Status(exit_status)),
                Some(ChannelMsg::ExitSignal { signal_name, core_dumped, .. }) => {
                    exit = Some(Exit::Signal { name: signal_label(&signal_name), core_dumped });
                }
                Some(ChannelMsg::Success) => exec_confirmed = true,
                Some(ChannelMsg::Failure) if !exec_confirmed => {
                    stdin_task.abort();
                    best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
                    return Err(ToolError::new(
                        "The server refused to run the command. It may allow only an interactive shell: try shell_open.",
                    ));
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            () = tokio::time::sleep_until(drain_until.unwrap_or(next_step)), if drain_until.is_some() => {
                left_output_open = true;
                best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
                break;
            }
            // Once the command has exited there is nothing left to stop; the drain ends the call.
            () = tokio::time::sleep_until(next_step), if exit.is_none() => {
                if stop.is_none() {
                    stop = Some(StopReason::TimedOut);
                }
                // Each step waits at most STOP_GRACE to be sent, so a server that stopped reading
                // the connection cannot keep the call from returning.
                match steps_taken {
                    0 | 1 => {
                        let (signal, name) = if steps_taken == 0 {
                            (Sig::TERM, "TERM")
                        } else {
                            (Sig::KILL, "KILL")
                        };
                        let sent = best_effort(
                            STOP_GRACE,
                            "sending a signal to the command",
                            channel.signal(signal),
                        )
                        .await;
                        if sent {
                            signals_sent.push(name);
                        } else {
                            unresponsive = true;
                        }
                    }
                    2 => {
                        best_effort(STOP_GRACE, "closing the exec channel", channel.close()).await;
                    }
                    _ => break,
                }
                steps_taken += 1;
                next_step = tokio::time::Instant::now() + STOP_GRACE;
            }
            // Before the exit a cancel starts the stop steps unless they have started; after it, a
            // cancel ends the reading of what is left.
            () = cancel.cancelled(), if exit.is_some() || stop.is_none() => {
                if exit.is_some() {
                    best_effort(CLOSE_TIMEOUT, "closing the exec channel", channel.close()).await;
                    break;
                }
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
            unresponsive,
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
    /// A signal could not be sent: the server stopped taking requests.
    unresponsive: bool,
}

/// Add `data` to `stream` without letting both streams together pass [`MAX_CAPTURE_BYTES`].
/// Returns whether the bound has been reached.
fn capture(stream: &mut Vec<u8>, other_stream_bytes: usize, data: &[u8]) -> bool {
    let room = MAX_CAPTURE_BYTES.saturating_sub(stream.len() + other_stream_bytes);
    stream.extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
    data.len() >= room
}

fn describe(request: &ExecRequest, ending: &Ending, stdout: &[u8], stderr: &[u8]) -> String {
    let Ending {
        elapsed,
        exit,
        stop,
        signals_sent,
        left_output_open,
        unresponsive,
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
    let mut notes = String::new();
    if *left_output_open {
        notes.push_str(
            "; something it started still holds its output open, so output after its exit is missing",
        );
    }
    if *unresponsive {
        notes.push_str(
            "; the server stopped taking the stop signals, so the command may still be running",
        );
    }
    let headline = match stop {
        None => format!("[{outcome} after {}{notes}]", format_duration(*elapsed)),
        Some(StopReason::TimedOut) => format!(
            "[timed out after {}{stopped_with}; {outcome}{notes}]",
            format_duration(request.timeout)
        ),
        Some(StopReason::Canceled) => {
            format!(
                "[canceled after {}{stopped_with}; {outcome}{notes}]",
                format_duration(*elapsed)
            )
        }
        Some(StopReason::OutputLimit) => format!(
            "[stopped after printing {}{stopped_with}; {outcome}{notes}]",
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
