//! Remote files over SFTP: reading, writing and editing text files in place, and copying files and
//! folders between this machine and the server.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use russh_sftp::{
    client::{Config, RawSftpSession, SftpSession, error::Error as SftpError, fs::Metadata},
    protocol::{FileAttributes, FileType, OpenFlags, StatusCode},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::{
    client::{
        CLOSE_TIMEOUT, REQUEST_TIMEOUT, SshHandle, best_effort, bounded, open_session_channel,
    },
    output::{Progress, ToolError, floor_char_boundary, format_duration, format_size, random_hex},
    paths::{open_regular_file, resolve_local_path},
};

/// The SFTP session of one connection, opened on first use, and the lock that keeps the text file
/// tools from interleaving on it.
#[derive(Default)]
pub(crate) struct SftpState {
    session: tokio::sync::Mutex<Option<Arc<SftpSession>>>,
    /// Held shared by `read_file` and exclusively by `write_file` and `edit_file`. An edit reads
    /// the file and writes it back, so a write in between would be lost, and a write truncates the
    /// file before it writes, so a read in between would see part of it. Waiting for it needs no
    /// timeout: whoever holds it waits only on bounded SFTP requests.
    text_files: tokio::sync::RwLock<()>,
}

/// The largest file `read_file` and `edit_file` read whole.
const MAX_TEXT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The most text one `read_file` result returns; the result says where to continue.
const MAX_READ_RESULT_BYTES: usize = 256 * 1024;

/// The lines `read_file` returns when no `limit` is given.
pub(crate) const DEFAULT_READ_LINES: usize = 2000;

/// The size of one read or write while copying; large enough for the SFTP session to keep several
/// requests in flight.
const COPY_CHUNK_BYTES: usize = 1024 * 1024;

/// How long the server has to answer one SFTP request. With up to 16 requests of 256 KiB in
/// flight, the library's default of 10 seconds fails transfers on links slower than about
/// 400 KiB/s.
const SFTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The most entries a folder download lists, so a server whose listing never ends cannot exhaust
/// this machine's memory.
const MAX_LISTED_ENTRIES: usize = 100_000;

fn canceled() -> ToolError {
    ToolError::new("The call was canceled.")
}

/// Stop a call its client canceled before it changes anything more. The client drops the result
/// unread, so a change made after the cancellation is one nobody is told about.
fn stop_if_canceled(cancel: &CancellationToken) -> Result<(), ToolError> {
    if cancel.is_cancelled() {
        Err(canceled())
    } else {
        Ok(())
    }
}

fn sftp_config() -> Config {
    Config {
        request_timeout_secs: SFTP_REQUEST_TIMEOUT.as_secs(),
        ..Config::default()
    }
}

/// Open a channel running the server's SFTP subsystem. The server's answer to the request is
/// read first: a server without SFTP refuses it and leaves the channel open, and the SFTP session
/// would wait for an answer to its first request until its timeout.
async fn open_sftp_channel(
    handle: &SshHandle,
    cancel: &CancellationToken,
) -> Result<russh::ChannelStream<russh::client::Msg>, ToolError> {
    let mut channel = open_session_channel(handle, cancel).await?;
    bounded(
        REQUEST_TIMEOUT,
        "request SFTP",
        channel.request_subsystem(true, "sftp"),
    )
    .await?;
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let failure = loop {
        let message = tokio::select! {
            message = channel.wait() => message,
            () = tokio::time::sleep_until(deadline) => break sftp_unavailable("no answer"),
            () = cancel.cancelled() => break canceled(),
        };
        match message {
            Some(russh::ChannelMsg::Success) => return Ok(channel.into_stream()),
            Some(russh::ChannelMsg::Failure) => break sftp_unavailable("the request was refused"),
            Some(russh::ChannelMsg::Close) | None => {
                break sftp_unavailable("the channel was closed");
            }
            Some(_) => {}
        }
    };
    best_effort(CLOSE_TIMEOUT, "closing the SFTP channel", channel.close()).await;
    Err(failure)
}

fn sftp_unavailable(error: impl std::fmt::Display) -> ToolError {
    ToolError::new(format!(
        "The server did not start SFTP ({error}); it may have no SFTP subsystem. Use exec instead."
    ))
}

/// Open the connection's SFTP session, or return the one already open.
pub(crate) async fn session(
    handle: &SshHandle,
    state: &SftpState,
    cancel: &CancellationToken,
) -> Result<Arc<SftpSession>, ToolError> {
    let mut slot = tokio::select! {
        slot = state.session.lock() => slot,
        () = cancel.cancelled() => return Err(canceled()),
    };
    if let Some(session) = slot.as_ref() {
        return Ok(Arc::clone(session));
    }
    let stream = open_sftp_channel(handle, cancel).await?;
    let session = tokio::select! {
        started = SftpSession::new_with_config(stream, sftp_config()) => {
            started.map_err(sftp_unavailable)?
        }
        () = cancel.cancelled() => return Err(canceled()),
    };
    let session = Arc::new(session);
    *slot = Some(Arc::clone(&session));
    Ok(session)
}

/// A remote path as SFTP understands it: `~/x` and `~` are relative to the login directory, which
/// is where SFTP resolves relative paths.
fn remote_path(path: &str) -> String {
    if path == "~" || path == "~/" {
        return ".".to_owned();
    }
    path.strip_prefix("~/").unwrap_or(path).to_owned()
}

fn join_remote(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn split_remote(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/".to_owned(), name.to_owned()),
        Some((parent, name)) => (parent.to_owned(), name.to_owned()),
        None => (".".to_owned(), trimmed.to_owned()),
    }
}

/// The local path of an entry `relative` to a folder being copied.
fn local_join(root: &Path, relative: &[String]) -> PathBuf {
    relative
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// An error from the SFTP session, as the reason a result gives.
trait SftpReason {
    fn reason(&self) -> String;
}

impl SftpReason for SftpError {
    /// The server's message, or the status's name when the server sent none. The library's own
    /// text joins the two, which reads "No such file: No such file".
    fn reason(&self) -> String {
        match self {
            SftpError::Status(status) if status.error_message.trim().is_empty() => {
                status.status_code.to_string()
            }
            SftpError::Status(status) => status.error_message.trim().to_owned(),
            other => other.to_string(),
        }
    }
}

impl SftpReason for std::io::Error {
    /// Reading and writing a remote file report some SFTP errors wrapped whole in I/O errors, and
    /// others as only the server's message, which may be empty.
    fn reason(&self) -> String {
        match self
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<SftpError>())
        {
            Some(error) => error.reason(),
            None if self.to_string().trim().is_empty() => "the server gave no reason".to_owned(),
            None => self.to_string(),
        }
    }
}

fn sftp_failure(action: &str, path: &str, error: impl SftpReason) -> ToolError {
    ToolError::new(format!("Could not {action} {path}: {}", error.reason()))
}

fn local_failure(action: &str, path: &Path, error: impl std::fmt::Display) -> ToolError {
    ToolError::new(format!("{} could not be {action}: {error}", path.display()))
}

/// What exists at a remote path, without following a final symlink, or `None` when nothing does.
/// Any other failure is an error, so a server that cannot answer is never taken to mean "absent".
async fn remote_entry(session: &SftpSession, path: &str) -> Result<Option<Metadata>, ToolError> {
    match session.symlink_metadata(path).await {
        Ok(metadata) => Ok(Some(metadata)),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(None),
        Err(error) => Err(sftp_failure("check", path, error)),
    }
}

/// Refuse to create `path` on the server when the folder it would go in is missing or is not a
/// folder. SFTP's own refusal does not say which part of the path is wrong.
async fn require_remote_parent(session: &SftpSession, path: &str) -> Result<(), ToolError> {
    let (parent, _) = split_remote(path);
    match session.metadata(parent.as_str()).await {
        Ok(metadata) if metadata.file_type() == FileType::Dir => Ok(()),
        Ok(_) => Err(ToolError::new(format!(
            "{parent} on the server is not a folder."
        ))),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
            Err(ToolError::new(format!(
                "The folder {parent} does not exist on the server; create it first, such as with exec and mkdir -p."
            )))
        }
        Err(error) => Err(sftp_failure("check", &parent, error)),
    }
}

/// What exists at a local path, without following a final symlink, or `None` when nothing does.
fn local_entry(path: &Path) -> Result<Option<std::fs::Metadata>, ToolError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(local_failure("checked", path, error)),
    }
}

/// Refuse a remote path the text file tools cannot use: a folder, or anything else that is not a
/// regular file, such as a pipe, which would block the server's SFTP process until something
/// opens its other end. `instead` is what exec would do with it, such as "read it".
fn require_regular_file(metadata: &Metadata, path: &str, instead: &str) -> Result<(), ToolError> {
    match metadata.file_type() {
        FileType::File => Ok(()),
        FileType::Dir => Err(ToolError::new(format!("{path} is a folder."))),
        _ => Err(ToolError::new(format!(
            "{path} is not a regular file; use exec to {instead}."
        ))),
    }
}

/// Read a remote text file whole, refusing folders, huge files and binary content.
async fn read_text(session: &SftpSession, path: &str) -> Result<String, ToolError> {
    let metadata = session
        .metadata(path)
        .await
        .map_err(|error| sftp_failure("read", path, error))?;
    require_regular_file(&metadata, path, "read it")?;
    let too_large = || {
        ToolError::new(format!(
            "{path} is larger than {}, too large to read as text; use download, or exec with head, tail or grep.",
            format_size(MAX_TEXT_FILE_BYTES)
        ))
    };
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        return Err(too_large());
    }
    // The size is only what stat said; a file that grows while it is read is still cut off.
    let mut file = session
        .open(path)
        .await
        .map_err(|error| sftp_failure("read", path, error))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_TEXT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| sftp_failure("read", path, error))?;
    if bytes.len() as u64 > MAX_TEXT_FILE_BYTES {
        return Err(too_large());
    }
    if bytes.contains(&0) {
        return Err(ToolError::new(format!(
            "{path} is a binary file; use download to copy it."
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        ToolError::new(format!(
            "{path} is not UTF-8 text; use download to copy it, or exec to inspect it."
        ))
    })
}

/// Overwrite a remote file's content in place, creating it when it does not exist. Writing in
/// place keeps the file's owner and permissions and writes through a symlink, where replacing the
/// file would turn the link into a regular file.
async fn write_text(session: &SftpSession, path: &str, content: &str) -> Result<(), ToolError> {
    let mut file = session
        .open_with_flags(
            path,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|error| sftp_failure("open", path, error))?;
    file.write_all(content.as_bytes())
        .await
        .map_err(|error| sftp_failure("write", path, error))?;
    file.shutdown()
        .await
        .map_err(|error| sftp_failure("finish writing", path, error))?;
    Ok(())
}

/// What `read_file` needs.
pub(crate) struct ReadRequest {
    pub(crate) path: String,
    /// The first line to return, counted from 1.
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

/// Read lines of a remote text file.
pub(crate) async fn read_file(
    state: &SftpState,
    session: &SftpSession,
    request: ReadRequest,
    cancel: &CancellationToken,
) -> Result<String, ToolError> {
    let path = remote_path(&request.path);
    let text = {
        let _reading = state.text_files.read().await;
        stop_if_canceled(cancel)?;
        read_text(session, &path).await?
    };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let total = lines.len();
    if total == 0 {
        return Ok(format!("[{path} is empty]"));
    }
    let first = request.offset;
    if first == 0 || first > total {
        return Err(ToolError::new(format!(
            "offset {first} is outside {path}, which has lines 1 to {total}."
        )));
    }
    let mut selected = String::new();
    let mut last = first - 1;
    let mut cut_line = false;
    for line in lines.iter().skip(first - 1).take(request.limit) {
        if selected.len() + line.len() > MAX_READ_RESULT_BYTES {
            if selected.is_empty() {
                let end = floor_char_boundary(line, MAX_READ_RESULT_BYTES);
                selected.push_str(line.get(..end).unwrap_or_default());
                last += 1;
                cut_line = true;
            }
            break;
        }
        selected.push_str(line);
        last += 1;
    }
    if first == 1 && last == total && !cut_line {
        return Ok(selected);
    }
    let mut notes = Vec::new();
    if cut_line {
        notes.push(format!(
            "line {last} is longer than {} and was cut; use exec to read all of it",
            format_size(MAX_READ_RESULT_BYTES as u64)
        ));
    }
    if last < total {
        notes.push(format!("continue with offset {}", last + 1));
    }
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!("; {}", notes.join("; "))
    };
    Ok(format!(
        "[lines {first}-{last} of {total}{notes}]\n{selected}"
    ))
}

/// Create or replace a remote text file.
pub(crate) async fn write_file(
    state: &SftpState,
    session: &SftpSession,
    path: &str,
    content: &str,
    cancel: &CancellationToken,
) -> Result<String, ToolError> {
    let path = remote_path(path);
    let _writing = state.text_files.write().await;
    let existed = match session.metadata(path.as_str()).await {
        Ok(metadata) => {
            require_regular_file(&metadata, &path, "write to it")?;
            true
        }
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => false,
        Err(error) => return Err(sftp_failure("check", &path, error)),
    };
    if !existed {
        require_remote_parent(session, &path).await?;
    }
    stop_if_canceled(cancel)?;
    write_text(session, &path, content).await?;
    let verb = if existed { "Replaced" } else { "Created" };
    Ok(format!(
        "{verb} {path} ({}).",
        format_size(content.len() as u64)
    ))
}

/// What `edit_file` needs.
pub(crate) struct EditRequest {
    pub(crate) path: String,
    pub(crate) old_string: String,
    pub(crate) new_string: String,
    pub(crate) replace_all: bool,
}

/// Replace text in a remote file.
pub(crate) async fn edit_file(
    state: &SftpState,
    session: &SftpSession,
    request: EditRequest,
    cancel: &CancellationToken,
) -> Result<String, ToolError> {
    let path = remote_path(&request.path);
    if request.old_string.is_empty() {
        return Err(ToolError::new(
            "old_string is empty; use write_file to write a whole file.",
        ));
    }
    if request.old_string == request.new_string {
        return Err(ToolError::new("old_string and new_string are the same."));
    }
    let _writing = state.text_files.write().await;
    let text = read_text(session, &path).await?;
    let mut old_string = Cow::Borrowed(request.old_string.as_str());
    let mut new_string = Cow::Borrowed(request.new_string.as_str());
    let mut count = text.matches(old_string.as_ref()).count();
    // The carriage return of a `\r\n` line ending is invisible in what read_file returns, and some
    // clients cannot send one, so line breaks written as `\n` are also tried as the file's.
    let as_crlf = count == 0
        && text.contains("\r\n")
        && old_string.contains('\n')
        && !old_string.contains('\r');
    if as_crlf {
        old_string = Cow::Owned(old_string.replace('\n', "\r\n"));
        new_string = Cow::Owned(new_string.replace("\r\n", "\n").replace('\n', "\r\n"));
        count = text.matches(old_string.as_ref()).count();
    }
    if count == 0 {
        let line_breaks = if as_crlf {
            ", with its line breaks taken as \\n or as the file's \\r\\n"
        } else {
            ""
        };
        return Err(ToolError::new(format!(
            "old_string was not found in {path}{line_breaks}. It must match exactly, including whitespace."
        )));
    }
    if count > 1 && !request.replace_all {
        return Err(ToolError::new(format!(
            "old_string matches {count} places in {path}. Add surrounding text to make it unique, or pass replace_all."
        )));
    }
    let edited = if request.replace_all {
        text.replace(old_string.as_ref(), &new_string)
    } else {
        text.replacen(old_string.as_ref(), &new_string, 1)
    };
    stop_if_canceled(cancel)?;
    write_text(session, &path, &edited).await?;
    let places = if count == 1 {
        "1 place".to_owned()
    } else {
        format!("{count} places")
    };
    let line_breaks = if as_crlf {
        ", with line breaks written as the file's \\r\\n"
    } else {
        ""
    };
    Ok(format!("Edited {path}: replaced {places}{line_breaks}."))
}

/// Counts for a transfer's result.
#[derive(Default)]
struct Tally {
    files: u64,
    directories: u64,
    symlinks: u64,
    skipped_symlinks: u64,
    skipped_special: u64,
    bytes: u64,
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

impl Tally {
    /// What was copied, such as `2 files, 1 folder (3.0 MiB)`.
    fn describe(&self) -> String {
        let mut parts = vec![plural(self.files, "file", "files")];
        if self.directories > 0 {
            parts.push(plural(self.directories, "folder", "folders"));
        }
        if self.symlinks > 0 {
            parts.push(plural(self.symlinks, "symlink", "symlinks"));
        }
        format!("{} ({})", parts.join(", "), format_size(self.bytes))
    }

    /// Sentences about what was left out, each starting with a space, or nothing.
    fn skipped(&self) -> String {
        let mut text = String::new();
        if self.skipped_symlinks > 0 {
            text.push_str(&format!(
                " {} skipped because this system could not create them.",
                plural(self.skipped_symlinks, "symlink was", "symlinks were")
            ));
        }
        if self.skipped_special > 0 {
            text.push_str(&format!(
                " {} skipped.",
                plural(
                    self.skipped_special,
                    "special file (a socket, device or pipe) was",
                    "special files (sockets, devices or pipes) were"
                )
            ));
        }
        text
    }
}

/// Progress through a transfer of known size.
struct TransferProgress<'a> {
    progress: &'a mut Progress,
    cancel: &'a CancellationToken,
    done: u64,
    total: u64,
}

impl TransferProgress<'_> {
    async fn advance(&mut self, bytes: u64, name: &str) -> Result<(), ToolError> {
        stop_if_canceled(self.cancel)?;
        self.done += bytes;
        self.progress
            .report_amount(
                &format!(
                    "{name}: {} of {}",
                    format_size(self.done),
                    format_size(self.total)
                ),
                self.done,
                self.total,
            )
            .await;
        Ok(())
    }
}

/// What `upload` needs.
pub(crate) struct UploadRequest {
    pub(crate) local_path: String,
    pub(crate) remote_path: String,
    pub(crate) overwrite: bool,
    /// Permission bits for a single uploaded file.
    pub(crate) mode: Option<u32>,
    /// The server reads symlink requests with their arguments reversed, as OpenSSH does.
    pub(crate) reversed_symlink_arguments: bool,
}

/// One entry of a local folder being uploaded, relative to its root.
enum LocalEntry {
    Directory {
        relative: Vec<String>,
        mode: u32,
    },
    File {
        relative: Vec<String>,
        mode: u32,
        size: u64,
    },
    Symlink {
        relative: Vec<String>,
        target: String,
    },
}

/// Copy a local file or folder to the server.
pub(crate) async fn upload(
    session: &SftpSession,
    request: UploadRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let started = Instant::now();
    let local = resolve_local_path("local_path", &request.local_path)?;
    let destination = remote_path(&request.remote_path);
    let metadata = tokio::fs::metadata(&local)
        .await
        .map_err(|error| local_failure("read", &local, error))?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(ToolError::new(format!(
            "{} is not a regular file or a folder.",
            local.display()
        )));
    }
    let existing = remote_entry(session, &destination).await?;
    if existing.is_some() && !request.overwrite {
        return Err(ToolError::new(format!(
            "{destination} already exists on the server; pass overwrite to replace it."
        )));
    }
    if existing.is_none() {
        require_remote_parent(session, &destination).await?;
    }
    let existing_kind = existing.as_ref().map(Metadata::file_type);
    let mut tally = Tally::default();
    if metadata.is_dir() {
        if request.mode.is_some() {
            return Err(ToolError::new(
                "mode applies to a single file; a folder's entries keep their own permissions.",
            ));
        }
        if existing_kind.is_some_and(|kind| kind != FileType::Dir) {
            return Err(ToolError::new(format!(
                "{destination} exists on the server and is not a folder."
            )));
        }
        let root = local.clone();
        let (entries, skipped_special) = tokio::task::spawn_blocking(move || walk_local(&root))
            .await
            .map_err(|error| ToolError::new(format!("Reading the folder failed: {error}")))??;
        tally.skipped_special = skipped_special;
        let total = entries
            .iter()
            .map(|entry| match entry {
                LocalEntry::File { size, .. } => *size,
                _ => 0,
            })
            .sum();
        let mut transfer = TransferProgress {
            progress,
            cancel,
            done: 0,
            total,
        };
        if existing.is_none() {
            stop_if_canceled(cancel)?;
            session
                .create_dir(destination.as_str())
                .await
                .map_err(|error| sftp_failure("create", &destination, error))?;
            tally.directories += 1;
        }
        // Folder permissions are set after their contents are written, so a read-only folder
        // does not refuse its own files. Folders that already existed keep theirs.
        let mut folder_modes = Vec::new();
        if existing.is_none() {
            folder_modes.push((destination.clone(), local_mode(&metadata)));
        }
        for entry in entries {
            stop_if_canceled(cancel)?;
            match entry {
                LocalEntry::Directory { relative, mode } => {
                    let path = join_remote(&destination, &relative.join("/"));
                    match remote_entry(session, &path)
                        .await?
                        .as_ref()
                        .map(Metadata::file_type)
                    {
                        Some(FileType::Dir) => {}
                        Some(_) => {
                            session
                                .remove_file(path.as_str())
                                .await
                                .map_err(|error| sftp_failure("replace", &path, error))?;
                            session
                                .create_dir(path.as_str())
                                .await
                                .map_err(|error| sftp_failure("create", &path, error))?;
                            folder_modes.push((path, mode));
                        }
                        None => {
                            session
                                .create_dir(path.as_str())
                                .await
                                .map_err(|error| sftp_failure("create", &path, error))?;
                            folder_modes.push((path, mode));
                        }
                    }
                    tally.directories += 1;
                }
                LocalEntry::File {
                    relative,
                    mode,
                    size: _,
                } => {
                    let source = local_join(&local, &relative);
                    let path = join_remote(&destination, &relative.join("/"));
                    tally.bytes += upload_file(
                        session,
                        LocalFile {
                            path: &source,
                            follow_symlink: false,
                        },
                        &path,
                        UploadMode::Kept(mode),
                        request.overwrite,
                        &mut transfer,
                    )
                    .await?;
                    tally.files += 1;
                }
                LocalEntry::Symlink { relative, target } => {
                    let path = join_remote(&destination, &relative.join("/"));
                    if remote_entry(session, &path).await?.is_some() {
                        session
                            .remove_file(path.as_str())
                            .await
                            .map_err(|error| sftp_failure("replace", &path, error))?;
                    }
                    let result = if request.reversed_symlink_arguments {
                        session.symlink(target.as_str(), path.as_str()).await
                    } else {
                        session.symlink(path.as_str(), target.as_str()).await
                    };
                    result.map_err(|error| sftp_failure("create the symlink", &path, error))?;
                    tally.symlinks += 1;
                }
            }
        }
        // Deepest first, so no folder loses write permission before the folders inside it.
        for (path, mode) in folder_modes.iter().rev() {
            stop_if_canceled(cancel)?;
            keep_remote_mode(session, path, *mode).await;
        }
    } else {
        if existing_kind == Some(FileType::Dir) {
            return Err(ToolError::new(format!(
                "{destination} is a folder on the server; give the full path of the file to write."
            )));
        }
        let mode = match request.mode {
            Some(mode) => UploadMode::Requested(mode),
            None => UploadMode::Kept(local_mode(&metadata)),
        };
        let mut transfer = TransferProgress {
            progress,
            cancel,
            done: 0,
            total: metadata.len(),
        };
        tally.bytes = upload_file(
            session,
            LocalFile {
                path: &local,
                follow_symlink: true,
            },
            &destination,
            mode,
            existing.is_some(),
            &mut transfer,
        )
        .await?;
        tally.files = 1;
    }
    Ok(format!(
        "Uploaded {} to {destination} in {}.{}",
        tally.describe(),
        format_duration(started.elapsed()),
        tally.skipped()
    ))
}

/// A local file to upload.
struct LocalFile<'a> {
    path: &'a Path,
    /// Whether a symlink at `path` is followed. An entry of a folder is not: the folder was listed
    /// with its symlinks kept as symlinks, so one found at a file's name was put there since.
    follow_symlink: bool,
}

/// The permissions an uploaded file gets.
#[derive(Clone, Copy)]
enum UploadMode {
    /// The local file's, kept when the server allows it.
    Kept(u32),
    /// The ones the caller asked for; the upload fails without them.
    Requested(u32),
}

/// Upload one file to a temporary name beside `destination`, then rename it into place, so an
/// interrupted upload never leaves a partial file under the destination name. `replace` allows an
/// existing file at `destination` to be replaced.
async fn upload_file(
    session: &SftpSession,
    source: LocalFile<'_>,
    destination: &str,
    mode: UploadMode,
    replace: bool,
    transfer: &mut TransferProgress<'_>,
) -> Result<u64, ToolError> {
    let LocalFile {
        path: source,
        follow_symlink,
    } = source;
    let (parent, name) = split_remote(destination);
    let temporary = join_remote(
        &parent,
        &format!(".{name}.ssh-mcp-{}.partial", random_hex(4)?),
    );
    let opened = tokio::task::spawn_blocking({
        let source = source.to_path_buf();
        move || open_regular_file(&source, follow_symlink)
    })
    .await
    .map_err(|error| ToolError::new(format!("Opening the file failed: {error}")))?;
    let mut local = match opened {
        Ok(Some(file)) => tokio::fs::File::from_std(file),
        Ok(None) => {
            return Err(ToolError::new(format!(
                "{} is not a regular file.",
                source.display()
            )));
        }
        Err(error) => return Err(local_failure("read", source, error)),
    };
    stop_if_canceled(transfer.cancel)?;
    // Set when the destination was removed but the new file could not take its place, so the
    // temporary file is the only copy left and must be kept.
    let mut keep_temporary = false;
    let result = async {
        let mut remote = session
            .open_with_flags(
                temporary.as_str(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            )
            .await
            .map_err(|error| sftp_failure("create", &temporary, error))?;
        let mut buffer = vec![0u8; COPY_CHUNK_BYTES];
        let mut copied = 0u64;
        loop {
            let read = local
                .read(&mut buffer)
                .await
                .map_err(|error| local_failure("read", source, error))?;
            if read == 0 {
                break;
            }
            remote
                .write_all(buffer.get(..read).unwrap_or_default())
                .await
                .map_err(|error| sftp_failure("write", destination, error))?;
            copied += read as u64;
            transfer.advance(read as u64, &name).await?;
        }
        remote
            .shutdown()
            .await
            .map_err(|error| sftp_failure("finish writing", destination, error))?;
        match mode {
            UploadMode::Kept(mode) => keep_remote_mode(session, &temporary, mode).await,
            UploadMode::Requested(mode) => set_remote_mode(session, &temporary, mode)
                .await
                .map_err(|error| sftp_failure("set the permissions of", destination, error))?,
        }
        stop_if_canceled(transfer.cancel)?;
        if let Err(error) = session.rename(temporary.as_str(), destination).await {
            // A rename whose answer was lost to a timeout may still have happened.
            if remote_entry(session, &temporary).await?.is_none() {
                return Ok(copied);
            }
            // SFTP's rename refuses an existing target on OpenSSH, and the posix-rename extension
            // is not available, so a file the caller asked to replace is removed first.
            if !replace || remote_entry(session, destination).await?.is_none() {
                return Err(sftp_failure("move into place", destination, error));
            }
            stop_if_canceled(transfer.cancel)?;
            session
                .remove_file(destination)
                .await
                .map_err(|error| sftp_failure("replace", destination, error))?;
            if let Err(error) = session.rename(temporary.as_str(), destination).await {
                if remote_entry(session, &temporary).await?.is_none() {
                    return Ok(copied);
                }
                keep_temporary = true;
                return Err(ToolError::new(format!(
                    "{destination} was removed to be replaced, but the new file could not be moved into its place ({}); the new file is kept at {temporary}.",
                    error.reason()
                )));
            }
        }
        Ok(copied)
    }
    .await;
    if result.is_err()
        && !keep_temporary
        && let Err(error) = session.remove_file(temporary.as_str()).await
    {
        tracing::debug!("the partial upload {temporary} could not be removed: {error}");
    }
    result
}

async fn set_remote_mode(session: &SftpSession, path: &str, mode: u32) -> Result<(), SftpError> {
    let mut attributes = FileAttributes::empty();
    attributes.permissions = Some(mode & 0o7777);
    session.set_metadata(path, attributes).await
}

/// Give a remote file or folder the permissions of what it was copied from where the server
/// allows it; some servers do not let permissions be set, and the copy is still made.
async fn keep_remote_mode(session: &SftpSession, path: &str, mode: u32) {
    if let Err(error) = set_remote_mode(session, path, mode).await {
        tracing::debug!("permissions of {path} could not be set: {error}");
    }
}

#[cfg(unix)]
fn local_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn local_mode(metadata: &std::fs::Metadata) -> u32 {
    match (metadata.is_dir(), metadata.permissions().readonly()) {
        (true, _) => 0o755,
        (false, true) => 0o444,
        (false, false) => 0o644,
    }
}

/// List a local folder's contents, each folder before its entries, without following symlinks.
/// Returns the entries and how many special files (sockets, devices, pipes) were left out.
fn walk_local(root: &Path) -> Result<(Vec<LocalEntry>, u64), ToolError> {
    let mut entries = Vec::new();
    let mut skipped_special = 0;
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(root.to_path_buf(), Vec::new())];
    while let Some((directory, relative)) = pending.pop() {
        let mut children: Vec<_> = std::fs::read_dir(&directory)
            .map_err(|error| local_failure("read", &directory, error))?
            .collect::<Result<_, _>>()
            .map_err(|error| local_failure("read", &directory, error))?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            let not_utf8 = || {
                ToolError::new(format!(
                    "{} has a name or target that is not UTF-8, which SFTP paths here cannot carry, so nothing was uploaded. Rename it, or pack the folder with tar and upload the archive.",
                    path.display()
                ))
            };
            let name = child.file_name().into_string().map_err(|_| not_utf8())?;
            let mut child_relative = relative.clone();
            child_relative.push(name);
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| local_failure("read", &path, error))?;
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(&path)
                    .map_err(|error| local_failure("read", &path, error))?
                    .into_os_string()
                    .into_string()
                    .map_err(|_| not_utf8())?;
                // A Windows link target uses backslashes; on Unix a backslash is part of a name.
                #[cfg(windows)]
                let target = target.replace('\\', "/");
                entries.push(LocalEntry::Symlink {
                    relative: child_relative,
                    target,
                });
            } else if metadata.is_dir() {
                entries.push(LocalEntry::Directory {
                    relative: child_relative.clone(),
                    mode: local_mode(&metadata),
                });
                pending.push((path, child_relative));
            } else if metadata.is_file() {
                entries.push(LocalEntry::File {
                    relative: child_relative,
                    mode: local_mode(&metadata),
                    size: metadata.len(),
                });
            } else {
                skipped_special += 1;
            }
        }
    }
    Ok((entries, skipped_special))
}

/// What `download` needs.
pub(crate) struct DownloadRequest {
    pub(crate) remote_path: String,
    pub(crate) local_path: String,
    pub(crate) overwrite: bool,
}

/// One entry of a remote folder being downloaded, relative to its root.
enum RemoteEntry {
    Directory {
        relative: Vec<String>,
        mode: Option<u32>,
    },
    File {
        relative: Vec<String>,
        mode: Option<u32>,
        size: u64,
    },
    Symlink {
        relative: Vec<String>,
        target: String,
    },
}

/// Copy a remote file or folder to this machine. This is the one tool that writes local files,
/// and it writes only under `local_path`.
pub(crate) async fn download(
    handle: &SshHandle,
    session: &SftpSession,
    request: DownloadRequest,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<String, ToolError> {
    let started = Instant::now();
    let source = remote_path(&request.remote_path);
    let local = resolve_local_path("local_path", &request.local_path)?;
    let metadata = session
        .metadata(source.as_str())
        .await
        .map_err(|error| sftp_failure("read", &source, error))?;
    let parent = local
        .parent()
        .ok_or_else(|| ToolError::new("local_path has no parent folder."))?;
    if !parent.is_dir() {
        return Err(ToolError::new(format!(
            "The folder {} does not exist on this machine.",
            parent.display()
        )));
    }
    let existing = local_entry(&local)?;
    if existing.is_some() && !request.overwrite {
        return Err(ToolError::new(format!(
            "{} already exists on this machine; pass overwrite to replace it.",
            local.display()
        )));
    }
    let mut tally = Tally::default();
    match metadata.file_type() {
        FileType::Dir => {
            if existing.as_ref().is_some_and(|metadata| !metadata.is_dir()) {
                return Err(ToolError::new(format!(
                    "{} exists on this machine and is not a folder.",
                    local.display()
                )));
            }
            let (entries, skipped_special) = {
                let lister = listing_session(handle, cancel).await?;
                walk_remote(&lister, session, &source, cancel).await?
            };
            tally.skipped_special = skipped_special;
            let total = entries
                .iter()
                .map(|entry| match entry {
                    RemoteEntry::File { size, .. } => *size,
                    _ => 0,
                })
                .sum();
            let mut transfer = TransferProgress {
                progress,
                cancel,
                done: 0,
                total,
            };
            if existing.is_none() {
                stop_if_canceled(cancel)?;
                create_local_directory(&local)?;
                tally.directories += 1;
            }
            // Folder permissions are set after their contents are written, so a read-only
            // folder does not refuse its own files. Folders that already existed keep theirs.
            let mut folder_modes = Vec::new();
            if existing.is_none() {
                folder_modes.push((local.clone(), metadata.permissions));
            }
            for entry in entries {
                stop_if_canceled(cancel)?;
                match entry {
                    RemoteEntry::Directory { relative, mode } => {
                        let path = local_join(&local, &relative);
                        match local_entry(&path)? {
                            Some(metadata) if metadata.is_dir() => {}
                            Some(_) => {
                                std::fs::remove_file(&path)
                                    .map_err(|error| local_failure("replaced", &path, error))?;
                                create_local_directory(&path)?;
                                folder_modes.push((path, mode));
                            }
                            None => {
                                create_local_directory(&path)?;
                                folder_modes.push((path, mode));
                            }
                        }
                        tally.directories += 1;
                    }
                    RemoteEntry::File {
                        relative,
                        mode,
                        size: _,
                    } => {
                        let path = local_join(&local, &relative);
                        let remote = join_remote(&source, &relative.join("/"));
                        tally.bytes +=
                            download_file(session, &remote, &path, mode, &mut transfer).await?;
                        tally.files += 1;
                    }
                    RemoteEntry::Symlink { relative, target } => {
                        let path = local_join(&local, &relative);
                        if local_entry(&path)?.is_some() {
                            std::fs::remove_file(&path)
                                .map_err(|error| local_failure("replaced", &path, error))?;
                        }
                        if create_local_symlink(&target, &path) {
                            tally.symlinks += 1;
                        } else {
                            tally.skipped_symlinks += 1;
                        }
                    }
                }
            }
            // Deepest first, so no folder loses write permission before the folders inside it.
            for (path, mode) in folder_modes.iter().rev() {
                stop_if_canceled(cancel)?;
                set_local_mode(path, *mode);
            }
        }
        FileType::File => {
            if existing.as_ref().is_some_and(std::fs::Metadata::is_dir) {
                return Err(ToolError::new(format!(
                    "{} is a folder on this machine; give the full path of the file to write.",
                    local.display()
                )));
            }
            let mut transfer = TransferProgress {
                progress,
                cancel,
                done: 0,
                total: metadata.len(),
            };
            tally.bytes = download_file(
                session,
                &source,
                &local,
                metadata.permissions,
                &mut transfer,
            )
            .await?;
            tally.files = 1;
        }
        _ => {
            return Err(ToolError::new(format!(
                "{source} is not a regular file or a folder; use exec to read it."
            )));
        }
    }
    Ok(format!(
        "Downloaded {} to {} in {}.{}",
        tally.describe(),
        local.display(),
        format_duration(started.elapsed()),
        tally.skipped()
    ))
}

fn create_local_directory(path: &Path) -> Result<(), ToolError> {
    std::fs::create_dir(path).map_err(|error| local_failure("created", path, error))
}

/// Whether a name the server listed is one plain path component on this machine. Anything else
/// (`..`, a separator, an absolute path, a Windows drive prefix, NUL) would let a server's listing
/// place files outside the download's destination.
fn is_plain_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    !name.contains('\0')
        && matches!(components.next(), Some(std::path::Component::Normal(part)) if part == name)
        && components.next().is_none()
}

/// A second SFTP session, used only to list folders. Its listing replies are read one at a time,
/// so a listing can be bounded; the main session's listing reads until the server says it is done.
async fn listing_session(
    handle: &SshHandle,
    cancel: &CancellationToken,
) -> Result<RawSftpSession, ToolError> {
    let stream = open_sftp_channel(handle, cancel).await?;
    let session = RawSftpSession::new_with_config(stream, sftp_config());
    tokio::select! {
        started = session.init() => {
            started.map_err(sftp_unavailable)?;
        }
        () = cancel.cancelled() => return Err(canceled()),
    }
    Ok(session)
}

/// The entries of one remote folder, except `.` and `..`, refusing more than `room` of them.
async fn list_folder(
    lister: &RawSftpSession,
    path: &str,
    room: usize,
    cancel: &CancellationToken,
) -> Result<Vec<(String, Metadata)>, ToolError> {
    let handle = lister
        .opendir(path)
        .await
        .map_err(|error| sftp_failure("list", path, error))?
        .handle;
    let mut entries = Vec::new();
    let listed = loop {
        let reply = tokio::select! {
            reply = lister.readdir(handle.as_str()) => reply,
            () = cancel.cancelled() => break Err(canceled()),
        };
        match reply {
            Ok(name) => {
                entries.extend(
                    name.files
                        .into_iter()
                        .filter(|file| file.filename != "." && file.filename != "..")
                        .map(|file| (file.filename, file.attrs)),
                );
                if entries.len() > room {
                    break Err(ToolError::new(format!(
                        "The folder holds more than {MAX_LISTED_ENTRIES} entries, more than one download copies. Download its subfolders separately, or pack it with exec (tar) and download the archive."
                    )));
                }
            }
            Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => {
                break Ok(());
            }
            Err(error) => break Err(sftp_failure("list", path, error)),
        }
    };
    if let Err(error) = lister.close(handle).await {
        tracing::debug!("the listing of {path} could not be closed: {error}");
    }
    listed.map(|()| entries)
}

/// List a remote folder's contents, each folder before its entries, without following symlinks.
/// Returns the entries and how many special files (sockets, devices, pipes) were left out.
async fn walk_remote(
    lister: &RawSftpSession,
    session: &SftpSession,
    root: &str,
    cancel: &CancellationToken,
) -> Result<(Vec<RemoteEntry>, u64), ToolError> {
    let mut entries = Vec::new();
    let mut skipped_special = 0;
    let mut listed = 0;
    let mut pending: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(relative) = pending.pop() {
        let directory = if relative.is_empty() {
            root.to_owned()
        } else {
            join_remote(root, &relative.join("/"))
        };
        let mut children = list_folder(
            lister,
            &directory,
            MAX_LISTED_ENTRIES.saturating_sub(listed),
            cancel,
        )
        .await?;
        listed += children.len();
        children.sort_by(|first, second| first.0.cmp(&second.0));
        for (name, metadata) in children {
            if !is_plain_name(&name) {
                return Err(ToolError::new(format!(
                    "The server listed an entry named {name:?} in {directory}, which is not a plain file name, so nothing was downloaded."
                )));
            }
            let mut child_relative = relative.clone();
            child_relative.push(name);
            match metadata.file_type() {
                FileType::Symlink => {
                    let path = join_remote(root, &child_relative.join("/"));
                    let target = session
                        .read_link(path.as_str())
                        .await
                        .map_err(|error| sftp_failure("read the symlink", &path, error))?;
                    entries.push(RemoteEntry::Symlink {
                        relative: child_relative,
                        target,
                    });
                }
                FileType::Dir => {
                    entries.push(RemoteEntry::Directory {
                        relative: child_relative.clone(),
                        mode: metadata.permissions,
                    });
                    pending.push(child_relative);
                }
                FileType::File => entries.push(RemoteEntry::File {
                    relative: child_relative,
                    mode: metadata.permissions,
                    size: metadata.len(),
                }),
                FileType::Other => skipped_special += 1,
            }
        }
    }
    Ok((entries, skipped_special))
}

/// Download one file to a temporary name beside `destination`, then rename it into place, so an
/// interrupted download never leaves a partial file under the destination name.
async fn download_file(
    session: &SftpSession,
    source: &str,
    destination: &Path,
    mode: Option<u32>,
    transfer: &mut TransferProgress<'_>,
) -> Result<u64, ToolError> {
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary =
        destination.with_file_name(format!(".{name}.ssh-mcp-{}.partial", random_hex(4)?));
    // Created new and private: it never follows something already at the name, and the content
    // is not readable by others before its permissions are set.
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    stop_if_canceled(transfer.cancel)?;
    let mut local = options
        .open(&temporary)
        .await
        .map_err(|error| local_failure("created", &temporary, error))?;
    let result = async {
        let mut remote = session
            .open(source)
            .await
            .map_err(|error| sftp_failure("open", source, error))?;
        let mut buffer = vec![0u8; COPY_CHUNK_BYTES];
        let mut copied = 0u64;
        loop {
            let read = remote
                .read(&mut buffer)
                .await
                .map_err(|error| sftp_failure("read", source, error))?;
            if read == 0 {
                break;
            }
            local
                .write_all(buffer.get(..read).unwrap_or_default())
                .await
                .map_err(|error| local_failure("written", &temporary, error))?;
            copied += read as u64;
            transfer.advance(read as u64, &name).await?;
        }
        local
            .flush()
            .await
            .map_err(|error| local_failure("written", &temporary, error))?;
        drop(local);
        stop_if_canceled(transfer.cancel)?;
        set_local_mode(&temporary, mode);
        // Replaces an existing file, on Windows as well.
        std::fs::rename(&temporary, destination)
            .map_err(|error| local_failure("moved into place", destination, error))?;
        Ok(copied)
    }
    .await;
    if result.is_err()
        && let Err(error) = std::fs::remove_file(&temporary)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(
            "the partial download {} could not be removed: {error}",
            temporary.display()
        );
    }
    result
}

/// Give a downloaded file or folder the server's permission bits, without setuid, setgid or
/// sticky: a server must not be able to plant a setuid program on this machine.
#[cfg(unix)]
fn set_local_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode
        && let Err(error) =
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))
    {
        tracing::debug!(
            "permissions of {} could not be set: {error}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn set_local_mode(_path: &Path, _mode: Option<u32>) {}

#[cfg(unix)]
fn create_local_symlink(target: &str, path: &Path) -> bool {
    match std::os::unix::fs::symlink(target, path) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!("symlink {} could not be created: {error}", path.display());
            false
        }
    }
}

#[cfg(windows)]
fn create_local_symlink(target: &str, path: &Path) -> bool {
    match std::os::windows::fs::symlink_file(target, path) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!("symlink {} could not be created: {error}", path.display());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tilde_path_is_relative_to_the_login_directory() {
        assert_eq!(remote_path("~"), ".");
        assert_eq!(remote_path("~/"), ".");
        assert_eq!(remote_path("~/notes.txt"), "notes.txt");
        assert_eq!(remote_path("/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn names_a_server_lists_must_stay_inside_the_destination() {
        assert!(is_plain_name("notes.txt"));
        assert!(is_plain_name(".hidden"));
        for hostile in ["", ".", "..", "../x", "a/b", "/etc/passwd", "a\0b"] {
            assert!(!is_plain_name(hostile), "{hostile:?} is accepted");
        }
        #[cfg(windows)]
        for hostile in ["C:x", "a\\b", "\\\\server\\share"] {
            assert!(!is_plain_name(hostile), "{hostile:?} is accepted");
        }
    }

    #[test]
    fn remote_paths_split_into_folder_and_name() {
        assert_eq!(
            split_remote("/srv/app/a.txt"),
            ("/srv/app".to_owned(), "a.txt".to_owned())
        );
        assert_eq!(split_remote("/a.txt"), ("/".to_owned(), "a.txt".to_owned()));
        assert_eq!(split_remote("a.txt"), (".".to_owned(), "a.txt".to_owned()));
        assert_eq!(join_remote("/", "a"), "/a");
        assert_eq!(join_remote("dir", "a"), "dir/a");
    }

    #[test]
    fn a_local_folder_is_listed_before_its_entries() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("sub/inner.txt"), "x").unwrap();
        std::fs::write(root.path().join("top.txt"), "yy").unwrap();
        let (entries, skipped) = walk_local(root.path()).unwrap();
        assert_eq!(skipped, 0);
        let names: Vec<String> = entries
            .iter()
            .map(|entry| match entry {
                LocalEntry::Directory { relative, .. } => format!("d:{}", relative.join("/")),
                LocalEntry::File { relative, size, .. } => {
                    format!("f:{}:{size}", relative.join("/"))
                }
                LocalEntry::Symlink { relative, .. } => format!("l:{}", relative.join("/")),
            })
            .collect();
        let sub = names.iter().position(|name| name == "d:sub").unwrap();
        let inner = names
            .iter()
            .position(|name| name == "f:sub/inner.txt:1")
            .unwrap();
        assert!(sub < inner);
        assert!(names.contains(&"f:top.txt:2".to_owned()));
    }

    #[test]
    fn special_remote_files_are_not_taken_for_folders_or_files() {
        let mut attributes = FileAttributes::empty();
        for (bits, expected) in [
            (0o040_755, FileType::Dir),
            (0o100_644, FileType::File),
            (0o120_777, FileType::Symlink),
            (0o140_755, FileType::Other),
            (0o060_660, FileType::Other),
            (0o010_644, FileType::Other),
        ] {
            attributes.permissions = Some(bits);
            assert_eq!(attributes.file_type(), expected, "{bits:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_local_socket_is_counted_as_skipped() {
        let root = tempfile::tempdir().unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(root.path().join("socket")).unwrap();
        std::fs::write(root.path().join("file"), "x").unwrap();
        let (entries, skipped) = walk_local(root.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(skipped, 1);
    }
}
