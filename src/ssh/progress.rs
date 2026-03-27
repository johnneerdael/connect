use std::io::IsTerminal;
use std::time::Instant;

use crossterm::terminal;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressMode {
    Hidden,
    Interactive,
    LogLines,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProgressRenderOptions {
    pub initial_copied: u64,
    pub finish_line: bool,
    pub started_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateProgressSnapshot {
    pub label: String,
    pub copied_bytes: u64,
    pub total_bytes: u64,
    pub resumed_bytes: u64,
    pub effective_threads: usize,
    pub failed_files: usize,
}

pub(crate) struct ThreadedProgressReporter<W> {
    writer: W,
    mode: ProgressMode,
    terminal_columns: usize,
    started_at: Instant,
    rendered: bool,
}

impl ProgressMode {
    pub(crate) fn from_stderr(show_progress_override: bool) -> Self {
        if std::io::stderr().is_terminal() {
            Self::Interactive
        } else if show_progress_override {
            Self::LogLines
        } else {
            Self::Hidden
        }
    }
}

impl<W> ThreadedProgressReporter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(writer: W, mode: ProgressMode) -> Self {
        Self::with_columns(writer, mode, interactive_progress_columns())
    }

    pub(crate) fn with_columns(writer: W, mode: ProgressMode, terminal_columns: usize) -> Self {
        Self {
            writer,
            mode,
            terminal_columns,
            started_at: Instant::now(),
            rendered: false,
        }
    }

    pub(crate) async fn render(&mut self, snapshot: &AggregateProgressSnapshot) -> Result<()> {
        let throughput = format_transfer_rate(
            snapshot.copied_bytes.saturating_sub(snapshot.resumed_bytes),
            self.started_at,
        );
        print_progress(
            &mut self.writer,
            &format_aggregate_progress_line(snapshot),
            snapshot.copied_bytes,
            Some(snapshot.total_bytes),
            throughput.as_deref(),
            self.mode,
            self.terminal_columns,
        )
        .await?;
        self.rendered = true;
        Ok(())
    }

    pub(crate) async fn finish(&mut self) -> Result<()> {
        if self.mode == ProgressMode::Interactive && self.rendered {
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;
        }
        Ok(())
    }
}

pub(crate) fn progress_label(
    direction: &str,
    local_path: &std::path::Path,
    remote_path: &str,
) -> String {
    format!("{direction} {} <-> {remote_path}", local_path.display())
}

pub(crate) async fn print_progress<W>(
    writer: &mut W,
    label: &str,
    copied: u64,
    total_bytes: Option<u64>,
    throughput: Option<&str>,
    progress_mode: ProgressMode,
    terminal_columns: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match progress_mode {
        ProgressMode::Hidden => {}
        ProgressMode::Interactive => {
            let line = format_interactive_progress_line(
                label,
                copied,
                total_bytes,
                throughput,
                terminal_columns,
            );
            writer.write_all(b"\r\x1b[2K").await?;
            writer.write_all(line.as_bytes()).await?;
        }
        ProgressMode::LogLines => {
            let line = format_progress_line(label, copied, total_bytes, throughput);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }
    }
    writer.flush().await?;
    Ok(())
}

pub(crate) fn format_progress_line(
    label: &str,
    copied: u64,
    total_bytes: Option<u64>,
    throughput: Option<&str>,
) -> String {
    let mut progress = match total_bytes {
        Some(total) if total > 0 => format!("{copied}/{total} bytes"),
        _ => format!("{copied} bytes"),
    };
    if let Some(throughput) = throughput {
        progress.push_str(" at ");
        progress.push_str(throughput);
    }
    format!("{label}: {progress}")
}

pub(crate) fn format_interactive_progress_line(
    label: &str,
    copied: u64,
    total_bytes: Option<u64>,
    throughput: Option<&str>,
    terminal_columns: usize,
) -> String {
    let mut progress = match total_bytes {
        Some(total) if total > 0 => format!("{copied}/{total} bytes"),
        _ => format!("{copied} bytes"),
    };
    if let Some(throughput) = throughput {
        progress.push_str(" at ");
        progress.push_str(throughput);
    }
    let available_width = terminal_columns.saturating_sub(1);
    let reserved_width = progress.chars().count() + 2;
    if available_width <= reserved_width {
        return progress;
    }

    let truncated_label = truncate_middle(label, available_width - reserved_width);
    format!("{truncated_label}: {progress}")
}

fn format_aggregate_progress_line(snapshot: &AggregateProgressSnapshot) -> String {
    let mut details = vec![
        format!("resumed {}", snapshot.resumed_bytes),
        format!("threads {}", snapshot.effective_threads),
    ];
    if snapshot.failed_files > 0 {
        details.push(format!("failed {}", snapshot.failed_files));
    }

    format!("{} [{}]", snapshot.label, details.join(", "))
}

pub(crate) fn format_transfer_rate(transferred_bytes: u64, started_at: Instant) -> Option<String> {
    if transferred_bytes == 0 {
        return None;
    }

    let elapsed_seconds = started_at.elapsed().as_secs_f64().max(0.001);
    let bytes_per_second = transferred_bytes as f64 / elapsed_seconds;
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return None;
    }

    Some(format_rate_value(bytes_per_second))
}

fn format_rate_value(bytes_per_second: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];

    let mut value = bytes_per_second;
    let mut unit_index = 0;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{value:.0} {}", UNITS[unit_index])
    } else {
        format!("{value:.1} {}", UNITS[unit_index])
    }
}

fn interactive_progress_columns() -> usize {
    terminal::size()
        .ok()
        .map(|(columns, _)| usize::from(columns))
        .filter(|columns| *columns > 0)
        .unwrap_or(80)
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }

    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }

    let prefix_len = (max_chars - 3) / 2;
    let suffix_len = max_chars - 3 - prefix_len;
    let prefix: String = value.chars().take(prefix_len).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(suffix_len)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    #[tokio::test]
    async fn threaded_interactive_progress_renders_one_aggregate_line() {
        let (mut reader, writer) = duplex(1024);
        let mut reporter =
            ThreadedProgressReporter::with_columns(writer, ProgressMode::Interactive, 80);
        let first = AggregateProgressSnapshot {
            label: "threaded upload /tmp/artifact".into(),
            copied_bytes: 64,
            total_bytes: 256,
            resumed_bytes: 0,
            effective_threads: 4,
            failed_files: 0,
        };
        let second = AggregateProgressSnapshot {
            copied_bytes: 256,
            ..first.clone()
        };

        reporter.render(&first).await.unwrap();
        reporter.render(&second).await.unwrap();
        reporter.finish().await.unwrap();
        drop(reporter);

        let mut output = String::new();
        reader.read_to_string(&mut output).await.unwrap();
        assert!(output.contains('\r'));
        assert_eq!(output.matches('\n').count(), 1);
        assert!(output.contains("64/256 bytes") || output.contains("256/256 bytes"));
        assert!(output.contains("/s"));
    }

    #[tokio::test]
    async fn explicit_non_interactive_progress_uses_snapshots_only_when_requested() {
        let snapshot = AggregateProgressSnapshot {
            label: "threaded download /tmp/archive".into(),
            copied_bytes: 10,
            total_bytes: 20,
            resumed_bytes: 5,
            effective_threads: 3,
            failed_files: 0,
        };

        let (mut visible_reader, visible_writer) = duplex(1024);
        let mut visible =
            ThreadedProgressReporter::with_columns(visible_writer, ProgressMode::LogLines, 80);
        visible.render(&snapshot).await.unwrap();
        visible.finish().await.unwrap();
        drop(visible);

        let mut visible_output = String::new();
        visible_reader
            .read_to_string(&mut visible_output)
            .await
            .unwrap();
        assert!(visible_output.contains('\n'));
        assert!(visible_output.contains("/s"));

        let (mut hidden_reader, hidden_writer) = duplex(1024);
        let mut hidden =
            ThreadedProgressReporter::with_columns(hidden_writer, ProgressMode::Hidden, 80);
        hidden.render(&snapshot).await.unwrap();
        hidden.finish().await.unwrap();
        drop(hidden);

        let mut hidden_output = String::new();
        hidden_reader
            .read_to_string(&mut hidden_output)
            .await
            .unwrap();
        assert_eq!(hidden_output, "");
    }

    #[tokio::test]
    async fn threaded_recursive_progress_does_not_emit_per_file_lines() {
        let (mut reader, writer) = duplex(1024);
        let mut reporter =
            ThreadedProgressReporter::with_columns(writer, ProgressMode::Interactive, 80);

        for copied in [8_u64, 16, 24, 32] {
            reporter
                .render(&AggregateProgressSnapshot {
                    label: "threaded upload /tmp/tree".into(),
                    copied_bytes: copied,
                    total_bytes: 32,
                    resumed_bytes: 4,
                    effective_threads: 4,
                    failed_files: 0,
                })
                .await
                .unwrap();
        }
        reporter.finish().await.unwrap();
        drop(reporter);

        let mut output = String::new();
        reader.read_to_string(&mut output).await.unwrap();
        assert_eq!(output.matches('\n').count(), 1);
        assert!(output.matches('\r').count() >= 4);
        assert!(output.contains("/s"));
    }

    #[test]
    fn interactive_progress_line_truncates_long_labels_to_terminal_width() {
        let line = format_interactive_progress_line(
            "download npa_publisher_wizard/npa_publisher_wizard <-> /home/jneerdael/npa_publisher_wizard/npa_publisher_wizard",
            42,
            Some(1024),
            None,
            40,
        );

        assert!(line.chars().count() <= 39);
        assert!(line.contains("..."));
        assert!(line.ends_with(": 42/1024 bytes"));
    }

    #[test]
    fn progress_line_can_include_transfer_rate() {
        let line = format_progress_line(
            "upload artifact.bin",
            1024,
            Some(4096),
            Some("2.0 MiB/s"),
        );

        assert_eq!(line, "upload artifact.bin: 1024/4096 bytes at 2.0 MiB/s");
    }
}
