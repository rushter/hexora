use crate::audit::result::AuditItem;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::Buffer;
use std::path::Path;

fn display_path(path: &Path, archive_path: Option<&Path>) -> String {
    if let Some(zip) = archive_path {
        format!("{}:{}", zip.display(), path.display())
    } else {
        path.display().to_string()
    }
}

pub fn annotation_preview(
    item: &AuditItem,
    path: &Path,
    archive_path: Option<&Path>,
    source_code: &str,
    context_lines: usize,
) -> Result<String, String> {
    let Some(location) = item.location else {
        return Ok(String::new());
    };

    let start = location.start().to_usize().min(source_code.len());
    let end = location.end().to_usize().min(source_code.len());
    let mut line_starts = vec![0usize];
    for (idx, ch) in source_code.char_indices() {
        if ch == '\n' {
            line_starts.push(idx + 1);
        }
    }
    line_starts.push(source_code.len() + 1);

    let start_line = line_starts.partition_point(|line_start| *line_start <= start);
    let end_line = line_starts.partition_point(|line_start| *line_start <= end);
    let first_line = start_line.saturating_sub(context_lines + 1);
    let last_line = (end_line + context_lines).min(line_starts.len().saturating_sub(2));

    let mut preview = String::new();
    preview.push_str(&format!(
        "{}:{}-{} [{} {:?}]\n",
        display_path(path, archive_path),
        start,
        end,
        item.rule.code(),
        item.confidence
    ));

    for line_index in first_line..=last_line {
        let line_start = line_starts[line_index];
        let line_end = line_starts[line_index + 1]
            .saturating_sub(1)
            .min(source_code.len());
        let line = &source_code[line_start..line_end];
        let marker = if start < line_end + 1 && end >= line_start {
            '>'
        } else {
            ' '
        };
        preview.push_str(&format!("{} {:4} | {}\n", marker, line_index + 1, line));
    }

    Ok(preview)
}

// Annotate findings for a single result
pub fn annotate_result(
    item: &AuditItem,
    path: &Path,
    archive_path: Option<&Path>,
    source_code: &str,
    colored: bool,
) -> Result<String, String> {
    let mut buffer = if colored {
        Buffer::ansi()
    } else {
        Buffer::no_color()
    };
    if let Some(location) = item.location {
        let file_path = display_path(path, archive_path);
        let file = SimpleFile::new(&file_path, &source_code);
        let diagnostic = Diagnostic::warning()
            .with_message(&item.description)
            .with_code(item.rule.code())
            .with_labels(vec![
                Label::primary((), location.start().to_usize()..location.end().to_usize())
                    .with_message(item.rule.code()),
            ])
            .with_note({
                let mut note = String::new();
                note.push_str(format!("Confidence: {:?}\n", &item.confidence).as_str());
                if let Some(help_msg) = item.rule.help() {
                    note.push_str(format!("Help: {}", help_msg).as_str());
                }
                note
            });

        let config = term::Config {
            before_label_lines: 3,
            after_label_lines: 3,
            ..Default::default()
        };
        if let Err(e) = term::emit(&mut buffer, &config, &file, &diagnostic) {
            return Err(e.to_string());
        }
    }
    Ok(String::from_utf8_lossy(buffer.as_slice()).to_string())
}

// Annotate findings for a single result
pub fn annotate_results<'a>(
    items: impl IntoIterator<Item = &'a AuditItem>,
    path: &Path,
    archive_path: Option<&Path>,
    source_code: &str,
) -> Result<String, String> {
    let mut buffer = Buffer::no_color();
    let labels = items
        .into_iter()
        .filter_map(|item| {
            if let Some(location) = item.location {
                return Some(
                    Label::primary((), location.start().to_usize()..location.end().to_usize())
                        .with_message(
                            format!("{}: {}", item.rule.code(), item.description).as_str(),
                        ),
                );
            }
            None
        })
        .collect();

    let file_path = display_path(path, archive_path);
    let file = SimpleFile::new(&file_path, &source_code);
    let diagnostic = Diagnostic::warning().with_labels(labels);

    let config = term::Config {
        before_label_lines: 3,
        after_label_lines: 3,
        ..Default::default()
    };
    if let Err(e) = term::emit(&mut buffer, &config, &file, &diagnostic) {
        return Err(e.to_string());
    }
    Ok(String::from_utf8_lossy(buffer.as_slice()).to_string())
}
