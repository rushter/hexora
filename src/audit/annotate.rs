use crate::audit::result::AuditItem;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::Buffer;
use std::path::Path;

pub fn annotate_result(
    item: &AuditItem,
    path: &Path,
    source_code: &str,
    colored: bool,
) -> Result<String, String> {
    let mut buffer = if colored {
        Buffer::ansi()
    } else {
        Buffer::no_color()
    };
    if let Some(location) = item.location {
        let file_path = path.display();
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
