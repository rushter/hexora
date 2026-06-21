use crate::features::StringStats;
use crate::schema::FeatureRecord;
use hexora_io::locator::Locator;

pub(crate) fn extract_source_features(
    record: &mut FeatureRecord,
    _locator: &Locator<'_>,
    source: &str,
) {
    let lines: Vec<&str> = source.lines().collect();
    let num_lines = lines.len() as f64;
    let num_nonempty_lines = lines.iter().filter(|line| !line.trim().is_empty()).count() as f64;
    let num_comment_lines = lines
        .iter()
        .filter(|line| line.trim_start().starts_with('#'))
        .count() as f64;
    let longest_line = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as f64;
    let total_line_length = lines.iter().map(|line| line.chars().count()).sum::<usize>() as f64;
    let ascii_chars = source.chars().filter(|ch| ch.is_ascii()).count() as f64;
    let total_chars = source.chars().count() as f64;

    record.insert("source.num_lines", num_lines);
    record.insert("source.num_nonempty_lines", num_nonempty_lines);
    record.insert("source.num_comment_lines", num_comment_lines);
    record.insert("source.num_bytes", source.len() as f64);
    record.insert("source.longest_line", longest_line);
    record.insert(
        "source.avg_line_length",
        if num_lines > 0.0 {
            total_line_length / num_lines
        } else {
            0.0
        },
    );
    record.insert(
        "source.non_ascii_ratio",
        if total_chars > 0.0 {
            1.0 - (ascii_chars / total_chars)
        } else {
            0.0
        },
    );

    let mut string_stats = StringStats::default();
    for line in &lines {
        if !line.is_empty() {
            string_stats.observe(line);
        }
    }

    record.insert("source.max_line_entropy", string_stats.max_entropy);
    record.insert("source.mean_line_entropy", string_stats.mean_entropy());
}
