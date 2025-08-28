use crate::audit::annotate::annotate_result;
use crate::audit::parse::audit_path;
use crate::audit::result::{AuditConfidence, AuditItem};
use crate::audit::result::{AuditItemJSON, Rule};
use clap::{Args, Parser, Subcommand};
use env_logger::Env;
use log::{error, info};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

#[derive(Clone, Debug)]
enum OutputFormat {
    Terminal,
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Parser)]
#[command(name = "hexora")]
#[command(about = "Hexora Command Line Interface", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(
        long,
        default_value = "error",
        help = "Logging level (trace, debug, info, warn, error)",
        global = true
    )]
    logging_level: String,
}

#[derive(Args, Clone, Debug)]
struct AuditOptions {
    #[arg(
        help = "Input path to a file or directory containing Python files.",
        index = 1
    )]
    input_path: PathBuf,

    #[arg(
        long,
        help = "Output path for results. If not specified, results will be printed to stdout."
    )]
    output_path: Option<PathBuf>,

    #[arg(
        long,
        help = "Output format: terminal | json ",
        default_value = "terminal"
    )]
    output_format: OutputFormat,

    #[arg(
        long = "annotate",
        help = "Include code annotations preview in JSON output."
    )]
    output_annotations: bool,

    #[arg(long, help = "Dump annotated files to the specified folder.")]
    dump_annotated: Option<PathBuf>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Exclude specific detection codes. Comma separated list."
    )]
    exclude: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Include only specific detection codes. Comma separated list. If provided, only these codes will be included."
    )]
    include: Vec<String>,

    #[arg(
        long,
        default_value = "low",
        help = "Minimum confidence level for detections to be included in the results. Supported values: low, \
            medium, high, very_high, very_low"
    )]
    min_confidence: AuditConfidence,
}
#[derive(Subcommand)]
enum Commands {
    Audit {
        #[command(flatten)]
        opts: AuditOptions,
    },

    Rules,
}

#[allow(clippy::format_in_format_args)]
fn print_rules_markdown() {
    println!("| Code | Name | Description |");
    println!("|---|---|---|");
    for rule in Rule::iter() {
        println!(
            "| {} | {} | {} |",
            rule.code(),
            format!("{:?}", rule),
            rule.description()
        );
    }
}

fn write_annotations(
    file_out: &mut Box<dyn Write>,
    item: &AuditItem,
    path: &Path,
    source_code: &str,
    colored: bool,
) {
    match annotate_result(item, path, source_code, colored) {
        Ok(annotation) => {
            writeln!(file_out, "{}", annotation)
                .unwrap_or_else(|e| error!("Failed to write annotation: {:?}", e));
        }
        Err(e) => {
            error!("Failed to annotate result: {}", e);
        }
    }
}

fn write_json(
    file_out: &mut Box<dyn Write>,
    item: &AuditItem,
    path: &Path,
    source_code: &str,
    annotate: bool,
) {
    let item = AuditItemJSON::new(item, path, source_code, annotate);
    match serde_json::to_string(&item) {
        Ok(json) => {
            writeln!(file_out, "{}", json)
                .unwrap_or_else(|e| error!("Failed to write json: {:?}", e));
        }
        Err(e) => {
            error!("Failed to serialize result to json: {:?}", e);
        }
    }
}

fn process_result<'a, I>(
    result: I,
    path: &Path,
    source_code: &str,
    colored: bool,
    output_path: &Option<PathBuf>,
    output_format: &OutputFormat,
    output_annotations: bool,
) -> Result<(), std::io::Error>
where
    I: Iterator<Item = &'a AuditItem>,
{
    let mut file_out: Box<dyn Write> = if let Some(output_path) = output_path {
        let file_out = std::fs::File::create(output_path)?;
        Box::new(file_out)
    } else {
        Box::new(std::io::stdout())
    };

    for item in result {
        match output_format {
            OutputFormat::Terminal => {
                write_annotations(&mut file_out, item, path, source_code, colored);
            }
            OutputFormat::Json => {
                write_json(&mut file_out, item, path, source_code, output_annotations);
            }
        }
    }
    Ok(())
}

fn audit_python_files(opts: &AuditOptions) {
    let colored = opts.output_path.is_none();
    let dump_dir = if let Some(dir) = &opts.dump_annotated {
        if dir.exists() && !dir.is_dir() {
            error!("Dump path {:?} exists but it is not a directory", dir);
            return;
        }
        if let Err(e) = fs::create_dir_all(&dir) {
            error!("Failed to create dump directory {:?}: {:?}", dir, e);
        }
        Some(dir.clone())
    } else {
        None
    };

    match audit_path(&opts.input_path) {
        Ok(results) => {
            for result in results {
                let filtered =
                    result.filter_items(&opts.include, &opts.exclude, &opts.min_confidence);
                if let Err(e) = process_result(
                    filtered,
                    &result.path,
                    &result.source_code,
                    colored,
                    &opts.output_path,
                    &opts.output_format,
                    opts.output_annotations,
                ) {
                    error!("{:?}", e);
                }
                if let Some(ref dest) = dump_dir {
                    result.annotate_to_file(dest);
                }
            }
        }
        Err(e) => {
            error!("{:?}", e);
        }
    }
}

pub fn run_cli(start_arg: usize) {
    let start = Instant::now();
    let cli = Cli::parse_from(std::env::args().skip(start_arg));

    let env = Env::default().default_filter_or(cli.logging_level);
    env_logger::Builder::from_env(env).init();

    match cli.command {
        Commands::Audit { opts } => {
            audit_python_files(&opts);
        }
        Commands::Rules => {
            print_rules_markdown();
        }
    }

    let end = Instant::now();
    let duration = end.duration_since(start);
    info!("Total execution time: {duration:?}");
}
