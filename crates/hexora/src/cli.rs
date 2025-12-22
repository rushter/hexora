use crate::audit::annotate::annotate_result;
use crate::audit::parse::audit_path;
use crate::audit::result::{AuditConfidence, AuditItem, AuditResult};
use crate::audit::result::{AuditItemJSON, Rule};
use crate::benchmark::run_benchmark;
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
#[derive(Args, Clone, Debug)]
struct BenchmarkOptions {
    #[arg(
        help = "Input path to a file or directory containing Python files.",
        index = 1
    )]
    input_path: PathBuf,

    #[arg(long, help = "Print zip paths with missing audits.")]
    print_missing: bool,

    #[arg(
        long,
        help = "Path to a txt file containing file names that should be skipped when benchmarking."
    )]
    exclude_path: Option<PathBuf>,

    #[arg(
        long,
        default_value = "very_low",
        help = "Minimum confidence level for detections to be included in the results. Supported values: very_low, low, \
            medium, high, very_high."
    )]
    min_confidence: AuditConfidence,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a file or directory for malicious patterns.
    Audit {
        #[command(flatten)]
        opts: AuditOptions,
    },

    /// List all available rules and their descriptions.
    Rules,

    /// Run a performance benchmark on a set of files.
    Benchmark {
        #[command(flatten)]
        opts: BenchmarkOptions,
    },

    /// This command is used to safely inspect archived malicious package.
    DumpPackage {
        #[arg(help = "Path to the zip file.", index = 1)]
        path: PathBuf,

        #[arg(long, help = "Filter files by name (contains pattern)")]
        filter: Option<String>,
    },
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
    file_out: &mut dyn Write,
    item: &AuditItem,
    path: &Path,
    archive_path: Option<&Path>,
    source_code: &str,
    colored: bool,
) {
    match annotate_result(item, path, archive_path, source_code, colored) {
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
    file_out: &mut dyn Write,
    item: &AuditItem,
    path: &Path,
    archive_path: Option<&Path>,
    source_code: &str,
    annotate: bool,
) {
    let item = AuditItemJSON::new(item, path, archive_path, source_code, annotate);
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

struct AuditOutput {
    writer: Box<dyn Write>,
    format: OutputFormat,
    annotate: bool,
    colored: bool,
}

impl AuditOutput {
    fn new(opts: &AuditOptions) -> Result<Self, std::io::Error> {
        let writer: Box<dyn Write> = if let Some(path) = &opts.output_path {
            Box::new(std::fs::File::create(path)?)
        } else {
            Box::new(std::io::stdout())
        };

        Ok(Self {
            writer,
            format: opts.output_format.clone(),
            annotate: opts.output_annotations,
            colored: opts.output_path.is_none(),
        })
    }

    fn write_result(&mut self, result: &AuditResult, items: &[AuditItem]) {
        for item in items {
            match self.format {
                OutputFormat::Terminal => {
                    write_annotations(
                        &mut *self.writer,
                        item,
                        &result.path,
                        result.archive_path.as_deref(),
                        &result.source_code,
                        self.colored,
                    );
                }
                OutputFormat::Json => {
                    write_json(
                        &mut *self.writer,
                        item,
                        &result.path,
                        result.archive_path.as_deref(),
                        &result.source_code,
                        self.annotate,
                    );
                }
            }
        }
    }
}

fn audit_python_files(opts: &AuditOptions) {
    let mut output = match AuditOutput::new(opts) {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to initialize output: {:?}", e);
            return;
        }
    };

    let dump_dir = if let Some(path) = &opts.dump_annotated {
        if path.exists() && !path.is_dir() {
            error!("Dump path {:?} exists but it is not a directory", path);
            return;
        }
        if let Err(e) = fs::create_dir_all(path) {
            error!("Failed to create dump directory {:?}: {:?}", path, e);
        }
        Some(path.clone())
    } else {
        None
    };

    match audit_path(&opts.input_path, None) {
        Ok(results) => {
            for result in results {
                let filtered: Vec<AuditItem> = result
                    .filter_items(&opts.include, &opts.exclude, &opts.min_confidence)
                    .collect();

                output.write_result(&result, &filtered);

                if let Some(ref dest) = dump_dir {
                    result.annotate_to_file(&filtered, dest);
                }
            }
        }
        Err(e) => {
            error!("Can't audit specified path: {:?}", e);
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
        Commands::Benchmark { opts } => {
            let exclude_names = opts.exclude_path.as_ref().and_then(|path| {
                hexora_io::read_exclude_names(path)
                    .map_err(|e| {
                        error!("Failed to read exclude file: {}", e);
                    })
                    .ok()
            });
            if exclude_names.is_none() && opts.exclude_path.is_some() {
                return;
            }

            match run_benchmark(
                &opts.input_path,
                exclude_names.as_ref(),
                opts.min_confidence,
            ) {
                Ok(result) => {
                    result.print_results(opts.print_missing);
                }
                Err(e) => {
                    error!("Benchmark failed: {}", e);
                }
            }
        }
        Commands::DumpPackage { path, filter } => {
            if let Err(e) = hexora_io::dump_package(&path, filter.as_deref()) {
                error!("Dump package failed: {}", e);
            }
        }
    }

    let end = Instant::now();
    let duration = end.duration_since(start);
    info!("Total execution time: {duration:?}");
}
