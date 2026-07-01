use clap::{Args, Subcommand};
use hexora_rules::result::AuditConfidence;
use std::path::PathBuf;

#[derive(Args, Clone, Debug)]
pub struct GenerateFeaturesOptions {
    #[arg(long, help = "Path to the JSON lines dataset file.", required = true)]
    pub input_path: PathBuf,

    #[arg(
        long,
        help = "Output path for generated features. If not specified, results will be written to stdout."
    )]
    pub output_path: Option<PathBuf>,

    #[arg(long, help = "Maximum number of entries to process.")]
    pub limit: Option<usize>,
}

#[derive(Args, Clone, Debug)]
pub struct ValidateDatasetOptions {
    #[arg(long, help = "Path to the JSON lines dataset file.", required = true)]
    pub input_path: PathBuf,

    #[arg(
        long,
        help = "Output path for results. If not specified, results will be printed to stdout."
    )]
    pub output_path: Option<PathBuf>,

    #[arg(
        long,
        default_value = "very_low",
        help = "Minimum confidence level for detections to be included in the results. Supported values: very_low, low, \
            medium, high, very_high."
    )]
    pub min_confidence: AuditConfidence,

    #[arg(
        long,
        help = "Only output files that triggered no rules (JSON output recommended)."
    )]
    pub no_rules: bool,

    #[arg(long, help = "Include the decoded source code in the output.")]
    pub code: bool,
}

#[derive(Subcommand, Clone, Debug)]
pub enum DatasetCommand {
    /// Generate features from a JSON lines dataset file.
    GenerateFeatures {
        #[command(flatten)]
        opts: GenerateFeaturesOptions,
    },
    /// Validate a JSON lines dataset and output triggered rules.
    Validate {
        #[command(flatten)]
        opts: ValidateDatasetOptions,
    },
    /// Read a file from the dataset by matching its `file` field and print decoded source.
    ReadFile {
        #[arg(long, help = "Path to the JSON lines dataset file.", required = true)]
        input_path: PathBuf,

        #[arg(
            long,
            help = "File path to match against the `file` field.",
            required = true
        )]
        file_path: String,
    },
}

pub fn handle_dataset_command(cmd: DatasetCommand) {
    match cmd {
        DatasetCommand::GenerateFeatures { opts } => {
            crate::generate::generate_features_from_dataset(
                &opts.input_path,
                opts.output_path.as_deref(),
                opts.limit,
            );
        }
        DatasetCommand::Validate { opts } => {
            crate::generate::validate_dataset(
                &opts.input_path,
                opts.output_path.as_deref(),
                opts.min_confidence,
                opts.no_rules,
                opts.code,
            );
        }
        DatasetCommand::ReadFile {
            input_path,
            file_path,
        } => {
            crate::generate::read_file_from_dataset(&input_path, &file_path);
        }
    }
}
