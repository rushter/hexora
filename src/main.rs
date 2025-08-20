use crate::cli::run_cli;

mod audit;
mod cli;
mod io;
mod rules;

const CLI_START_ARG_STANDALONE: usize = 0;

fn main() {
    run_cli(CLI_START_ARG_STANDALONE);
}
