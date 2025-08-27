use crate::cli::run_cli;

mod audit;
mod cli;
mod io;
mod macros;
mod rules;

const CLI_START_ARG_STANDALONE: usize = 0;
// #[macro_use]
// extern crate litcrypt;
//
// use_litcrypt!();

fn main() {
    run_cli(CLI_START_ARG_STANDALONE);
}
