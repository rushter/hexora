use crate::cli::run_cli;

mod audit;
mod cli;
mod io;
mod rules;

fn main() {
    run_cli(0);
}
