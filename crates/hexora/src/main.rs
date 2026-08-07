use hexora::cli::run_cli;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const CLI_START_ARG_STANDALONE: usize = 0;

fn main() {
    run_cli(CLI_START_ARG_STANDALONE);
}
