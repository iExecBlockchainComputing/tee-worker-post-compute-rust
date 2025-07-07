use env_logger::Env;
use std::process;

mod api;
mod compute;

fn main() {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    process::exit(compute::app_runner::start());
}
