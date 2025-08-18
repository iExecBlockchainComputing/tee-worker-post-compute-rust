use env_logger::{Builder, Env, Target};
use std::process;

mod api;
mod compute;

fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Stdout)
        .init();
    process::exit(compute::app_runner::start() as i32);
}
