use crate::compute::app_runner::{PostComputeRunner, PostComputeService};
use env_logger::{Builder, Env, Target};
use std::process;

mod api;
mod compute;

fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Stdout)
        .init();
    process::exit(PostComputeRunner::start() as i32);
}
