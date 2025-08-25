use env_logger::{Builder, Env, Target};
use std::process;
use tee_worker_pre_compute::compute::app_runner::start;

fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Stdout)
        .init();
    process::exit(start() as i32);
}
