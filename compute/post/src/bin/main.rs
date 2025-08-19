use tee_worker_post_compute::compute::app_runner::start;
use env_logger::{Builder, Env, Target};
use std::process;

fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .target(Target::Stdout)
        .init();
    process::exit(start() as i32);
}
