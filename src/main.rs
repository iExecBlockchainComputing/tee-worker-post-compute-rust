use std::process;

mod api;
mod compute;

fn main() {
    env_logger::init();
    process::exit(compute::app_runner::start());
}
