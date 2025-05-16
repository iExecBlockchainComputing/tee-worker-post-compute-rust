use std::process;

mod api;
mod compute;

fn main() {
    process::exit(compute::app_runner::start());
}
