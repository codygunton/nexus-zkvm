use clap::Subcommand;

use super::ENV;

pub mod host;
pub mod execute;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new host/guest Nexus package at <path>.
    Host(host::HostArgs),
    /// Execute a RISC-V ELF file using the emulator.
    Execute(execute::ExecuteArgs),
}

pub fn handle_command(cmd: Command) -> anyhow::Result<()> {
    dotenvy::from_read(ENV.as_bytes()).expect("env must be valid");

    match cmd {
        Command::Host(args) => host::handle_command(args),
        Command::Execute(args) => execute::handle_command(args),
    }
}
